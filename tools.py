# =============================================================================
# aviation_ci_app | Governed OSINT connectors, retrieval safety, and source provenance
#
# Responsibility: Implement NewsAPI, FAA/EASA, NTSB, manufacturer PR, Bluesky, airshow, and YouTube
#   collection utilities.
# Design boundary: Request controls cover date scoping, source policy, SSRF/robots/TDM safety,
#   deduplication, and telemetry.
# =============================================================================

import csv
import email.utils
import hashlib
import html
import io
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import unicodedata
import urllib.parse
import urllib.robotparser
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urljoin, urlparse

import feedparser
import requests
from bs4 import BeautifulSoup
from crewai.tools import tool
from dotenv import load_dotenv
from google import genai
from google.genai import types
from playwright.sync_api import sync_playwright
from tenacity import retry, stop_after_attempt, wait_exponential
from youtube_transcript_api import YouTubeTranscriptApi

load_dotenv()
logger = logging.getLogger(__name__)

# Legacy export for callers importing this setting; NewsAPI requests read it dynamically.
NEWS_API_KEY = os.getenv("NEWS_API_KEY")
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
EXA_API_KEY = os.getenv("EXA_API_KEY")

# Provide a normalized UTC timestamp for report metadata and audit records.
def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

# Canonical monitoring date-window choices.
class AnalysisScope(str, Enum):
    LAST_24_HOURS = "24h"
    LAST_7_DAYS = "7d"
    LAST_30_DAYS = "30d"
    LAST_90_DAYS = "90d"
    LAST_365_DAYS = "365d"
    CUSTOM = "custom"
    ALL = "all"

SCOPE_LABEL_MAP = {
    "24h": AnalysisScope.LAST_24_HOURS,
    "last 24 hours (quick briefing)": AnalysisScope.LAST_24_HOURS,
    "7d": AnalysisScope.LAST_7_DAYS,
    "last 7 days (standard monitoring)": AnalysisScope.LAST_7_DAYS,
    "30d": AnalysisScope.LAST_30_DAYS,
    "last 30 days": AnalysisScope.LAST_30_DAYS,
    "90d": AnalysisScope.LAST_90_DAYS,
    "365d": AnalysisScope.LAST_365_DAYS,
    "custom": AnalysisScope.CUSTOM,
    "all": AnalysisScope.ALL,
    "deep historical analysis (unrestricted)": AnalysisScope.ALL,
}

_SCOPE_FALLBACK_RULES = (
    (("24", "1d"), AnalysisScope.LAST_24_HOURS),
    (("7", "week"), AnalysisScope.LAST_7_DAYS),
    (("30", "month"), AnalysisScope.LAST_30_DAYS),
    (("90",), AnalysisScope.LAST_90_DAYS),
    (("365", "year"), AnalysisScope.LAST_365_DAYS),
    (("custom",), AnalysisScope.CUSTOM),
    (("unrestricted", "all", "deep"), AnalysisScope.ALL),
)

# Convert user-facing time ranges into the application’s canonical analysis scopes.
def normalize_scope_value(raw_scope: str) -> AnalysisScope:
    if not raw_scope:
        return AnalysisScope.LAST_7_DAYS
    s = raw_scope.strip().lower()
    if s in SCOPE_LABEL_MAP:
        return SCOPE_LABEL_MAP[s]
    return next(
        (scope for tokens, scope in _SCOPE_FALLBACK_RULES if any(t in s for t in tokens)),
        AnalysisScope.LAST_7_DAYS,
    )

# Public registry objects retain their legacy import locations.
from aero_ews.collection.registry import (
    AEROSPACE_SUPPLIER_REGISTRY,
    SOURCE_REGISTRY,
)


# Resolve aerospace organizations against controlled supplier metadata.
def _supplier_name_key(value: str) -> str:
    text = unicodedata.normalize('NFKD', str(value or '').casefold()).replace('&', ' and ')

    text = ''.join(ch for ch in text if not unicodedata.combining(ch))

    text = re.sub(r"[^a-z0-9]+", " ", text)

    return re.sub(r"\s+", " ", text).strip()

def find_supplier_mentions(text: str) -> list[dict[str, Any]]:
    """Return all distinct explicitly mentioned registry entities."""
    normalized = _supplier_name_key(text)

    if not normalized:
        return []

    matches = []

    for supplier in AEROSPACE_SUPPLIER_REGISTRY:
        aliases = (supplier['official_name'], *supplier.get('aliases', []))

        for alias in aliases:
            candidate = _supplier_name_key(alias)

            if len(candidate) < 3:
                continue

            pattern = '(?<![a-z0-9])' + re.escape(candidate) + '(?![a-z0-9])'

            if re.search(pattern, normalized):
                matches.append(supplier)
                break

    return matches

def lookup_supplier_in_registry(text_or_company: str, exact: bool=False) -> dict[str, Any] | None:
    """Resolve an entity only when exactly one registry entry matches."""

    if not text_or_company:
        return None

    if exact:
        target = _supplier_name_key(text_or_company)
        matches = [
            supplier
            for supplier in AEROSPACE_SUPPLIER_REGISTRY
            if target in {
                _supplier_name_key(alias)
                for alias in (
                    supplier["official_name"],
                    *supplier.get("aliases", []),
                )
            }
        ]
    else:
        matches = find_supplier_mentions(text_or_company)

    # Multiple organizations in an article are not proof
    # that any particular one is the primary event subject.
    if len(matches) != 1:
        return None

    return matches[0]

# Shared coordination of outgoing requests and response-sensitive throttling.
class CentralRateLimiter:
    # Initialize the shared request-rate counters and synchronization lock.
    def __init__(self) -> None:
        # Coordinate network rate limits across source connectors.
        self._lock = threading.Lock()
        self._last_call: dict[str, float] = {}

    # Enforce a centralized retrieval rate budget before network access.
    def wait_for_slot(self, source_id: str) -> None:
        min_interval = float(SOURCE_REGISTRY.get(source_id, {}).get("min_interval_sec", 1.0))
        with self._lock:
            wait_sec = min_interval - (time.time() - self._last_call.get(source_id, 0.0))
            if wait_sec > 0:
                time.sleep(wait_sec)
            self._last_call[source_id] = time.time()

    # Adjust the rate-limiter state after successful or throttled requests.
    def record_outcome(self, source_id: str, success: bool) -> None:
        if source_id not in SOURCE_REGISTRY:
            return
        with self._lock:
            if success:
                SOURCE_REGISTRY[source_id]["success_count"] += 1
                SOURCE_REGISTRY[source_id]["last_success_at"] = _now_iso()
            else:
                SOURCE_REGISTRY[source_id]["failure_count"] += 1

RATE_LIMITER = CentralRateLimiter()

# Check source governance status before collection.
def is_source_allowed(source_id: str) -> bool:
    cfg = SOURCE_REGISTRY.get(source_id, {})
    status = cfg.get("legal_status")

    if status in {"ALLOWED", "RESTRICTED"}:
        return True

    return (
        status == "REQUIRES_REVIEW"
        and os.getenv("EWS_TEST_REVIEW_SOURCES") == "1"
        and os.getenv("EWS_ENV", "development").lower()
        in {"dev", "development", "test"}
    )

_ROBOTS_CACHE: dict[str, urllib.robotparser.RobotFileParser] = {}

# Reject local, private, and restricted IP targets to reduce SSRF exposure.
def is_ip_public_and_safe(hostname: str) -> bool:
    if not hostname:
        return False
    low = hostname.lower().strip()
    if low in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or low.endswith((".local", ".internal")):
        return False
    try:
        for item in socket.getaddrinfo(hostname, None):
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                    ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                    or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
            ):
                logger.warning(f"[SSRF GUARD] Blocked non-public IP {ip_str} for host {hostname}")
                return False
        return True
    except Exception as e:
        logger.debug(f"[SSRF GUARD] DNS resolution failed for {hostname}: {e}")
        return False

HTML_TDM_OPT_OUT_REGEX = re.compile(
    r"<meta[^>]+(?:name|property)\s*=\s*[\"'](?:tdm-reservation|robots|googlebot)[\"'][^>]+content\s*=\s*[\"'][^\"']*(?:1|noai|notdm|noarchive|noindex)[^\"']*[\"']",
    re.IGNORECASE,
)

# Apply robots.txt and text-and-data-mining access restrictions.
# Apply source-specific robots and text/data-mining restrictions before retrieval.
def check_robots_and_tdm_compliance(
        url: str, source_id: str = "SRC_004", user_agent: str = "AeroEWSBot"
) -> tuple[bool, str]:
    # Check both automated-access rules and documented TDM restrictions.
    """Apply configured robots.txt and text-and-data-mining access checks."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False, "Invalid URL scheme or host"

    src_cfg = SOURCE_REGISTRY.get(source_id)
    if not src_cfg:
        return False, f"Unregistered source '{source_id}' - collection suspended (REQUIRES_REVIEW)"
    if not is_source_allowed(source_id):
        return False, f"Source {source_id} legal status is {src_cfg.get('legal_status')} - collection suspended"
    if src_cfg.get("tdm_opt_out"):
        return False, f"Source {source_id} has active TDM copyright opt-out (EU 2019/790 Art. 4)"
    if not src_cfg.get("tos_url") or not src_cfg.get("last_legal_review_date"):
        return False, f"Source {source_id} is missing ToS link or legal review date - collection suspended"

    base_robots = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        if parsed.netloc not in _ROBOTS_CACHE:
            if not is_ip_public_and_safe(parsed.hostname or ""):
                return False, "Host failed SSRF public IP check"

            load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

            contact = os.getenv("EWS_CONTACT_EMAIL", "").strip()
            contact = contact.removeprefix("mailto:")

            if not contact or "@" not in contact:
                raise RuntimeError("Missing EWS_CONTACT_EMAIL")

            robots_headers = {
                "User-Agent": f"AeroEWS Academic Research {contact}",
                "Accept": "text/plain",
            }

            resp = requests.get(base_robots, headers=robots_headers, timeout=5)
            _note_http_request(source_id, resp.status_code)
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(base_robots)

            if resp.status_code == 200:
                if resp.headers.get("TDM-Reservation", "").strip() == "1":
                    return False, "TDM-Reservation opt-out header active on host"
                rp.parse(resp.text.splitlines())
            elif resp.status_code == 404 and src_cfg.get("verified_domain", False):
                rp.allow_all = True
            else:
                logger.warning(
                    f"[COMPLIANCE FAIL-CLOSED] Could not verify robots.txt for {parsed.netloc} "
                    f"(HTTP {resp.status_code}). Suspending collection for review."
                )
                return False, f"Cannot verify robots.txt (HTTP {resp.status_code}) - collection suspended for manual review"

            _ROBOTS_CACHE[parsed.netloc] = rp

        rp = _ROBOTS_CACHE[parsed.netloc]
        if not rp.can_fetch(user_agent, url) or not rp.can_fetch("*", url):
            return False, "Disallowed by technical robots.txt policy"
    except Exception as e:
        if isinstance(e, requests.RequestException):
            _note_http_request(source_id, None, timed_out=isinstance(e, requests.Timeout))
        logger.warning(f"[COMPLIANCE FAIL-CLOSED] Error loading robots.txt from {base_robots} ({e}).")
        return False, "Error loading robots.txt rules - collection suspended (REQUIRES_REVIEW)"

    return True, "Allowed (Registry ToS, robots.txt, and TDM pre-check passed)"

@dataclass
class HTTPResult:
    response: requests.Response | None = None
    status_code: int | None = None
    error_type: str = ""
    retryable: bool = False
    retry_after: float | None = None
    response_complete: bool = False
    bytes_received: int = 0
    attempts: int = 0
    wait_seconds: float = 0.0
    payload_classification: str = ""
    payload_shape: dict[str, Any] | None = None


def _retry_after_seconds(value: str) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            return max(0.0, (parsed - datetime.now(UTC)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


def _safe_http_request(
        url: str,
        source_id: str = "SRC_004",
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 12,
        max_redirects: int = 3,
        max_bytes: int = 2_000_000,
        check_robots: bool = False,
        max_attempts: int = 3,
) -> HTTPResult:
    """Guarded GET with explicit HTTP, policy, truncation and retry outcomes."""
    result = HTTPResult()
    if not is_source_allowed(source_id):
        result.error_type = "SOURCE_POLICY_BLOCKED"
        _note_blocked_request(source_id)
        return result

    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AeroEWS/2.0",
                   **(headers or {})}
    current_url, current_params, redirects, retries = url, params, 0, 0
    while True:
        parsed = urlparse(current_url)
        if parsed.scheme not in {"http", "https"} or not is_ip_public_and_safe(parsed.hostname or ""):
            result.error_type = "SSRF_OR_INVALID_URL"
            _note_blocked_request(source_id)
            return result

        if check_robots:
            allowed, reason = check_robots_and_tdm_compliance(current_url, source_id=source_id)
            if not allowed:
                logger.info(f"[COMPLIANCE] Skipping {current_url}: {reason}")
                result.error_type = "ROBOTS_OR_TDM_BLOCKED"
                _note_blocked_request(source_id)
                return result

        try:
            RATE_LIMITER.wait_for_slot(source_id)
            resp = requests.get(
                current_url, params=current_params, headers=req_headers,
                timeout=timeout, allow_redirects=False, stream=True,
            )
            result.attempts += 1
            result.status_code = resp.status_code
            _note_http_request(source_id, resp.status_code)
            RATE_LIMITER.record_outcome(source_id, resp.status_code < 400)

            if resp.status_code in {301, 302, 303, 307, 308}:
                loc = resp.headers.get("Location")
                resp.close()
                if not loc:
                    result.error_type = "REDIRECT_WITHOUT_LOCATION"
                    return result
                if redirects >= max_redirects:
                    result.error_type = "TOO_MANY_REDIRECTS"
                    return result
                current_url = urljoin(current_url, loc)
                current_params = None
                redirects += 1
                continue

            tdm_header = resp.headers.get("TDM-Reservation", "").strip()
            x_robots = resp.headers.get("X-Robots-Tag", "").lower()
            if tdm_header == "1" or any(tok in x_robots for tok in ("noai", "notdm", "none")):
                logger.info(f"[TDM COMPLIANCE] Respecting TDM/X-Robots opt-out header on {current_url}")
                resp.close()
                result.error_type = "RESPONSE_TDM_BLOCKED"
                _note_blocked_request(source_id)
                return result

            retryable = resp.status_code in {429, 500, 502, 503, 504}
            retry_after = _retry_after_seconds(resp.headers.get("Retry-After", ""))
            result.retryable, result.retry_after = retryable, retry_after
            delay = retry_after if retry_after is not None else min(2 ** retries, 8)
            if retryable and retries < max_attempts - 1 and delay <= 5:
                resp.close()
                retries += 1
                time.sleep(delay)
                result.wait_seconds += delay
                continue

            chunks, downloaded = [], 0
            truncated = False
            try:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    room = max_bytes - downloaded
                    chunks.append(chunk[:room])
                    downloaded += min(len(chunk), room)
                    if len(chunk) > room:
                        truncated = True
                        break
            except requests.RequestException as exc:
                result.error_type = "INCOMPLETE_BODY"
                truncated = True
                if isinstance(exc, requests.Timeout):
                    with _COLLECTION_LOCK:
                        metrics = HTTP_TELEMETRY.setdefault(
                            source_id, {"http_requests": 0, "http_status_counts": {}})
                        metrics["timeouts"] = metrics.get("timeouts", 0) + 1
            resp._content = b"".join(chunks)
            resp.close()
            # The cap is a safety limit, never a proof that the body is complete.
            # requests.iter_content() transparently decompresses gzip/br/deflate.
            # Content-Length describes the transferred (encoded) bytes, so only
            # compare it with decoded content for identity-encoded responses.
            encoding = resp.headers.get("Content-Encoding", "identity").strip().lower()
            comparable_length = encoding in {"", "identity"}
            resp.aero_content_truncated = truncated or (
                comparable_length
                and (resp.headers.get("Content-Length") or "").isdigit()
                and int(resp.headers["Content-Length"]) > len(resp._content)
            )
            result.bytes_received = len(resp._content)
            result.response_complete = not resp.aero_content_truncated
            if resp.aero_content_truncated:
                logger.warning("[HTTP CONTENT LIMIT] %s: response incomplete at %d bytes", current_url, max_bytes)

            if check_robots and "text/html" in resp.headers.get("Content-Type", "").lower():
                if HTML_TDM_OPT_OUT_REGEX.search(resp.text[:4000]):
                    logger.info(f"[TDM COMPLIANCE] Respecting HTML meta TDM opt-out on {current_url}")
                    result.error_type = "HTML_TDM_BLOCKED"
                    _note_blocked_request(source_id)
                    return result

            result.response = resp
            if result.error_type != "INCOMPLETE_BODY":
                result.error_type = ("ACCESS_BLOCKED" if resp.status_code in {401, 403}
                                     else "HTTP_ERROR" if resp.status_code >= 400
                                     else "BODY_TRUNCATED" if resp.aero_content_truncated else "")
            return result
        except requests.RequestException as e:
            logger.debug(f"[HTTP CLIENT] Error fetching {current_url}: {e}")
            result.attempts += 1
            result.status_code = None
            result.error_type = "NETWORK_ERROR"
            result.retryable = True
            _note_http_request(source_id, None, timed_out=isinstance(e, requests.Timeout))
            RATE_LIMITER.record_outcome(source_id, False)
            return result


def safe_http_get(
        url: str, source_id: str = "SRC_004", params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None, timeout: int = 12,
        max_redirects: int = 3, max_bytes: int = 2_000_000,
        check_robots: bool = False,
) -> requests.Response | None:
    """Backward-compatible GET; inspect `_safe_http_request` for failure details."""
    return _safe_http_request(url, source_id, params, headers, timeout,
                              max_redirects, max_bytes, check_robots).response


def safe_http_post_json(
        url: str,
        payload: dict[str, Any],
        *,
        source_id: str,
        headers: dict[str, str] | None = None,
        timeout: int = 20,
        max_bytes: int = 3_000_000,
        max_attempts: int = 2,
) -> HTTPResult:
    """Guarded HTTPS JSON POST enforcing source policy, SSRF safety, rate limits, and telemetry."""
    result = HTTPResult()
    if not is_source_allowed(source_id):
        result.error_type = "SOURCE_POLICY_BLOCKED"
        _note_blocked_request(source_id)
        return result

    parsed = urlparse(url)
    if parsed.scheme != "https" or not is_ip_public_and_safe(parsed.hostname or ""):
        result.error_type = "SSRF_OR_INVALID_URL"
        _note_blocked_request(source_id)
        return result

    req_headers = {
        "User-Agent": "AeroEWS Academic Research/2.0",
        "Accept": "application/json",
        "Content-Type": "application/json",
        **(headers or {}),
    }

    for attempt in range(max(1, max_attempts)):
        try:
            RATE_LIMITER.wait_for_slot(source_id)
            resp = requests.post(
                url, json=payload, headers=req_headers,
                timeout=timeout, allow_redirects=False, stream=True,
            )
            result.attempts += 1
            result.status_code = resp.status_code
            _note_http_request(source_id, resp.status_code)
            RATE_LIMITER.record_outcome(source_id, resp.status_code < 400)

            retryable = resp.status_code in {429, 500, 502, 503, 504}
            retry_after = _retry_after_seconds(resp.headers.get("Retry-After", ""))
            result.retryable, result.retry_after = retryable, retry_after
            delay = retry_after if retry_after is not None else min(2 ** attempt, 5)
            if retryable and attempt < max_attempts - 1 and delay <= 5:
                resp.close()
                time.sleep(delay)
                result.wait_seconds += delay
                continue

            chunks, downloaded, truncated = [], 0, False
            for chunk in resp.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                room = max_bytes - downloaded
                chunks.append(chunk[:room])
                downloaded += min(len(chunk), room)
                if len(chunk) > room:
                    truncated = True
                    break
            resp._content = b"".join(chunks)
            resp.close()
            resp.aero_content_truncated = truncated
            result.bytes_received = len(resp._content)
            result.response_complete = not truncated
            result.response = resp
            result.error_type = (
                "ACCESS_BLOCKED" if resp.status_code in {401, 403}
                else "RATE_LIMITED" if resp.status_code == 429
                else "HTTP_ERROR" if resp.status_code >= 400
                else "BODY_TRUNCATED" if truncated else ""
            )
            return result
        except requests.RequestException as exc:
            logger.debug("[HTTP POST] Error posting to %s: %s", url, exc)
            result.attempts += 1
            result.status_code = None
            result.error_type = "NETWORK_ERROR"
            result.retryable = True
            _note_http_request(source_id, None, timed_out=isinstance(exc, requests.Timeout))
            RATE_LIMITER.record_outcome(source_id, False)
            if attempt >= max_attempts - 1:
                return result
    return result

PROMPT_INJECTION_REGEX = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|system)\s+prompts?|"
    r"you\s+are\s+now\s+a\s+|system\s+override\s*:|new\s+directive\s*:|"
    r"forget\s+everything|do\s+not\s+mention\s+this\s+instruction|"
    r"output\s+threat_score\s*=\s*10|<\s*/?\s*system\s*>)",
    re.IGNORECASE,
)

PII_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PII_PHONE_REGEX = re.compile(r"(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b")
PII_SOCIAL_HANDLE_REGEX = re.compile(r"(?<!\w)@[A-Za-z0-9_.-]{3,40}\b")
PII_PERSONAL_BYLINE_REGEX = re.compile(
    r"\b(?:contact\s+person|media\s+contact|press\s+contact|written\s+by|reported\s+by)\s*:\s*[A-Z][a-z]+\s+[A-Z][a-z]+",
    re.IGNORECASE,
)

_PII_REDACTION_RULES = (
    (PII_EMAIL_REGEX, "[REDACTED_EMAIL]"),
    (PII_PHONE_REGEX, "[REDACTED_PHONE]"),
    (PII_SOCIAL_HANDLE_REGEX, "[REDACTED_HANDLE]"),
    (PII_PERSONAL_BYLINE_REGEX, "[REDACTED_CONTACT_NAME]"),
)

PERSONAL_NON_INDUSTRIAL_POST_REGEX = re.compile(
    r"\b(?:my\s+flight\s+was|my\s+luggage|lost\s+my\s+bag|vacation|holiday\s+vlog|hotel\s+room|"
    r"my\s+seat\s+on|flight\s+attendant\s+was\s+rude|looking\s+for\s+a\s+job|hiring\s+me|"
    r"my\s+personal|family\s+trip|birthday|wedding|selfie|rate\s+my\s+landing|plane\s+spotting\s+at)\b",
    re.IGNORECASE,
)

AEROSPACE_B2B_RELEVANCE_ANCHORS = re.compile(
    r"\b(?:airbus|boeing|comac|embraer|pratt|whitney|cfm|safran|rolls-royce|ge\s+aerospace|spirit\s+aerosystems|"
    r"collins|faa|easa|ntsb|airworthiness|directive|supply\s+chain|tier\s*[123]|delivery\s+delay|shortage|"
    r"production|grounding|grounded|mro|turbine|fuselage|titanium|forging|defect|inspection|fleet\s+order)\b",
    re.IGNORECASE,
)

# Flag community text unrelated to the monitored industrial intelligence question.
def is_unrelated_personal_post(text: str, title: str = "") -> bool:
    combined = f"{title} {text}".strip()
    return (
            not combined
            or bool(PERSONAL_NON_INDUSTRIAL_POST_REGEX.search(combined))
            or not bool(AEROSPACE_B2B_RELEVANCE_ANCHORS.search(combined))
    )

# Remove unnecessary personal or unsafe content before storing source excerpts.
def sanitize_and_minimize_osint_text(raw_text: str) -> tuple[str, bool, int]:
    if not raw_text:
        return "", False, 0
    cleaned, inj_count = PROMPT_INJECTION_REGEX.subn("[REDACTED_PROMPT_INJECTION_ATTEMPT]", raw_text)
    pii_count = 0
    for regex, replacement in _PII_REDACTION_RULES:
        cleaned, count = regex.subn(replacement, cleaned)
        pii_count += count
    return cleaned, inj_count > 0, pii_count

COLLECTED_URLS: set[str] = set()
COLLECTED_DOCUMENTS: list[dict[str, Any]] = []
CONNECTOR_TELEMETRY: dict[str, dict[str, Any]] = {}
HTTP_TELEMETRY: dict[str, dict[str, Any]] = {}
NEWS_FALLBACK_CACHE: dict[tuple[str, str, str, int, str], list[dict[str, Any]]] = {}
FAA_SEARCH_CACHE: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]] = {}
EASA_PAGE_CACHE: dict[str, str] = {}
_COLLECTION_LOCK = threading.Lock()

class NewsAPIState(str, Enum):
    AVAILABLE = "AVAILABLE"
    RATE_LIMITED = "RATE_LIMITED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    ACCESS_RESTRICTED = "ACCESS_RESTRICTED"
    TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"
    MISCONFIGURED = "MISCONFIGURED"


_NEWSAPI_LOCK = threading.Lock()
_NEWSAPI_HEALTH: dict[str, Any] = {
    "state": NewsAPIState.AVAILABLE, "key_digest": "", "until": 0.0, "error_code": "",
    "restricted_queries": set(),
}


def _newsapi_key() -> str:
    return os.getenv("NEWS_API_KEY", "").strip()


def reload_newsapi_configuration() -> dict[str, Any]:
    """Reload a changed .env key without restarting the worker process."""
    load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=True)
    return check_newsapi_availability()


def _newsapi_current_state(key: str, query: str = "") -> NewsAPIState:
    digest = hashlib.sha256(key.encode()).hexdigest() if key else ""
    with _NEWSAPI_LOCK:
        if digest != _NEWSAPI_HEALTH["key_digest"]:
            _NEWSAPI_HEALTH.update(state=NewsAPIState.AVAILABLE, key_digest=digest,
                                   until=0.0, error_code="", restricted_queries=set())
        if not key:
            return NewsAPIState.MISCONFIGURED
        if query in _NEWSAPI_HEALTH["restricted_queries"]:
            return NewsAPIState.ACCESS_RESTRICTED
        state = _NEWSAPI_HEALTH["state"]
        if state in {NewsAPIState.RATE_LIMITED, NewsAPIState.TEMPORARILY_UNAVAILABLE}:
            if time.monotonic() >= _NEWSAPI_HEALTH["until"]:
                _NEWSAPI_HEALTH.update(state=NewsAPIState.AVAILABLE, error_code="")
                return NewsAPIState.AVAILABLE
        return state


def _newsapi_request(params: dict[str, Any], key: str, max_attempts: int = 3) -> tuple[dict[str, Any] | None, NewsAPIState, str]:
    response = _safe_http_request(
        "https://newsapi.org/v2/everything", source_id="SRC_004",
        params=params, headers={"X-Api-Key": key, "User-Agent": "AeroEWS/2.0"},
        timeout=15, max_attempts=max_attempts,
    )
    data: dict[str, Any] = {}
    if response.response is not None and response.response_complete:
        try:
            data = response.response.json()
        except (ValueError, TypeError):
            pass
    status, code = response.status_code, str(data.get("code") or response.error_type or "UNKNOWN")
    if status == 200 and data.get("status") == "ok" and isinstance(data.get("articles"), list):
        return data, NewsAPIState.AVAILABLE, ""
    if status == 401 or code in {"apiKeyInvalid", "apiKeyDisabled", "apiKeyMissing"}:
        state = NewsAPIState.AUTHENTICATION_FAILED
    elif status == 429 or code in {"rateLimited", "apiKeyExhausted"}:
        state = NewsAPIState.RATE_LIMITED
    elif status == 403:
        state = NewsAPIState.ACCESS_RESTRICTED
    elif status == 400 or code in {"parameterInvalid", "parametersMissing"}:
        state = NewsAPIState.MISCONFIGURED
    else:
        state = NewsAPIState.TEMPORARILY_UNAVAILABLE
    with _NEWSAPI_LOCK:
        if state == NewsAPIState.ACCESS_RESTRICTED and code in {
            "upgradeRequired", "planUpgradeRequired", "apiKeyPlanRequired"
        }:
            _NEWSAPI_HEALTH["state"] = state
        elif state == NewsAPIState.ACCESS_RESTRICTED or (state == NewsAPIState.MISCONFIGURED and status == 400):
            _NEWSAPI_HEALTH["restricted_queries"].add(str(params.get("q", "")))
        else:
            _NEWSAPI_HEALTH["state"] = state
            if state in {NewsAPIState.RATE_LIMITED, NewsAPIState.TEMPORARILY_UNAVAILABLE}:
                fallback = 600 if state == NewsAPIState.RATE_LIMITED else 60
                _NEWSAPI_HEALTH["until"] = time.monotonic() + (
                    response.retry_after if response.retry_after is not None else fallback
                )
        _NEWSAPI_HEALTH["error_code"] = code
    logger.warning("[NEWS API] state=%s http=%s code=%s", state.value, status, code)
    return None, state, code


def check_newsapi_availability(probe: bool = False) -> dict[str, Any]:
    """Cheap preflight (no API request by default; probe=True uses exactly one)."""
    key = _newsapi_key()
    state = _newsapi_current_state(key)
    if (os.getenv("EWS_ENV", "development").lower() not in {"dev", "development", "test"}
            and os.getenv("EWS_NEWSAPI_PRO_LICENSE") != "1"):
        return {"state": NewsAPIState.ACCESS_RESTRICTED.value, "reason": "LICENSE_REQUIRED", "requests": 0}
    if probe and state == NewsAPIState.AVAILABLE:
        _, state, reason = _newsapi_request({"q": "aviation", "pageSize": 1}, key, max_attempts=1)
        return {"state": state.value, "reason": reason, "requests": 1}
    with _NEWSAPI_LOCK:
        remaining = max(0.0, _NEWSAPI_HEALTH["until"] - time.monotonic())
        reason = _NEWSAPI_HEALTH["error_code"]
    return {"state": state.value, "reason": reason or ("MISSING_API_KEY" if not key else ""),
            "retry_after_seconds": round(remaining, 1), "requests": 0}

def _note_http_request(source_id: str, status_code: int | None, *, timed_out: bool = False) -> None:
    """Count physical HTTP attempts, including retries and robots.txt checks."""
    with _COLLECTION_LOCK:
        item = HTTP_TELEMETRY.setdefault(source_id, {"http_requests": 0, "http_status_counts": {}})
        item["http_requests"] += 1
        key = str(status_code) if status_code is not None else "NETWORK_ERROR"
        counts = item["http_status_counts"]
        counts[key] = counts.get(key, 0) + 1
        metric = ("timeouts" if timed_out else "network_errors" if status_code is None
                  else "http_errors" if status_code >= 400 else "http_redirects" if status_code >= 300
                  else "successful_responses")
        item[metric] = item.get(metric, 0) + 1
        if status_code in {401, 403}:
            item["blocked_requests"] = item.get("blocked_requests", 0) + 1


def _note_blocked_request(source_id: str) -> None:
    """Record policy-blocked retrievals without inventing an HTTP request."""
    with _COLLECTION_LOCK:
        item = HTTP_TELEMETRY.setdefault(source_id, {"http_requests": 0, "http_status_counts": {}})
        item["blocked_requests"] = item.get("blocked_requests", 0) + 1

# Reset per-run URL deduplication and collection state.
def reset_collected_urls() -> None:
    # Reset only per-run source caches and deduplication state.
    with _COLLECTION_LOCK:
        COLLECTED_URLS.clear()
        COLLECTED_DOCUMENTS.clear()
        CONNECTOR_TELEMETRY.clear()
        NEWS_FALLBACK_CACHE.clear()
        FAA_SEARCH_CACHE.clear()
        EASA_PAGE_CACHE.clear()
        HTTP_TELEMETRY.clear()

# Return the current run’s collected document records.
def get_collected_documents() -> list[dict[str, Any]]:
    with _COLLECTION_LOCK:
        return list(COLLECTED_DOCUMENTS)

# Read per-connector retrieval and rejection statistics.
def get_connector_telemetry() -> dict[str, dict[str, Any]]:
    with _COLLECTION_LOCK:
        snapshot = {name: {**entry, "http_status_counts": dict(entry["http_status_counts"]),
                           "content_status_counts": dict(entry["content_status_counts"])}
                    for name, entry in CONNECTOR_TELEMETRY.items()}
        for sid, metrics in HTTP_TELEMETRY.items():
            matches = [entry for entry in snapshot.values() if entry["source_id"] == sid]
            # Several connectors may share a source; never assign its HTTP calls to each.
            entry = matches[0] if len(matches) == 1 else snapshot.setdefault(
                f"HTTP {sid}", {"source_id": sid, "connector_name": f"HTTP {sid}"})
            for metric, value in metrics.items():
                if metric == "http_status_counts":
                    counts = entry.setdefault(metric, {})
                    for code, n in value.items():
                        counts[code] = counts.get(code, 0) + n
                else:
                    entry[metric] = entry.get(metric, 0) + value
        for doc in COLLECTED_DOCUMENTS:
            name = doc["connector_name"]
            entry = snapshot.setdefault(name, {
                "connector_name": name, "source_id": doc["source_id"],
                "found_count": 0, "accepted_count": 0, "http_requests": 0,
                "http_status_counts": {}, "content_status_counts": {},
                "operational_status": "UNKNOWN", "last_search_outcome": "UNKNOWN",
            })
            entry["collected_document_count"] = entry.get("collected_document_count", 0) + 1
            status = doc.get("content_status", "")
            availability = (status if status in {"FULL_TEXT", "PARTIAL_TEXT", "METADATA_ONLY", "UNAVAILABLE"}
                            else "METADATA_ONLY" if status == "SUMMARY_ONLY" else "UNKNOWN")
            counts = entry.setdefault("content_availability_counts", {})
            counts[availability] = counts.get(availability, 0) + 1
            date = str(doc.get("published_at") or "")[:10]
            if re.fullmatch(r"(?:19|20)\d{2}-\d{2}-\d{2}", date):
                entry["observed_publication_from"] = min(date, entry.get("observed_publication_from", date))
                entry["observed_publication_to"] = max(date, entry.get("observed_publication_to", date))
        return snapshot

# Accumulate source-level collection counts and operational failures.
# Track source-level results separately from analytical relevance.
def record_connector_telemetry(
        connector_name: str,
        source_id: str,
        query: str,
        found_count: int = 0,
        accepted_count: int = 0,
        rejected_out_of_scope: int = 0,
        unknown_date_count: int = 0,
        error: str | None = None,
        coverage_note: str | None = None,
        http_requests: int = 0,
        http_status_counts: dict[str, int] | None = None,
        content_status_counts: dict[str, int] | None = None,
        operational_status: str | None = None,
        search_outcome: str | None = None,
        coverage_window: dict[str, Any] | None = None,
        diagnostics: dict[str, Any] | None = None,
) -> None:
    now_str = _now_iso()
    reg = SOURCE_REGISTRY.get(source_id, {})
    with _COLLECTION_LOCK:
        entry = CONNECTOR_TELEMETRY.setdefault(
            connector_name,
            {
                "connector_name": connector_name,
                "source_id": source_id,
                "technical_source": reg.get("technical_host", reg.get("domain", "unknown")),
                "origin_type": reg.get("origin", "UNKNOWN"),
                "legal_status": reg.get("legal_status", "ALLOWED"),
                "queries": [],
                "found_count": 0,
                "accepted_count": 0,
                "rejected_out_of_scope": 0,
                "unknown_date_count": 0,
                "http_requests": 0,
                "http_status_counts": {},
                "content_status_counts": {},
                "operational_status": "UNKNOWN",
                "last_search_outcome": "UNKNOWN",
                "errors": [],
                "coverage_advisories": [],
                "time_window": {
                    "from": os.getenv("EWS_EFFECTIVE_FROM", ""),
                    "to": os.getenv("EWS_EFFECTIVE_TO", ""),
                    "scope": os.getenv("EWS_DYNAMIC_SCOPE", "7d"),
                },
                "last_updated": now_str,
            },
        )
        if connector_name == "EASA Official Index":
            entry["technical_source"] = "easa.europa.eu"
            entry["origin_type"] = "PRIMARY_OFFICIAL_INDEX_METADATA"
        if query and query not in entry["queries"]:
            entry["queries"].append(query)
        entry["found_count"] += found_count
        entry["accepted_count"] += accepted_count
        entry["rejected_out_of_scope"] += rejected_out_of_scope
        entry["unknown_date_count"] += unknown_date_count
        entry["http_requests"] += http_requests
        for status, count in (http_status_counts or {}).items():
            entry["http_status_counts"][str(status)] = entry["http_status_counts"].get(str(status), 0) + count
        for status, count in (content_status_counts or {}).items():
            entry["content_status_counts"][str(status)] = entry["content_status_counts"].get(str(status), 0) + count
        if error:
            entry["errors"].append(error)
        if operational_status is not None:
            entry["operational_status"] = operational_status
        if search_outcome is not None:
            entry["last_search_outcome"] = search_outcome

        if coverage_note and coverage_note not in entry["coverage_advisories"]:
            entry["coverage_advisories"].append(coverage_note)
        if coverage_window:
            entry["time_window"].update(coverage_window)
        if diagnostics:
            entry.setdefault("diagnostics", {}).update(diagnostics)
            entry.setdefault("diagnostics_history", []).append({"query": query, **diagnostics})
            entry["diagnostics_history"] = entry["diagnostics_history"][-20:]

        entry["last_updated"] = now_str

# Assign a document ID, sanitize content, and preserve source provenance.
# Attach the retrieved source identity before downstream evidence assessment.
def register_collected_document(
        source_id: str,
        connector_name: str,
        url: str,
        title: str,
        raw_text: str,
        published_at: str,
        query_used: str = "",
) -> dict[str, Any]:
    # Normalize source records, compute provenance fingerprints, and assign stable document IDs.
    """Assign a unique DOC_xxx identifier, compute syndication fingerprint, sanitize text, and store metadata."""
    clean_text, injection_flag, pii_redacted = sanitize_and_minimize_osint_text(raw_text)
    clean_title, title_inj, _ = sanitize_and_minimize_osint_text(title)
    norm_pub = normalize_date_str(published_at)
    parsed_url = urlparse(url)
    preserve_fragment = bool(
        parsed_url.fragment and (
                source_id == "SRC_003"
                or parsed_url.fragment.startswith(("ad=", "case=", "record="))
        )
    )
    canonical_url = url if preserve_fragment else parsed_url._replace(fragment="").geturl()
    content_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()

    words_for_fp = re.findall(r"\b[a-z0-9]{4,}\b", f"{clean_title} {clean_text[:300]}".lower())
    fingerprint = hashlib.sha256(" ".join(words_for_fp[:25]).encode("utf-8")).hexdigest()[:16]

    parsed_domain = urlparse(url).netloc.lower().replace("www.", "")
    reg_info = SOURCE_REGISTRY.get(source_id, {})
    title_matches = find_supplier_mentions(clean_title)
    body_matches = find_supplier_mentions(clean_text[:400])

    # Prefer an unambiguous organization explicitly named
    # in the document title. The body can mention competitors,
    # customers and unrelated manufacturers.
    if len(title_matches) == 1:
        supplier_match = title_matches[0]
        supplier_match_basis = "TITLE_UNAMBIGUOUS"

    elif not title_matches and len(body_matches) == 1:
        supplier_match = body_matches[0]
        supplier_match_basis = "BODY_UNAMBIGUOUS"

    else:
        supplier_match = None
        supplier_match_basis = "AMBIGUOUS_OR_NOT_FOUND"

    supplier_candidates = list(dict.fromkeys(
        s["official_name"]
        for s in (*title_matches, *body_matches)
    ))

    with _COLLECTION_LOCK:
        existing = next((d for d in COLLECTED_DOCUMENTS
                         if d.get("canonical_url", d["url"]) == canonical_url), None)
        if existing:
            queries = existing.setdefault("queries_used", [existing.get("query_used", "")])
            if query_used and query_used not in queries:
                queries.append(query_used)
            return existing
        doc_id = f"DOC_{len(COLLECTED_DOCUMENTS) + 1:03d}"
        COLLECTED_URLS.update((url, canonical_url))
        duplicate_text = next((d["doc_id"] for d in COLLECTED_DOCUMENTS
                               if clean_text and d.get("content_sha256") == content_hash), None)
        doc_record = {
            "doc_id": doc_id,
            "global_document_id": hashlib.sha256(
                f"{source_id}:{canonical_url.lower()}".encode()
            ).hexdigest()[:24],
            "source_id": source_id,
            "connector_name": connector_name,
            "url": url,
            "canonical_url": canonical_url,
            "publisher_domain": parsed_domain,
            "origin_type": reg_info.get("origin", "SECONDARY"),
            "source_type": reg_info.get("source_type", "MEDIA"),
            "supplier_registry_candidates": supplier_candidates,
            "supplier_match_basis": supplier_match_basis,
            "verified_domain": bool(reg_info.get("verified_domain", False)),
            "title": clean_title,
            "text": clean_text,
            "content_status": "TEXT_COMPLETENESS_UNVERIFIED",
            "content_sha256": content_hash,
            "content_duplicate_of": duplicate_text,
            "content_truncated": False,
            "content_limit_reason": "",
            "published_at": norm_pub or "DATE_UNKNOWN",
            "raw_published_at": published_at,
            "date_unknown": not bool(norm_pub),
            "event_date": "NOT_ESTABLISHED",
            "event_date_basis": "NOT_ESTABLISHED",
            "collected_at": _now_iso(),
            "query_used": query_used,
            "queries_used": [query_used] if query_used else [],
            "syndication_fingerprint": fingerprint,
            "prompt_injection_flagged": injection_flag or title_inj,
            "pii_redacted_count": pii_redacted,
            "gdpr_legal_basis": reg_info.get("gdpr_legal_basis", "Art. 6(1)(f) GDPR Legitimate Interest (Minimized)"),
            "tos_url": reg_info.get("tos_url", ""),
            "usage_restrictions": reg_info.get("usage_restrictions", ""),
            "supplier_registry_match": supplier_match["official_name"] if supplier_match else None,
            "supplier_default_tier": supplier_match["default_tier"] if supplier_match else None,
        }
        COLLECTED_DOCUMENTS.append(doc_record)
        return doc_record

AIRSHOW_NEWS_URLS = {
    "Farnborough": "https://www.farnboroughairshow.com/resources/news-blogs/",
    "Paris Air Show": "https://www.siae.fr/media/",
    "Dubai Airshow": "https://www.dubaiairshow.aero/usefulinfo/info/news/",
    "Singapore Airshow": "https://www.singaporeairshow.com/media/singapore-airshow-newsroom",
    "ILA Berlin": "https://ila-berlin.com/en/press",
}

AEROSPACE_REGIONS = {
    "North America (US / Canada)": {"gl": "US", "ceid": "US:en", "hl": "en-US"},
    "Europe (EU / UK / France / Germany)": {"gl": "GB", "ceid": "GB:en", "hl": "en-GB"},
    "Asia-Pacific (Singapore / China / Japan / India)": {"gl": "SG", "ceid": "SG:en", "hl": "en-SG"},
    "Middle East (UAE / Qatar / Saudi Arabia)": {"gl": "AE", "ceid": "AE:en", "hl": "en"},
}

COUNTRY_KEYWORDS = {
    "North America (US / Canada)": [
        "united states", "u.s.", "faa", "american", "united airlines", "delta", "jetblue", "canada", "air canada",
    ],
    "Europe (EU / UK / France / Germany)": [
        "europe", "easa", "france", "toulouse", "germany", "hamburg", "uk", "britain", "farnborough", "aegean", "wizz",
        "iberia",
    ],
    "Asia-Pacific (Singapore / China / Japan / India)": [
        "china", "comac", "singapore", "india", "indigo", "qantas", "australia", "japan", "korea", "starlux",
    ],
    "Middle East (UAE / Qatar / Saudi Arabia)": [
        "dubai", "uae", "emirates", "etihad", "flydubai", "abu dhabi", "qatar", "doha", "saudi", "riyadh",
    ],
}

MAX_PAGES_PER_AIRSHOW = min(12, max(1, int(os.getenv('EWS_AIRSHOW_MAX_PAGES', '5'))))
MAX_ARTICLES_PER_AIRSHOW = 15

GENERIC_MANUFACTURERS = {
    "airbus", "boeing", "comac", "embraer", "bombardier", "lockheed",
    "martin", "atr", "dassault", "gulfstream", "cessna", "safran", "rolls-royce", "ge",
}

AIRSHOW_ROUNDUP_KEYWORDS = [
    "deals", "orders", "day one", "day two", "day three", "day 1", "day 2", "day 3",
    "highlights", "wraps up", "fleet", "announces", "milestone", "commercial",
    "proves the future", "partnership", "expansion", "sustainability", "future",
]

IRRELEVANT_TEXT_REGEX = re.compile(
    r"\b(?:careers?|apprentices?|apprenticeships?|graduates?|intern|interns|internships?|"
    r"genz|traffic-arrangements?|transportation-advisory|public-days?|wedding|brewerkz|dorscon|coronavirus)\b|"
    r"(?:was appointed|prior to this,\s+\w+\s+held|in this role\s+(?:she|he)\s+manages)",
    re.IGNORECASE,
)

IRRELEVANT_URL_REGEX = re.compile(
    r"/(?:speakers?|aeroforum|archive|contact-us|faqs?|gallery|book-a-booth|201\d|2020|2021)(?:/|-|$)|"
    r"announces-.*-wave-of-speakers",
    re.IGNORECASE,
)

MONTH_MAP = {
    "jan": 1, "january": 1, "feb": 2, "february": 2, "mar": 3, "march": 3,
    "apr": 4, "april": 4, "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
    "aug": 8, "august": 8, "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10, "nov": 11, "november": 11, "dec": 12, "december": 12,
}

_DATE_RANGE_RE = re.compile(
    r"\b\d{1,2}\s*(?:\([A-Za-z]+\)\s*)?(?:–|-|to)\s*\d{1,2}\s*(?:\([A-Za-z]+\)\s*)?[A-Za-z]+\s+20[12]\d\b", re.IGNORECASE
)
_ISO_DATE_RE = re.compile(r"(20[12]\d-\d{2}-\d{2})")
_ISO_EXACT_RE = re.compile(r"^20[12]\d-\d{2}-\d{2}$")
_ISO_FULL_RE = re.compile(r"(20[12]\d-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_MONTH_NAMES_PAT = r"(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*"
_DMY_RE = re.compile(rf"\b(\d{{1,2}})\s+{_MONTH_NAMES_PAT}\s+(20[12]\d)\b", re.IGNORECASE)
_MDY_RE = re.compile(rf"\b{_MONTH_NAMES_PAT}\s+(\d{{1,2}}),?\s+(20[12]\d)\b", re.IGNORECASE)
_COMPACT_DMY_RE = re.compile(r"(?:airshow|news|pr)[-_]?(\d{2})(\d{2})(202\d)", re.IGNORECASE)
_JSON_DATE_RE = re.compile(
    r'\\?"(?:datePublished|publishedAt|publishDate|articlePublishedTime)\\?"\s*:\s*\\?"(20[12]\d-\d{2}-\d{2})')
_LAYOUT_NOISE_RE = re.compile(r"masthead|footer|sidebar|sitemenu|banner|timer", re.IGNORECASE)
_DATE_CLASS_RE = re.compile(r"blogpost-date|post-date|article-date|publish", re.IGNORECASE)
_VALID_AIRCRAFT_TOKEN_RE = re.compile(
    r"^(?:a(?:220|319|320|321|330|340|350|380)|737|747|757|767|777|787|c919)(?:[a-z0-9-]*)$", re.IGNORECASE
)
_PAGINATION_CONTAINER_RE = re.compile(r"pagin|pager|page-numbers|nav-links", re.IGNORECASE)
_PAGINATION_QUERY_RE = re.compile(r"[?&](?:page|pageNo|pageno|paged|p|start)=([2-9]|\d{2,})\b", re.IGNORECASE)
_PAGINATION_PATH_RE = re.compile(r"/page/([2-9]|\d{2,})(?:/|$|\?)", re.IGNORECASE)
_NOISE_ATTR_RE = re.compile(
    r"cookie|consent|modal|signup|top-signup|mega-menu|navbar|"
    r"sitemenu_area|masthead_area|masthead2_area|sidebar_area|footer_area|mobile-menu|path_box",
    re.IGNORECASE,
)
_CARD_ANCHOR_RE = re.compile(r"BlockWrapper_anchor|informa-module-block")

# Read the active per-query retrieval budget.
def get_dynamic_limit() -> int:
    return int(os.getenv("EWS_DYNAMIC_LIMIT", 5))

# Resolve the monitoring reference date used for current and replay scopes.
def get_reference_now_utc() -> datetime:
    as_of = os.getenv("EWS_AS_OF_DATE", "").strip()
    if as_of:
        try:
            if "T" in as_of:
                dt = datetime.fromisoformat(as_of)
                return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
            return datetime.strptime(as_of[:10], "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=UTC)
        except Exception:
            pass
    return datetime.now(UTC)

# Translate normalized monitoring scope into an optional day limit.
def get_scope_days() -> int | None:
    scope_enum = normalize_scope_value(os.getenv("EWS_DYNAMIC_SCOPE", "7d"))
    mapping = {
        AnalysisScope.LAST_24_HOURS: 1,
        AnalysisScope.LAST_7_DAYS: 7,
        AnalysisScope.LAST_30_DAYS: 30,
        AnalysisScope.LAST_90_DAYS: 90,
        AnalysisScope.LAST_365_DAYS: 365,
    }
    if scope_enum == AnalysisScope.CUSTOM:
        start_dt, end_dt = get_time_window_utc()
        if start_dt and end_dt:
            return max(1, (end_dt - start_dt).days)
    return mapping.get(scope_enum)

# Calculate the active UTC retrieval window from request scope.
def get_time_window_utc() -> tuple[datetime | None, datetime]:
    # Compute consistent UTC date bounds for all collection channels.
    end_utc = get_reference_now_utc()
    scope_enum = normalize_scope_value(os.getenv("EWS_DYNAMIC_SCOPE", "7d"))
    custom_from = os.getenv("EWS_DATE_FROM", "").strip()
    custom_to = os.getenv("EWS_DATE_TO", "").strip()

    if scope_enum == AnalysisScope.CUSTOM and custom_to:
        try:
            end_utc = datetime.strptime(custom_to[:10], "%Y-%m-%d").replace(hour=23, minute=59, second=59,
                                                                            tzinfo=UTC)
        except ValueError:
            pass

    if scope_enum == AnalysisScope.CUSTOM and custom_from:
        try:
            return datetime.strptime(custom_from[:10], "%Y-%m-%d").replace(tzinfo=UTC), end_utc
        except ValueError:
            pass

    if scope_enum == AnalysisScope.ALL:
        return None, end_utc
    if scope_enum == AnalysisScope.LAST_24_HOURS:
        return end_utc - timedelta(hours=24), end_utc
    return end_utc - timedelta(days=get_scope_days() or 7), end_utc

# Parse source timestamps into normalized timezone-aware UTC values.
def parse_datetime_utc(date_str: str) -> datetime | None:
    if not date_str or date_str in {"N/A", "Unknown", "DATE_UNKNOWN"} or "unknown" in date_str.lower():
        return None
    raw = date_str.strip()
    try:
        parsed_rss = email.utils.parsedate_to_datetime(raw)
        return (parsed_rss if parsed_rss.tzinfo else parsed_rss.replace(tzinfo=UTC)).astimezone(UTC)
    except Exception:
        pass

    if iso_full := _ISO_FULL_RE.search(raw):
        try:
            dt = datetime.fromisoformat(iso_full.group(1))
            return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
        except Exception:
            pass

    norm = normalize_date_str(raw)
    if norm and _ISO_EXACT_RE.match(norm):
        try:
            return datetime.strptime(norm, "%Y-%m-%d").replace(hour=12, minute=0, second=0, tzinfo=UTC)
        except ValueError:
            return None
    return None

# Reject records outside the configured time window.
def is_date_within_scope(date_str: str) -> bool:
    start_utc, end_utc = get_time_window_utc()
    max_allowed_future = end_utc + timedelta(hours=6)

    parsed_dt = parse_datetime_utc(date_str)
    if parsed_dt is not None:
        if parsed_dt > max_allowed_future:
            logger.debug(f"[DATE FILTER] Rejected future-dated record: {date_str} > {end_utc.isoformat()}")
            return False
        if start_utc is None:
            return True
        scope_enum = normalize_scope_value(os.getenv("EWS_DYNAMIC_SCOPE", "7d"))
        if scope_enum == AnalysisScope.LAST_24_HOURS and ("T" in date_str or ":" in date_str):
            return start_utc <= parsed_dt <= max_allowed_future
        return start_utc.date() <= parsed_dt.date() <= max_allowed_future.date()

    if start_utc is None:
        year_match = re.search(r"\b(20[12]\d)\b", date_str or "")
        return not (year_match and int(year_match.group(1)) > end_utc.year)
    return False

# Discard clearly unrelated text before higher-cost analysis.
def smart_context_filter(full_text: str, query_keywords: list) -> str:
    core_keywords = [k.lower() for k in query_keywords] + [
        "airbus", "boeing", "supplier", "safety", "delay", "defect",
        "easa", "faa", "titanium", "engine", "spirit", "pratt",
    ]
    relevant = [p.strip() for p in full_text.split("\n") if
                len(p) > 40 and any(kw in p.lower() for kw in core_keywords)]
    filtered = "\n".join(relevant)
    return filtered[:5000] if filtered else full_text[:1000]

# Normalize a source publication date into a stable representation.
def normalize_date_str(raw_str: str) -> str:
    if not raw_str:
        return ""
    cleaned = _DATE_RANGE_RE.sub("", raw_str.strip())

    if iso_match := _ISO_DATE_RE.search(cleaned):
        return iso_match.group(1)

    if dmy_match := _DMY_RE.search(cleaned):
        day, month, year = int(dmy_match.group(1)), MONTH_MAP.get(dmy_match.group(2).lower()[:3], 1), int(
            dmy_match.group(3))
        if 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"

    if mdy_match := _MDY_RE.search(cleaned):
        month, day, year = MONTH_MAP.get(mdy_match.group(1).lower()[:3], 1), int(mdy_match.group(2)), int(
            mdy_match.group(3))
        if 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"

    if compact_dmy := _COMPACT_DMY_RE.search(cleaned):
        day, month, year = int(compact_dmy.group(1)), int(compact_dmy.group(2)), int(compact_dmy.group(3))
        if 1 <= month <= 12 and 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"

    return ""

# Discover publication time from available article metadata.
# Extract publication metadata without assuming missing dates are current.
def extract_article_date(
        raw_html: str, clean_article_text: str = "", url: str = "", fallback_date: str = ""
) -> str:
    if fallback_date and _ISO_EXACT_RE.match(fallback_date):
        return fallback_date
    if safe_json_date := _JSON_DATE_RE.search(raw_html):
        return safe_json_date.group(1)

    soup = BeautifulSoup(raw_html, "html.parser")
    for meta_prop in ("article:published_time", "og:published_time", "publish-date", "date"):
        meta = soup.find("meta", attrs={"property": meta_prop}) or soup.find("meta", attrs={"name": meta_prop})
        if meta and meta.get("content") and (norm := normalize_date_str(meta["content"])):
            return norm

    for tag in soup(["header", "footer", "nav", "aside", "script", "style"]):
        tag.extract()
    for el in soup.find_all(attrs={"class": _LAYOUT_NOISE_RE}):
        el.extract()

    if (time_tag := soup.find("time")) and (
            norm := normalize_date_str(time_tag.get("datetime", "") or time_tag.get_text(" ", strip=True))):
        return norm

    for date_el in soup.find_all(attrs={"class": _DATE_CLASS_RE}):
        if norm := normalize_date_str(date_el.get_text(" ", strip=True)):
            return norm

    for candidate in (clean_article_text[:600], fallback_date, url):
        if candidate and (norm := normalize_date_str(candidate)):
            return norm

    return "DATE_UNKNOWN"

# Preserve the legacy search-query API for existing callers.
from aero_ews.collection.queries import (
    _model_tokens,
    build_social_video_queries,
    get_program_engine_domain,
)
from aero_ews.collection.queries import (
    news_api_search_key as _compile_newsapi_query,
)
from aero_ews.domain.identity import (
    EntityType,
    IdentityStatus,
    resolve_technical_identity,
)


def news_api_search_key(query: str) -> str:
    """Keep the established query API while delegating its implementation."""
    return _compile_newsapi_query(query)


@dataclass(frozen=True)
class ModelIdentity:
    kind: str
    canonical_id: str
    aliases: tuple[str, ...]


def _model_identities(query: str) -> list[ModelIdentity]:
    """Keep verified catalog labels separate from syntactically detected model codes."""
    candidates = list(_model_tokens(query))
    candidates.extend(match.group() for match in re.finditer(
        r"(?<!\w)737[ -]*(?:MAX[ -]*)?(?:7|8|9|10)(?!\w)"
        r"|(?<!\w)A\d{3}[ -]*(?:NEO|XLR)(?!\w)"
        r"|(?<!\w)LEAP[ -]*1[ -]*[AB](?!\w)", query, re.IGNORECASE,
    ))
    if not candidates:
        subject = resolve_technical_identity(query)
        if (subject.resolution_status == IdentityStatus.MATCH
                and subject.entity_type in {EntityType.AIRCRAFT, EntityType.ENGINE}):
            candidates.append(subject.canonical_identity)
    identities = {}
    for value in candidates:
        normalized = re.sub(r"[^A-Z0-9]", "", value.upper())
        if match := re.fullmatch(r"737(?:MAX)?(7|8|9|10)", normalized):
            variant = match.group(1)
            identity = ModelIdentity("aircraft_model", f"737-MAX-{variant}", (
                f"737 MAX {variant}", f"737 MAX-{variant}", f"737-{variant}", f"B737-{variant}",
            ))
        elif match := re.fullmatch(r"LEAP1([AB])", normalized):
            suffix = match.group(1)
            identity = ModelIdentity("engine_model", f"LEAP-1{suffix}", (
                f"LEAP-1{suffix}", f"LEAP 1{suffix}",
            ))
        else:
            resolved = resolve_technical_identity(str(value))
            kind = ({EntityType.AIRCRAFT: "aircraft_model", EntityType.ENGINE: "engine_model"}
                    .get(resolved.entity_type) if resolved.resolution_status == IdentityStatus.MATCH
                    else None)
            identity = ModelIdentity(kind or "unknown_technical_identifier",
                                     resolved.canonical_identity if kind == "engine_model" else normalized,
                                     tuple(dict.fromkeys((str(value), *resolved.candidate_aliases))) if kind
                                     else (str(value),))
        identities[identity.canonical_id] = identity
    # A generic family token must not dilute an explicitly selected variant.
    return [item for item in identities.values() if not any(
        item.canonical_id != other.canonical_id
        and other.canonical_id.startswith(item.canonical_id)
        for other in identities.values()
    )]


def _model_matches(identity: ModelIdentity, text: str) -> bool:
    return any(_model_alias_pattern(alias).search(text) for alias in identity.aliases)


@lru_cache(maxsize=256)
def _model_alias_pattern(alias: str) -> re.Pattern:
    return re.compile(
        r"(?<![a-z0-9])" + r"[\s-]*".join(map(re.escape, re.findall(r"[A-Za-z]+|\d+", alias)))
        + r"(?![a-z0-9])", re.IGNORECASE,
    )


_NEWS_STATUS_TOPICS = {
    "certif": "certified OR granted OR approved OR completed",
    "deliver": "resumed OR restored OR backlog OR completed",
    "produc": "resumed OR restarted OR restored OR halted",
    "strike": "ended OR settled OR resumed OR agreement",
    "shortag": "restored OR recovered OR resolved OR resumed",
    "supply": "restored OR recovered OR resolved OR resumed",
    "defect": "fixed OR resolved OR repaired OR cleared",
    "ground": "lifted OR resumed OR restored",
    "delay": "resumed OR restored OR completed OR cancelled",
    "order": "cancelled OR reinstated OR confirmed",
    "engine": "engine OR engines OR turbine OR PW1100G OR GTF OR LEAP",
    "turbine": "turbine OR HPT OR disk OR blade OR inspection",
    "inspect": "inspection OR airworthiness OR directive OR maintenance",
    "directiv": "directive OR airworthiness OR FAA OR EASA",
    "problem": "problems OR issues OR defect OR grounded OR inspection",
    "issue": "issues OR problems OR defect OR grounded OR inspection",
    "powder": "powder OR metal OR GTF OR PW1100G OR inspection",
}

_NEWS_NOISE_DOMAINS = frozenset({
    "onemileatatime.com", "thealviator.com", "dansdeals.com", "wimp.com",
    "motorbiscuit.com", "gizmodo.com",
})


def _newsapi_search_stages(query: str) -> list[tuple[str, str]]:
    identities = _model_identities(query)
    exact = news_api_search_key(query)
    alternative = _compile_newsapi_query(query, mode="alternative")
    recall = _compile_newsapi_query(query, mode="recall")
    aliases = list(dict.fromkeys(alias for item in identities for alias in item.aliases))[:8]
    entity = next((name for name in ("Airbus", "Boeing") if re.search(rf"\b{name}\b", query, re.IGNORECASE)), "")
    subject = "(" + " OR ".join(f'"{alias}"' for alias in aliases) + ")" if aliases else (
        f'"{entity}"' if entity else ""
    )
    topics = [(name, match.group()) for name in _NEWS_STATUS_TOPICS
              if (match := re.search(rf"\b\w*{name}\w*\b", query, re.IGNORECASE))]
    topic_query = " OR ".join(f'"{term}"' for _, term in topics[:3])
    state_query = " OR ".join(dict.fromkeys(
        term.strip() for topic, _ in topics[:2]
        for term in _NEWS_STATUS_TOPICS[topic].split(" OR ")
    ))
    stages = [("EXACT", exact)]
    if alternative and alternative != exact:
        stages.append(("ALTERNATIVE", alternative))
    if recall and recall not in {exact, alternative}:
        stages.append(("RECALL", recall))
    if subject:
        if topic_query:
            stages.append(("ALIASES", f"{subject} AND ({topic_query})"))
        if state_query:
            stages.append(("STATUS_CHANGE", f"{subject} AND ({state_query})"))
        # Nikdy nespouštěj holý CONTEXT bez rizikové/technické kotvy, jinak se kvóta zahltí cestovatelskými blogy.
        if not topics:
            stages.append((
                "CONTEXT",
                f"{subject} AND (engine OR defect OR delay OR inspection OR directive OR shortage OR grounded OR safety)",
            ))
    return [(name, expression) for index, (name, expression) in enumerate(stages)
            if expression and expression not in {q for _, q in stages[:index]}]

_STOP_WORDS = {
    "find", "search", "show", "tell", "about", "this", "what",
    "are", "the", "latest", "new", "from", "with", "for", "and",
}

# Derive search intent without discarding explicit aircraft or engine identifiers.
# Preserve model-specific terms while normalizing search intent.
def parse_query_intent(safe_query: str) -> tuple[list[str], str]:
    # Keep exact technical model tokens when deriving search intent.
    """Preserve explicit aircraft and engine identifiers while parsing search intent."""
    detected_specific_models: list[str] = []
    remaining_query = safe_query.lower()

    for identity in _model_identities(safe_query):
        detected_specific_models.append(identity.aliases[0])
        for alias in identity.aliases:
            remaining_query = _model_alias_pattern(alias).sub(" ", remaining_query)

    words = [w.lower() for w in re.findall(r"\b\w+\b", remaining_query)]
    significant_words = [w for w in words if (any(c.isdigit() for c in w) or len(w) > 3) and w not in _STOP_WORDS]

    expanded_words = list(detected_specific_models)
    models_for_search = list(detected_specific_models)

    for w in significant_words:
        if w not in expanded_words:
            expanded_words.append(w)
        if not detected_specific_models:
            if model_match := re.match(r"^([a-z]?\d{3})(?:[a-z]+|\d+)$", w):
                models_for_search.append(w)
                base_model = model_match.group(1)
                if base_model not in expanded_words:
                    expanded_words.append(base_model)
            elif any(c.isdigit() for c in w):
                models_for_search.append(w)
        elif any(c.isdigit() for c in w) and w not in models_for_search:
            models_for_search.append(w)

    has_specific_model = bool(detected_specific_models) or any(any(c.isdigit() for c in w) for w in expanded_words)
    required_words = [w for w in expanded_words if
                      w not in GENERIC_MANUFACTURERS] if has_specific_model else expanded_words
    if not required_words:
        required_words = words or [""]

    text_words = [w for w in required_words if w not in detected_specific_models and not any(c.isdigit() for c in w)]
    models_for_search = [m for m in models_for_search if any(c.isdigit() for c in m)]
    search_candidates = (models_for_search + text_words)[:3]
    return required_words, (" ".join(search_candidates) if search_candidates else safe_query)

# Retain only article paragraphs that provide useful KIT context.
# Exclude boilerplate but retain source passages relevant to the KIT.
def filter_relevant_paragraphs(text: str, required_words: list[str]) -> str:
    if not text or not required_words or required_words == [""]:
        return ""

    lines = [line.strip() for line in text.split("\n") if line.strip()]
    matched_chunks, seen_normalized = [], set()
    skip_next = False
    num_words = [rw for rw in required_words if any(c.isdigit() for c in rw)]

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        line_lower = line.lower()
        if "this website uses cookies" in line_lower or "... ..." in line_lower:
            continue
        if line.startswith(("·", "•")) and len(line) < 100:
            continue

        is_heading = line.startswith("### ")
        if not is_heading:
            first_alpha = next((ch for ch in line if ch.isalpha()), "")
            if len(line) < 80 or (first_alpha and first_alpha.islower()):
                continue

        if IRRELEVANT_TEXT_REGEX.search(line_lower):
            continue

        next_line = lines[i + 1] if (is_heading and i + 1 < len(lines) and not lines[i + 1].startswith("### ")) else ""
        combined_block = f"{line}\n{next_line}".strip() if next_line else line
        combined_lower = combined_block.lower()

        if IRRELEVANT_TEXT_REGEX.search(combined_lower):
            continue

        if any(nw in combined_lower for nw in num_words) or sum(
                1 for rw in required_words if rw in combined_lower) >= min(2, len(required_words)):
            norm_key = re.sub(r"[^a-z0-9]", "", combined_lower)
            if norm_key not in seen_normalized:
                seen_normalized.add(norm_key)
                if next_line:
                    seen_normalized.add(re.sub(r"[^a-z0-9]", "", next_line.lower()))
                    skip_next = True
                matched_chunks.append(combined_block)

    return "\n\n".join(matched_chunks)

# Remove navigation, ads, and page boilerplate from source HTML.
# Page text extraction is a collection step, not fact verification.
def extract_clean_blocks(soup: BeautifulSoup, base_url: str) -> tuple[str, list[dict], list[str]]:
    # Extract substantive article passages while filtering page navigation noise.
    pagination_urls = []
    base_domain = urlparse(base_url).netloc

    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full_href = urljoin(base_url, href)
        a_text = a_tag.get_text(strip=True).lower()
        classes_str = f"{' '.join(a_tag.parent.get('class', [])) if a_tag.parent else ''} {' '.join(a_tag.get('class', []))}"
        in_pag = bool(_PAGINATION_CONTAINER_RE.search(classes_str))

        if urlparse(full_href).netloc == base_domain and full_href != base_url:
            if (
                    _PAGINATION_QUERY_RE.search(full_href)
                    or _PAGINATION_PATH_RE.search(full_href)
                    or a_text in {"next", "next page", "›", "»", "older posts", "more"}
                    or (in_pag and a_text.isdigit() and int(a_text) >= 2)
            ) and full_href not in pagination_urls:
                pagination_urls.append(full_href)

    if "farnboroughairshow.com" in base_domain:
        for li_tag in soup.find_all("li", attrs={"data-page": True}):
            page_num = str(li_tag["data-page"]).strip()
            if page_num.isdigit() and 2 <= int(page_num) <= MAX_PAGES_PER_AIRSHOW:
                fia_ajax_url = (
                    f"https://www.farnboroughairshow.com/umbraco/surface/blog/GetBlog"
                    f"?ViewId=1157&category=ALL&viewName=Blog/LoadBlogs&pageNo={page_num}"
                )
                if fia_ajax_url not in pagination_urls:
                    pagination_urls.append(fia_ajax_url)

    for tag in soup(
            ["script", "style", "nav", "footer", "header", "noscript", "svg", "form", "button", "iframe", "aside"]):
        tag.extract()
    for attr in ("id", "class"):
        for el in soup.find_all(attrs={attr: _NOISE_ATTR_RE}):
            el.extract()

    for block in soup.find_all("div", class_="pageblock_box"):
        h2 = block.find("h2")
        if h2 and h2.get_text(strip=True).isdigit() and int(h2.get_text(strip=True)) < 2022:
            block.extract()

    text_blocks, seen_texts, article_links, seen_urls = [], set(), [], set()

    # Insert a discovered link only when it passes the existing candidate checks.
    def add_candidate_link(title: str, raw_href: str, context_str: str, card_date: str = ""):
        full_u = urljoin(base_url, raw_href)
        if full_u not in seen_urls and urlparse(full_u).netloc == base_domain:
            seen_urls.update((raw_href, full_u))
            article_links.append({
                "title": title.strip(), "url": full_u,
                "context": context_str[:350].lower(), "date": card_date,
            })

    for td in soup.find_all("td"):

        # ILA Berlin: extract official press-release cards
        # and convert European DD/MM/YYYY publication dates.
        if "ila-berlin.com" in base_domain:
            for row in soup.select("a.pml-row[href]"):
                href = row.get("href", "")
                absolute = urljoin(base_url, href)

                if not urlparse(absolute).path.startswith('/en/press/releases/'):
                    continue

                heading = row.select_one(".pml-body strong")
                title = heading.get_text(' ', strip=True) if heading else row.get_text(' ', strip=True)

                body_element = row.select_one(".pml-body")
                context = body_element.get_text(' ', strip=True) if body_element else title

                raw_date = row.select_one(".pml-date")
                card_date = ""

                if raw_date:
                    date_text = raw_date.get_text(' ', strip=True)
                    try:
                        card_date = datetime.strptime(date_text, '%d/%m/%Y').date().isoformat()
                    except ValueError:
                        pass

                add_candidate_link(title, href, context, card_date)
        if h3 := td.find("h3"):
            raw_h4 = td.find("h4").get_text(strip=True) if td.find("h4") else ""
            card_date = normalize_date_str(raw_h4) if not re.match(r"^\d+\.", raw_h4) else ""
            td_text = td.get_text(separator=" | ", strip=True)
            if len(td_text) > 40 and td_text not in seen_texts:
                seen_texts.add(td_text)
                text_blocks.append(td_text)
            if a_tag := h3.find("a", href=True):
                add_candidate_link(a_tag.get_text(strip=True), a_tag["href"], td_text, card_date)

    for card_a in soup.find_all("a", class_=_CARD_ANCHOR_RE, href=True):
        card_text = card_a.get_text(separator=" | ", strip=True)
        href = card_a["href"]
        img_src = card_a.find("img").get("src", "") if card_a.find("img") else ""
        card_date = normalize_date_str(href) or normalize_date_str(img_src)
        if len(card_text) > 20 and card_text not in seen_texts:
            seen_texts.add(card_text)
            text_blocks.append(card_text)
        add_candidate_link(card_text, href, card_text, card_date)

    for element in soup.find_all(["h1", "h2", "h3", "h4", "p", "li", "div"]):
        if element.name == "div" and element.find(["p", "h1", "h2", "h3", "h4", "div", "table", "ul"]):
            continue
        text = element.get_text(separator=" ", strip=True)
        is_heading = element.name in ("h1", "h2", "h3", "h4")
        if len(text) >= (12 if is_heading else 40) and text not in seen_texts:
            seen_texts.add(text)
            text_blocks.append(f"### {text}" if is_heading else text)

    is_search_page = "search" in base_url.lower() or "o.x" in base_url.lower()
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full_url = urljoin(base_url, href)
        if full_url in seen_urls:
            continue
        parsed = urlparse(full_url)
        path_parts = [p for p in parsed.path.split("/") if p]
        if parsed.netloc == base_domain and len(path_parts) >= 2 and not full_url.lower().endswith(
                (".pdf", ".jpg", ".png", ".svg", ".webp")):
            a_title = a_tag.get_text(" ", strip=True) or path_parts[-1]
            parent_text = a_tag.parent.get_text(" ", strip=True) if a_tag.parent else a_title
            ctx_text = parent_text if len(parent_text) <= 350 else a_title
            card_date = normalize_date_str(full_url) if is_search_page else (
                    normalize_date_str(ctx_text) or normalize_date_str(full_url))
            add_candidate_link(a_title, href, ctx_text, card_date)

    return "\n".join(text_blocks), article_links, pagination_urls

# Extract the substantive body text of a retrieved publisher article.
def _extract_news_article_body(html_text: str) -> str:
    """Extract article paragraphs and exclude unrelated page navigation, recommendations and sidebars."""
    soup = BeautifulSoup(html_text, "html.parser")
    for node in soup.select(
            "script, style, noscript, nav, header, footer, aside, form, "
            "[role='navigation'], [class*='related'], [class*='recommend'], [class*='advert'], [id*='related']"
    ):
        node.decompose()

    for selector in (
            "[itemprop='articleBody']",
            "[data-module='ArticleBody']",
            "[class*='ArticleBody']",
            ".wd_body",
            ".wd_news_body",
            ".wd_newsfeed_releases-detail",
            ".wd_content",
            "[class*='release-body']",
            "[class*='press-release']",
            "article",
            "[class*='article-body']",
            "[class*='story-body']",
            "main",
    ):
        candidates = []
        for node in soup.select(selector):
            content = "\n".join(
                p.get_text(" ", strip=True) for p in node.find_all("p") if len(p.get_text(" ", strip=True)) >= 35)
            if len(content) >= 120:
                candidates.append(content)
        if candidates:
            return max(candidates, key=len)
    fallback_p = "\n".join(
        p.get_text(" ", strip=True) for p in soup.find_all("p")
        if len(p.get_text(" ", strip=True)) >= 45
    )
    return fallback_p if len(fallback_p) >= 220 else ""

# Combine precise and conditional broad NewsAPI searches with deduplication.
# Conditional recall search can broaden results; it does not bypass relevance screening.
# Recall broadening does not override source scope or later relevance gates.
@tool("Search Aerospace News and Read Full Articles")
def search_aerospace_news(query: str) -> str:
    # Search the news source using a primary query and guarded recall fallback.
    """Query News API preserving specific aircraft model suffixes (e.g., 777X, A321XLR)."""
    if (
        os.getenv("EWS_ENV", "development").lower()
        not in {"dev", "development", "test"}
        and os.getenv("EWS_NEWSAPI_PRO_LICENSE") != "1"
    ):
        record_connector_telemetry("News API", "SRC_004", query,
                                   operational_status=NewsAPIState.ACCESS_RESTRICTED.value,
                                   search_outcome="NOT_EXECUTED", error="LICENSE_REQUIRED")
        return "News API: ACCESS_RESTRICTED (production license required)."
    safe_query = query.replace(",", "").replace("  ", " ").strip()
    if not safe_query:
        record_connector_telemetry("News API", "SRC_004", query,
                                   operational_status="MISCONFIGURED", search_outcome="NOT_EXECUTED",
                                   error="EMPTY_QUERY")
        return "News API: MISCONFIGURED (empty query)."
    and_query = news_api_search_key(safe_query)
    key = _newsapi_key()
    state = _newsapi_current_state(key, and_query)
    if state != NewsAPIState.AVAILABLE:
        record_connector_telemetry("News API", "SRC_004", safe_query,
                                   error=f"CONNECTOR_{state.value}", operational_status=state.value,
                                   search_outcome="NOT_EXECUTED")
        return f"News API: {state.value} (search not executed)."
    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()

    logger.info(
        f"[OSINT GATHERER] Querying News API for: '{and_query}' "
        f"(limit: {limit}, from: {start_utc.strftime('%Y-%m-%d') if start_utc else 'unrestricted'})"
    )
    params: dict[str, Any] = {
        "q": and_query,
        "language": "en",
        "sortBy": "relevancy",
        "pageSize": min(100, limit * 4),
        "to": end_utc.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    # A plan-limited publication archive is never equivalent to the KIT window.
    archive_days = max(1, int(os.getenv("EWS_NEWSAPI_HISTORY_DAYS", "29")))
    earliest = datetime.now(UTC) - timedelta(days=archive_days)
    effective_start = max(filter(None, (start_utc, earliest)))
    partial_window = start_utc is None or effective_start > start_utc
    searchable_days = round(max(0.0, (end_utc - effective_start).total_seconds() / 86400), 2)
    window_unavailable = effective_start > end_utc
    window = {
        "requested_from": start_utc.date().isoformat() if start_utc else "UNRESTRICTED",
        "requested_to": end_utc.date().isoformat(),
        "searchable_from": None if window_unavailable else effective_start.isoformat(),
        "searchable_to": None if window_unavailable else end_utc.isoformat(),
        "actual_from": None if window_unavailable else effective_start.date().isoformat(),
        "actual_to": None if window_unavailable else end_utc.date().isoformat(),
        "actual_window_basis": "CONFIGURED_SEARCH_WINDOW_NOT_RETRIEVAL_VERIFIED",
        "actual_searchable_days": searchable_days,
        "requested_horizon_days": round((end_utc - start_utc).total_seconds() / 86400, 2) if start_utc else None,
        "provider_archive_limit_days": archive_days,
        "provider_limit_basis": "CONFIGURED_PLAN_WINDOW_NOT_API_VERIFIED",
        "coverage_status": ("WINDOW_UNAVAILABLE" if window_unavailable
                            else "PARTIAL_WINDOW" if partial_window else "WITHIN_PLAN_LIMIT"),
        "source_coverage": ("UNAVAILABLE" if window_unavailable
                            else "PARTIAL" if partial_window else "UNVERIFIED"),
        "coverage_complete": False,  # Search budget/results cannot prove exhaustive coverage.
        "date_basis": "PUBLICATION_DATE",
        "event_date_coverage": "NOT_ESTABLISHED",
    }
    coverage_line = (f"[NEWSAPI_COVERAGE] {window['source_coverage']}; "
                     f"requested_days={window['requested_horizon_days']}; "
                     f"configured_searchable_days={searchable_days}; "
                     "provider_window_not_independently_verified\n")
    if partial_window:
        logger.warning("[NEWS API COVERAGE] Requested publication period is not fully accessible: %s", window)
    if effective_start > end_utc:
        record_connector_telemetry(
            "News API", "SRC_004", safe_query,
            operational_status=NewsAPIState.ACCESS_RESTRICTED.value,
            search_outcome="NOT_EXECUTED", coverage_window=window,
            coverage_note="NEWSAPI_WINDOW_UNAVAILABLE: source plan excludes requested dates",
        )
        return coverage_line + "News API: ACCESS_RESTRICTED (requested publication period not searchable)."
    params["from"] = effective_start.strftime("%Y-%m-%dT%H:%M:%S")

    logger.info(
        "[NEWS API REQUEST] primary=%r from=%s to=%s",
        and_query,
        params.get("from", "unrestricted"),
        params["to"],
    )

    identities = _model_identities(safe_query)
    articles, seen_urls, searched_stages, stage_errors = [], set(), [], []
    budget = min(4, max(1, int(os.getenv("EWS_NEWSAPI_QUERY_BUDGET", "2"))))
    coverage_target = min(8, max(3, limit))
    recall_state = NewsAPIState.AVAILABLE
    for stage, expression in _newsapi_search_stages(safe_query)[:budget]:
        coverage = sum(
            not identities or any(_model_matches(identity, f"{a.get('title', '')} {a.get('description', '')}")
                                  for identity in identities)
            for a in articles
        )
        if stage != "EXACT" and coverage >= coverage_target:
            break
        stage_params = {**params, "q": expression}
        cache_key = (expression, params["from"], params["to"], params["pageSize"],
                     hashlib.sha256(key.encode()).hexdigest()[:16])
        with _COLLECTION_LOCK:
            cached = NEWS_FALLBACK_CACHE.get(cache_key) if stage != "EXACT" else None
        if cached is None:
            payload, current_state, code = _newsapi_request(stage_params, key)
            if payload is None:
                recall_state = current_state
                stage_errors.append(f"{stage}:{current_state.value}:{code}")
                if stage == "EXACT":
                    record_connector_telemetry(
                        "News API", "SRC_004", safe_query, error=stage_errors[-1],
                        operational_status=current_state.value, search_outcome="RETRIEVAL_FAILED",
                        coverage_window=window,
                        coverage_note=f"NEWSAPI_COVERAGE={window['coverage_status']}; archive_limit_days={archive_days}",
                    )
                    return coverage_line + f"News API: {current_state.value} (source unavailable; {code})."
                break  # Do not retry a blocked or exhausted source with broader queries.
            cached = payload["articles"]
            if stage != "EXACT":
                with _COLLECTION_LOCK:
                    NEWS_FALLBACK_CACHE[cache_key] = list(cached)
        searched_stages.append(stage)
        for article in cached:
            url = article.get("url")
            if url and url not in seen_urls:
                articles.append(article)
                seen_urls.add(url)
        logger.info("[NEWS API STAGE] %s candidates=%d cumulative=%d", stage, len(cached), len(articles))

    recall_failed = bool(stage_errors)
    articles.sort(key=lambda item: (
        any(_model_matches(identity, f"{item.get('title', '')} {item.get('description', '')}")
            for identity in identities) if identities else True,
        str(item.get("publishedAt") or ""),
    ), reverse=True)
    if not articles and recall_failed:
        record_connector_telemetry(
            "News API", "SRC_004", safe_query, error="; ".join(stage_errors),
            operational_status=recall_state.value, search_outcome="PARTIAL_RESULT",
            coverage_window=window,
            coverage_note=f"NEWSAPI_COVERAGE={window['coverage_status']}; archive_limit_days={archive_days}",
        )
        return coverage_line + "News API: PARTIAL_RESULT (search coverage incomplete; no documents retrieved)."

    extracted_content = ""
    query_words = [w.lower() for w in safe_query.split() if len(w) > 2]
    count = rejected_scope = unknown_dates = rejected_missing_url = rejected_duplicate = model_unconfirmed = metadata_only = 0
    observed_dates: list[str] = []

    for article in articles:
        if count >= limit:
            break

        article_url = article.get("url", "")
        if not article_url:
            rejected_missing_url += 1
            continue
        article_host = (urlparse(article_url).hostname or "").lower().removeprefix("www.")
        if any(article_host == d or article_host.endswith("." + d) for d in _NEWS_NOISE_DOMAINS):
            rejected_scope += 1
            continue
        if article_url in COLLECTED_URLS:
            rejected_duplicate += 1
            continue

        title = article.get("title") or "Untitled"
        desc = article.get("description") or ""
        raw_date = article.get("publishedAt", "DATE_UNKNOWN")
        if not is_date_within_scope(raw_date):
            rejected_scope += 1
            continue

        pub_date = raw_date.split("T")[0] if "T" in raw_date else raw_date
        normalized_pub_date = normalize_date_str(pub_date)
        if not normalized_pub_date:
            unknown_dates += 1

        # Retrieve full article bodies when permitted; mark metadata-only results honestly.
        body_text = ""
        body_complete = False
        page_resp = safe_http_get(article_url, source_id="SRC_004", timeout=10, check_robots=True)
        if page_resp is not None and page_resp.status_code == 200:
            content_type = page_resp.headers.get("Content-Type", "").lower()
            if "text/html" in content_type or not content_type:
                # Attempt publisher-body extraction only after the network and access checks succeed.
                article_body = _extract_news_article_body(page_resp.text)
                title_terms = {
                    w for w in re.findall(r"[a-z]{4,}", title.lower())
                    if w not in {"with", "from", "that", "this", "over", "about", "after", "into", "years"}
                }
                body_terms = set(re.findall(r"[a-z]{4,}", article_body.lower()))
                if article_body and (not title_terms or title_terms & body_terms):
                    body_text = smart_context_filter(article_body, query_words)
                    body_complete = (body_text.strip() == article_body.strip()
                                     and not getattr(page_resp, "aero_content_truncated", False))
                elif article_body:
                    logger.warning("[NEWS BODY MISMATCH] %s: title does not match article text", article_url)

        if not body_text:
            metadata_only += 1
            body_text = (
                    "[NEWSAPI_METADATA_ONLY: PUBLISHER ARTICLE TEXT UNAVAILABLE]\n"
                    + (desc.strip() or "No article description available.")
            )

        if identities and not any(_model_matches(identity, f"{title} {desc} {body_text}")
                                  for identity in identities):
            model_unconfirmed += 1
            logger.info(
                "[NEWS API SCOPE REVIEW] Exact target not established in %r; retaining for FR03.",
                title[:100],
            )

        doc = register_collected_document(
            source_id="SRC_004", connector_name="News API", url=article_url,
            title=title, raw_text=body_text, published_at=pub_date, query_used=safe_query,
        )
        excerpted = not body_complete and not body_text.startswith("[NEWSAPI_METADATA_ONLY:")
        doc.update(content_status="FULL_TEXT" if body_complete else
                   "PARTIAL_TEXT" if excerpted else "METADATA_ONLY",
                   content_truncated=excerpted,
                   content_limit_reason="EXCERPT_SELECTION" if excerpted else "",
                   event_date="NOT_ESTABLISHED", event_date_basis="PUBLICATION_DATE_ONLY")
        if normalized_pub_date:
            observed_dates.append(normalized_pub_date)
        extracted_content += (
                f"\n<untrusted_osint_document id=\"{doc['doc_id']}\" source_id=\"SRC_004\">\n"
                f"DOC_ID: {doc['doc_id']}\n"
                f"DATE: {doc['published_at']}\n"
                f"COLLECTED_AT: {doc['collected_at']}\n"
                f"TITLE: {doc['title']}\n"
                f"SOURCE: {article_url}\n"
                f"CONTENT: {doc['text']}...\n"
                f"</untrusted_osint_document>\n"
                + ("-" * 40) + "\n"
        )
        count += 1

    window.update(observed_publication_from=min(observed_dates) if observed_dates else None,
                  observed_publication_to=max(observed_dates) if observed_dates else None,
                  observed_document_count=count)

    logger.info(
        "[NEWS API AUDIT] query=%r candidates=%d accepted=%d missing_url=%d duplicate=%d out_of_scope=%d model_unconfirmed=%d metadata_only=%d",
        safe_query, len(articles), count, rejected_missing_url, rejected_duplicate, rejected_scope, model_unconfirmed,
        metadata_only,
    )
    record_connector_telemetry(
        "News API", "SRC_004", safe_query, len(articles), count, rejected_scope, unknown_dates,
        coverage_note=(f"STAGES={','.join(searched_stages)}; "
                       f"NEWSAPI_COVERAGE={window['coverage_status']}; "
                       f"requested_days={window['requested_horizon_days']}; searchable_days={searchable_days}; "
                       f"archive_limit_days={archive_days}; "
                       f"SEARCH_STATUS={'PARTIAL_RESULT' if recall_failed else ('NO_MATCH' if not articles else 'RESULTS_RETRIEVED')}"),
        operational_status=recall_state.value,
        search_outcome="PARTIAL_RESULT" if recall_failed else ("NO_MATCH" if not articles else "RESULTS_RETRIEVED"),
        coverage_window=window,
        error="; ".join(stage_errors) if stage_errors else None,
    )

    if count == 0:
        return coverage_line + f"News API: {'PARTIAL_RESULT' if recall_failed else 'NO_MATCH'} (no relevant articles for '{query}')."

    logger.info(f"[OSINT GATHERER] News API extraction completed ({count} articles).")
    return coverage_line + extracted_content

# Retrieve recent NTSB investigation announcements within the analysis scope.
# Keep official investigation identifiers and publication dates in each record.

@tool("Scrape NTSB Safety Investigations")
def scrape_ntsb_investigations(query: str = "latest") -> str:
    """Collect authorized NTSB aviation cases without inventing findings."""
    sid = "SRC_003"

    if not is_source_allowed(sid):
        return "NTSB: source requires approval or development review mode."

    api_key = os.getenv("NTSB_API_KEY", "").strip()
    if not api_key:
        return "NTSB: missing NTSB_API_KEY in .env"

    start, end = get_time_window_utc()
    case_ids = {m.group(0).upper() for m in re.finditer(r"\b[A-Z]{3}\d{2}[A-Z]{2}\d{3}\b", query or "", re.IGNORECASE)}
    explicit_years = sorted({int(y) for y in re.findall(r"\b(20\d{2})\b", query or "")})
    max_windows = max(1, min(36, int(os.getenv("EWS_NTSB_MAX_WINDOWS", "14" if case_ids else "12"))))

    if start is None:
        if case_ids:
            # NTSB case prefix obsahuje fiskální rok USA (např. DCA24MA063 -> FY2024: říjen 2023 – říjen 2024).
            fy = 2000 + int(next(iter(case_ids))[3:5])
            start = datetime(fy - 1, 10, 1, tzinfo=UTC)
            end = min(end, datetime(fy, 10, 15, 23, 59, 59, tzinfo=UTC))
        elif explicit_years:
            start = datetime(explicit_years[0], 1, 1, tzinfo=UTC)
            end = min(end, datetime(explicit_years[-1], 12, 31, 23, 59, 59, tzinfo=UTC))
        else:
            start = end - timedelta(days=30 * max_windows)

    limit = max(1, get_dynamic_limit())
    ntsb_stop = {
        "latest", "ntsb", "aviation", "accident", "incident", "aircraft",
        "investigation", "findings", "faa", "easa", "airworthiness", "directive",
        "directives", "federal", "register", "proposed", "safety", "status", "report",
    }
    generic_ntsb = {"boeing", "airbus", "embraer", "comac", "737", "a320", "a350", "787", "777", "max", "neo",
                    "airlines"}
    tokens = [
        word for word in re.findall(r"[a-z0-9-]{3,}", (query or "").lower())
        if word not in ntsb_stop
    ]
    specific_tokens = [t for t in tokens if t not in generic_ntsb]

    headers = {
        "Ocp-Apim-Subscription-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "AeroEWS Academic Research/2.0",
    }

    endpoint = 'https://api.ntsb.gov/public/api/Common/v2/GetCasesByDateRange/'

    output = []
    seen = set()
    cursor_end = end.date()
    requests_count = 0
    partial = False

    for _ in range(max_windows):
        if cursor_end < start.date() or len(output) >= limit:
            break

        cursor_start = max(start.date(), cursor_end - timedelta(days=29))

        marker = None

        for page_number in range(5):
            params = {
                "startDate": cursor_start.strftime("%m/%d/%Y"),
                "endDate": cursor_end.strftime("%m/%d/%Y"),
                "mode": "aviation",
            }
            if marker:
                params["marker"] = marker

            response = safe_http_get(
                endpoint,
                source_id=sid,
                params=params,
                headers=headers,
                timeout=30,
                max_bytes=8_000_000,
            )
            requests_count += 1

            if response is None or response.status_code not in (200, 204):
                partial = True
                break

            if response.status_code == 204:
                break

            try:
                payload = response.json()
            except ValueError:
                partial = True
                break

            if not isinstance(payload, dict):
                partial = True
                break

            cases = sorted(
                payload.get("data") or [],
                key=lambda case: (
                        case.get("publishDateTime")
                        or case.get("eventDate")
                        or ""
                ),
                reverse=True,
            )

            for case in cases:
                if len(output) >= limit:
                    break

                number = str(case.get("ntsbNumber") or "").strip()
                if not number or number in seen:
                    continue
                seen.add(number)

                event_date = str(case.get("eventDate") or "")
                published = str(case.get('publishDateTime') or '')[:10]

                aircraft = case.get("aircrafts") or []
                models = [
                    (
                        str(a.get('aircraftMake') or a.get('aircraftManufacturer') or '')
                        + " "
                        + str(a.get("aircraftModel") or "")
                    ).strip()
                    for a in aircraft
                ]
                models_text = "; ".join(models)

                narrative_parts = [
                    str(case.get(k) or "").strip()
                    for k in ("probableCause", "analysisNarrative", "factualNarrative",
                              "preliminaryNarrative", "eventDescription")
                    if str(case.get(k) or "").strip()
                ]
                operators = [
                    str(a.get("operatorName") or a.get("operator") or "").strip()
                    for a in aircraft if isinstance(a, dict)
                ]
                searchable = " ".join([
                    number,
                    models_text,
                    " ".join(operators),
                    " ".join(narrative_parts),
                    str(case.get("eventType") or ""),
                    str(case.get("eventCity") or ""),
                    str(case.get("eventStateOrRegion") or ""),
                ]).lower()

                if case_ids:
                    if number.upper() not in case_ids:
                        continue
                elif specific_tokens:
                    if not any(t in searchable for t in specific_tokens):
                        continue
                elif tokens and not any(t in searchable for t in tokens):
                    continue

                if not event_date or not is_date_within_scope(event_date):
                    continue

                classification = [
                    str(e.get('cicttEventSOEGroup') or e.get('eventTier2Name') or '')
                    for a in aircraft
                    for e in (a.get("events") or [])
                ]
                narrative_text = " ".join(narrative_parts).strip()
                has_substantive_narrative = len(narrative_text) >= 120

                body = (
                        f"NTSB case {number}. "
                        f"Occurrence date: {event_date}. "
                        f"Publication: {published or 'UNKNOWN'}. "
                        f"Event type: {case.get('eventType')}. "
                        f"Aircraft: {models_text or 'UNKNOWN'}. "
                        f"Operator: {', '.join(o for o in operators if o) or 'UNKNOWN'}. "
                        f"Location: {case.get('eventCity')}, "
                        f"{case.get('eventStateOrRegion')}, "
                        f"{case.get('eventCountry')}. "
                        f"Injury level: {case.get('highestInjuryLevel')}. "
                        f"Investigation status: {case.get('completionStatus')}. "
                        f"Case closed: {case.get('caseClosed')}. "
                        f"Event classification: {', '.join(classification[:4])}. "
                        + (f"Official NTSB Narrative / Findings: {narrative_text[:4000]}"
                           if has_substantive_narrative
                           else "These metadata do not establish a final root cause.")
                )

                case_url = response.url.split("#")[0] + "#" + urllib.parse.quote(number)

                doc = register_collected_document(
                    source_id=sid,
                    connector_name="NTSB Public Aviation API",
                    url=case_url,
                    title=f"NTSB {number}: {models_text or 'Aviation case'}",
                    raw_text=body,
                    published_at=published or event_date,
                    query_used=query,
                )

                doc.update({
                    "ntsb_number": number,
                    "event_date": event_date,
                    "document_type": "NTSB_CASE_SUMMARY" if has_substantive_narrative else "NTSB_CASE_METADATA_ONLY",
                    "content_status": "PARTIAL_TEXT" if has_substantive_narrative else "METADATA_ONLY",
                    "investigation_status": case.get("completionStatus"),
                })

                output.append(
                    f"DOC_ID: {doc['doc_id']} | SOURCE_ID: {sid}\n"
                    f"DATE: {doc['published_at']}\n"
                    f"Title: {doc['title']}\n"
                    f"Link: {case_url}\n"
                    f"Summary: {doc['text']}\n---"
                )

            if len(output) >= limit:
                break

            if not payload.get("hasMore"):
                break

            marker = payload.get("nextMarker")
            if not marker:
                partial = True
                break

        else:
            partial = True

        cursor_end = cursor_start - timedelta(days=1)

    if cursor_end >= start.date() and len(output) < limit:
        partial = True

    record_connector_telemetry(
        "NTSB Public Aviation API",
        sid,
        query,
        found_count=len(seen),
        accepted_count=len(output),
        operational_status=(
            "TEMPORARILY_UNAVAILABLE" if partial and not requests_count
            else "PARTIAL_COVERAGE" if partial
            else "AVAILABLE"
        ),
        search_outcome=(
            "PARTIAL_RESULT" if partial
            else "RESULTS_RETRIEVED" if output
            else "NO_MATCH"
        ),
        coverage_note=(
            f"requests={requests_count}; "
            f"partial={partial}; max_windows={max_windows}"
        ),
    )

    if not output:
        return f'NTSB: no matching cases in scanned windows. Partial coverage: {partial}'

    return "\n".join(output)

_FAA_LIFECYCLE_FIELDS = [
    "document_number", "docket_id", "docket_ids", "title", "abstract",
    "action", "type", "html_url", "raw_text_url", "publication_date", "effective_on",
]

_FAA_DOCKET_RE = re.compile(r"(?<![A-Z0-9])FAA-20\d{2}-\d{3,7}(?!\d)", re.IGNORECASE)
_FAA_NUMBER_RE = re.compile(r"(?<![A-Z0-9-])20\d{2}-\d{4,6}(?!\d)", re.IGNORECASE)
_FAA_CERTIFICATION_INTENT = re.compile(
    r"\b(?:certif\w*|approv\w*|type\s+certificate)\b", re.IGNORECASE,
)
_FAA_CACHE_LOCK = threading.RLock()
_FAA_OVERSIZE_FAILURES: dict[str, float] = {}


def _faa_cache_file(url: str, params: dict[str, Any] | None = None) -> Path:
    root = Path(os.getenv("EWS_FAA_CACHE_DIR") or Path(__file__).resolve().parent / ".aero_ews_cache" / "faa")
    identifier = json.dumps([url, params or {}], sort_keys=True, default=str)
    return root / hashlib.sha256(identifier.encode("utf-8")).hexdigest()


def _faa_cache_read(path: Path, max_bytes: int) -> requests.Response | None:
    try:
        metadata = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        body = path.with_suffix(".body").read_bytes()
        if len(body) > max_bytes or hashlib.sha256(body).hexdigest() != metadata["sha256"]:
            return None
        response = requests.Response()
        response.status_code = 200
        response.headers.update(metadata.get("headers", {}))
        response._content = body
        response.url = metadata["url"]
        response.aero_content_truncated = False
        return response
    except (OSError, ValueError, KeyError):
        return None


def _faa_cache_write(path: Path, response: requests.Response) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        metadata = {
            "url": response.url, "sha256": hashlib.sha256(response.content).hexdigest(),
            "headers": {name: value for name, value in response.headers.items()
                        if name.lower() in {"etag", "last-modified", "content-type"}},
        }
        suffix = f".{threading.get_ident()}.tmp"
        body_tmp = Path(f"{path}.body{suffix}")
        meta_tmp = Path(f"{path}.json{suffix}")
        with _FAA_CACHE_LOCK:
            body_tmp.write_bytes(response.content)
            os.replace(body_tmp, path.with_suffix(".body"))
            meta_tmp.write_text(json.dumps(metadata), encoding="utf-8")
            os.replace(meta_tmp, path.with_suffix(".json"))
    except OSError as exc:
        logger.debug("[FAA CACHE] Could not persist response: %s", exc)


def _faa_cached_get(url: str, *, params: dict[str, Any] | None = None,
                    immutable: bool = False, max_bytes: int = 2_000_000,
                    check_robots: bool = False) -> HTTPResult:
    """On-disk FAA cache; immutable hits bypass HTTP, mutable hits revalidate."""
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.hostname not in {"federalregister.gov", "www.federalregister.gov"}
            or not is_source_allowed("SRC_001")):
        _note_blocked_request("SRC_001")
        return HTTPResult(error_type="SOURCE_POLICY_OR_HOST_BLOCKED")
    if check_robots and not check_robots_and_tdm_compliance(url, "SRC_001")[0]:
        _note_blocked_request("SRC_001")
        return HTTPResult(error_type="ROBOTS_OR_TDM_BLOCKED")
    path = _faa_cache_file(url, params)
    cached = _faa_cache_read(path, max_bytes)
    if immutable and cached is not None:
        return HTTPResult(response=cached, status_code=200, response_complete=True,
                          bytes_received=len(cached.content))
    validators = {}
    if cached is not None:
        for field, header in (("ETag", "If-None-Match"), ("Last-Modified", "If-Modified-Since")):
            if cached.headers.get(field):
                validators[header] = cached.headers[field]
    result = _safe_http_request(url, "SRC_001", params=params, headers=validators or None,
                                timeout=18, max_bytes=max_bytes, check_robots=check_robots)
    if result.status_code == 304 and cached is not None:
        return HTTPResult(response=cached, status_code=200, response_complete=True,
                          bytes_received=len(cached.content), attempts=result.attempts,
                          wait_seconds=result.wait_seconds)
    if result.status_code == 200 and result.response_complete and result.response is not None:
        _faa_cache_write(path, result.response)
    return result


def _faa_json_result(url: str, *, params: dict[str, Any] | None = None,
                     max_bytes: int = 2_000_000, immutable: bool = False) -> tuple[dict[str, Any] | None, HTTPResult]:
    """Classify FAA API replies without logging bodies or confusing HTTP 200 with success."""
    result = _faa_cached_get(url, params=params, max_bytes=max_bytes, immutable=immutable)
    blocked = result.status_code in {401, 403} or result.error_type in {
        "SOURCE_POLICY_BLOCKED", "SOURCE_POLICY_OR_HOST_BLOCKED",
        "ROBOTS_OR_TDM_BLOCKED", "RESPONSE_TDM_BLOCKED", "HTML_TDM_BLOCKED",
    }
    if blocked:
        result.payload_classification = "ACCESS_BLOCKED"
        return None, result
    if result.status_code != 200 or not result.response_complete or result.response is None:
        result.payload_classification = "HTTP_ERROR" if result.status_code and result.status_code >= 400 else "SOURCE_UNAVAILABLE"
        return None, result
    try:
        payload = result.response.json()
    except ValueError:
        result.error_type = result.payload_classification = "INVALID_JSON"
        return None, result
    if not isinstance(payload, dict):
        result.error_type = result.payload_classification = "UNEXPECTED_SCHEMA"
        result.payload_shape = {"json_type": type(payload).__name__}
        return None, result

    error = payload.get("error") or payload.get("errors")
    api_code = payload.get("code") or payload.get("error_code")
    if isinstance(error, dict):
        api_code = api_code or error.get("code") or error.get("error_code")
    elif isinstance(error, list) and error and isinstance(error[0], dict):
        api_code = api_code or error[0].get("code") or error[0].get("error_code")
    result.payload_shape = {
        "keys": sorted(str(key) for key in payload)[:20],
        "types": {str(key): type(value).__name__ for key, value in list(payload.items())[:20]},
        "api_error_code": str(api_code or "")[:48],
        "declared_count": (payload.get("count")
                           if isinstance(payload.get("count"), int)
                           and not isinstance(payload.get("count"), bool) else None),
        "results_present": "results" in payload,
        "results_type": type(payload.get("results")).__name__,
    }
    if error:
        result.error_type = result.payload_classification = "API_ERROR_RESPONSE"
        return None, result
    search_response = urlparse(url).path.endswith("/documents.json")
    if search_response:
        # Federal Register can represent a valid empty result without a
        # results array. Normalize only an explicit zero count, never failures.
        if (type(payload.get("count")) is int and payload["count"] == 0
                and "results" not in payload
                and isinstance(payload.get("description"), str)
                and not payload.get("next_page_url")):
            payload = {**payload, "results": []}
            result.payload_shape["empty_results_normalized"] = True
        valid = (isinstance(payload.get("results"), list)
                 and isinstance(payload.get("count"), int)
                 and not isinstance(payload["count"], bool)
                 and payload["count"] >= 0
                 and all(isinstance(item, dict) for item in payload["results"]))
    else:
        valid = isinstance(payload.get("document_number"), str)
    result.payload_classification = "VALID_SEARCH_RESPONSE" if valid and search_response else (
        "VALID_DOCUMENT_RESPONSE" if valid else "UNEXPECTED_SCHEMA"
    )
    if not valid:
        result.error_type = result.payload_classification
        return None, result
    return payload, result


def _faa_search_pages_once(params: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Execute one FAA search shape with bounded, audited pagination and per-run deduplication."""
    url = "https://www.federalregister.gov/api/v1/documents.json"
    params = dict(params)  # Preserve omission of fields[] for schema-repair requests.
    page_size = min(25, max(10, limit * 3))
    page_budget = min(20, max(1, int(os.getenv("EWS_FAA_MAX_PAGES", "12"))))
    doc_cap = min(200, max(limit * 10, 80))
    request_budget = page_budget * 3 + 8
    run_cache_key = hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest()
    with _COLLECTION_LOCK:
        cached_run = FAA_SEARCH_CACHE.get(run_cache_key)
    if cached_run is not None:
        cached_docs, cached_audit = cached_run
        return list(cached_docs), {**cached_audit, "request_calls": 0, "dedup_cache_hit": True}

    cache_key = hashlib.sha256(json.dumps([params, page_size], sort_keys=True, default=str).encode()).hexdigest()
    with _FAA_CACHE_LOCK:
        recent_failure = _FAA_OVERSIZE_FAILURES.get(cache_key, 0) > time.monotonic()
    if recent_failure:
        return [], {"status": "SOURCE_UNAVAILABLE", "declared_count": 0, "processed_count": 0,
                    "access_restricted": False, "pages": 0, "page_size": page_size,
                    "pagination_complete": False, "last_error": "PREVIOUS_OVERSIZE_FAILURE",
                    "attempts": [], "request_calls": 0, "retry_suppressed": True}

    pages, page, requests_made, declared = 0, 1, 0, 0
    seen, docs, attempts = set(), [], []
    access_restricted, complete, last_error = False, False, ""
    status = "RESULTS_RETRIEVED"
    while pages < page_budget and len(docs) < doc_cap:
        max_bytes = 600_000
        while requests_made < request_budget:
            payload, http = _faa_json_result(
                url, params={**params, "page": page, "per_page": page_size}, max_bytes=max_bytes,
            )
            requests_made += 1
            results = payload.get("results") if payload else None
            headers = http.response.headers if http.response is not None else {}
            attempts.append({
                "page": page, "requested_page_size": page_size, "max_bytes": max_bytes,
                "http_status": http.status_code, "content_type": headers.get("Content-Type"),
                "content_length": headers.get("Content-Length"), "received_bytes": http.bytes_received,
                "http_attempts": http.attempts,
                "requested_fields": list(params.get("fields[]") or []),
                "actual_results_count": len(results) if isinstance(results, list) else None,
                "pagination_honored": len(results) <= page_size if isinstance(results, list) else None,
                "error_code": http.error_type or (f"HTTP_{http.status_code}" if payload is None else None),
                "response_classification": http.payload_classification,
                "response_schema": http.payload_shape,
            })
            if payload is not None or http.error_type != "BODY_TRUNCATED":
                break
            if page_size > 1:
                page_size = max(1, page_size // 2)
            elif max_bytes < 2_400_000:
                max_bytes *= 2
            else:
                with _FAA_CACHE_LOCK:
                    if len(_FAA_OVERSIZE_FAILURES) >= 128:
                        _FAA_OVERSIZE_FAILURES.clear()
                    _FAA_OVERSIZE_FAILURES[cache_key] = time.monotonic() + 600
                break
            logger.warning("[FAA PAGINATION] Incomplete page %d; trying size=%d, cap=%d",
                           page, page_size, max_bytes)
        else:
            payload, http = None, None
            last_error = "REQUEST_BUDGET_EXHAUSTED"

        if payload is None:
            if http is not None:
                access_restricted = (http.status_code in {401, 403} or http.error_type in {
                    "SOURCE_POLICY_BLOCKED", "SOURCE_POLICY_OR_HOST_BLOCKED", "ROBOTS_OR_TDM_BLOCKED",
                    "RESPONSE_TDM_BLOCKED", "HTML_TDM_BLOCKED",
                })
                # The transport may report HTTP_400 or STATUS_400; the semantic
                # classification must drive repair and availability decisions.
                last_error = http.payload_classification or http.error_type or f"HTTP_{http.status_code}"
            malformed = last_error in {
                "API_ERROR_RESPONSE", "UNEXPECTED_SCHEMA", "INVALID_JSON", "INVALID_RESULT_SCHEMA",
            } or (last_error == "HTTP_ERROR" and http is not None
                  and http.status_code in {400, 414, 422})
            status = ("PARTIAL_COVERAGE" if docs else "ACCESS_BLOCKED" if access_restricted
                      else "RETRIEVAL_FAILED" if malformed else "SOURCE_UNAVAILABLE")
            break

        results, count = payload.get("results"), payload.get("count")
        if (not isinstance(results, list) or not isinstance(count, int) or count < 0
                or any(not isinstance(row, dict) for row in results)):
            status, last_error = ("PARTIAL_COVERAGE" if docs else "RETRIEVAL_FAILED"), "UNEXPECTED_SCHEMA"
            attempts[-1]["error_code"] = last_error
            break
        if len(results) > page_size:
            status, last_error = "PARTIAL_COVERAGE", "PAGINATION_IGNORED"
            attempts[-1]["error_code"] = last_error
            break
        pages += 1
        declared = max(declared, count)
        for entry in results:
            number = entry.get("document_number")
            if number and number not in seen:
                seen.add(number)
                docs.append(entry)
        if not payload.get("next_page_url"):
            complete = len(docs) >= declared
            break
        page += 1
    if status == "RESULTS_RETRIEVED":
        status = ("RESULTS_RETRIEVED" if docs else "NO_RESULTS") if complete else "PARTIAL_COVERAGE"
    audit_out = {
        "status": status, "declared_count": declared, "processed_count": len(docs),
        "access_restricted": access_restricted, "pages": pages, "page_size": page_size,
        "pagination_complete": complete, "last_error": last_error, "attempts": attempts,
        "request_calls": requests_made, "retry_suppressed": False,
    }
    if status in {"RESULTS_RETRIEVED", "NO_RESULTS", "PARTIAL_COVERAGE"}:
        with _COLLECTION_LOCK:
            FAA_SEARCH_CACHE[run_cache_key] = (list(docs), dict(audit_out))
    return docs, audit_out


def _faa_native_term(query: str, *, compact: bool = False) -> str:
    """Translate web-search syntax into bounded native full-text terms."""
    clean = re.sub(r"(?<!\w)-?(?:site|inurl|filetype):\S+", " ", str(query), flags=re.IGNORECASE)
    clean = re.sub(r"\b(?:AND|OR)\b|[()\"']", " ", clean)
    clean = " ".join(clean.split())
    identities = list(dict.fromkeys(identity.aliases[0] for identity in _model_identities(clean)))
    issue = next((label for pattern, label in (
        (r"\bairworthiness\s+directiv\w*\b", "airworthiness directive"),
        (r"\binspect\w*\b", "inspection"),
        (r"\bcertif\w*\b", "certification"),
        (r"\bdefect\w*\b", "defect"),
        (r"\b(?:failure|fault)\b", "failure"),
        (r"\bturbine\b", "turbine"),
        (r"\bengine\b", "engine"),
        (r"\bproduction\b", "production"),
        (r"\bsafety\b", "safety"),
    ) if re.search(pattern, clean, re.IGNORECASE)), "")
    if identities:
        terms = [*identities[:1 if compact else 2], issue]
        return " ".join(term for term in terms if term)[:120]
    _, extracted = parse_query_intent(clean)
    meaningful = " ".join(extracted.split())[:120] or clean[:120]
    if compact and issue and issue.casefold() not in meaningful.casefold():
        meaningful = f"{meaningful[:75]} {issue}"
    return meaningful.strip()


def _faa_search_pages(params: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Retry at most two distinct, scope-preserving shapes after actionable schema errors."""
    base = dict(params)
    variants: list[tuple[str, dict[str, Any]]] = [("ORIGINAL", base)]
    no_fields = {key: value for key, value in base.items() if key != "fields[]"}
    if no_fields != base:
        variants.append(("DEFAULT_FIELDS", no_fields))
    if base.get("conditions[docket_id]"):
        docket = str(base["conditions[docket_id]"])
        fallback = {key: value for key, value in no_fields.items()
                    if key != "conditions[docket_id]"}
        fallback["conditions[term]"] = docket
    elif base.get("conditions[term]"):
        fallback = dict(no_fields)
        fallback["conditions[term]"] = _faa_native_term(str(base["conditions[term]"]), compact=True)
    else:
        fallback = dict(no_fields)
    if fallback and all(fallback != previous for _, previous in variants):
        variants.append(("IDENTITY_PRESERVING_TERM", fallback))

    all_attempts: list[dict[str, Any]] = []
    calls, attempts_tried = 0, []
    final_docs: list[dict[str, Any]] = []
    final_audit: dict[str, Any] = {}
    for index, (kind, variant) in enumerate(variants[:3]):
        docs, audit = _faa_search_pages_once(variant, limit)
        attempts_tried.append(kind)
        calls += int(audit.get("request_calls") or 0)
        all_attempts.extend({**attempt, "query_variant": kind} for attempt in audit.get("attempts") or [])
        final_docs, final_audit = docs, dict(audit)
        failure = str(audit.get("last_error") or "")
        last_attempt = (audit.get("attempts") or [{}])[-1]
        last_http = last_attempt.get("http_status")
        api_code = str((last_attempt.get("response_schema") or {}).get("api_error_code") or "")
        repairable = failure in {"UNEXPECTED_SCHEMA", "INVALID_RESULT_SCHEMA"} or (
            failure == "API_ERROR_RESPONSE"
            and bool(re.search(r"INVALID|QUERY|PARAM|FIELD|BAD_REQUEST|SCHEMA", api_code, re.IGNORECASE))
        ) or (failure == "HTTP_ERROR" and last_http in {400, 414, 422})
        if docs or not repairable or index >= 2:
            if index and kind == "IDENTITY_PRESERVING_TERM" and audit["status"] in {
                "RESULTS_RETRIEVED", "NO_RESULTS"
            }:
                final_audit["status"] = "PARTIAL_COVERAGE"
                final_audit["last_error"] = "ORIGINAL_QUERY_SCHEMA_FAILURE"
            break
        if index + 1 >= len(variants):
            break
        logger.warning(
            "[FAA API] %s, HTTP=%s, schema=%s; trying bounded query repair %d/2",
            failure, last_http,
            (audit.get("attempts") or [{}])[-1].get("response_classification"), index + 1,
        )
    final_audit.update({
        "attempts": all_attempts, "request_calls": calls,
        "search_variants": attempts_tried,
        "repair_used": len(attempts_tried) > 1,
    })
    return final_docs, final_audit


def _faa_full_text(response: requests.Response, url: str) -> str:
    """Cache normalized FAA text against the exact retrieved response bytes."""
    path = _faa_cache_file(url).with_suffix("." + hashlib.sha256(response.content).hexdigest()[:16] + ".txt")
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        pass
    mime = response.headers.get("Content-Type", "").lower()
    if "html" in mime:
        soup = BeautifulSoup(response.text, "html.parser")
        for element in soup.select("script, style, nav, footer, aside, header"):
            element.decompose()
        text = (soup.select_one("article") or soup.select_one("main") or soup).get_text(" ", strip=True)
    else:
        text = response.text.strip() if "text/plain" in mime else ""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return text

# Resolve FAA notices by docket and distinguish their regulatory lifecycle.
# Track proposed, final and effective stages separately for each docket.
def _faa_resolve_docket(
        doc: dict[str, Any], as_of: str, cache: dict[str, tuple[dict[str, Any], bool]]
) -> tuple[dict[str, Any], str, bool]:
    """Enrich original notice with docket lifecycle without replacing its identity."""
    number = str(doc.get("document_number") or "")
    full_doc = dict(doc)

    if _FAA_NUMBER_RE.fullmatch(number):
        detail, _ = _faa_json_result(
            f"https://www.federalregister.gov/api/v1/documents/{number}.json",
            params={"fields[]": _FAA_LIFECYCLE_FIELDS}, immutable=True,
        )
        if detail and detail.get("document_number") == number:
            full_doc.update(detail)

    docket_data = json.dumps({"docket_ids": full_doc.get("docket_ids"), "docket_id": full_doc.get("docket_id")})
    match = _FAA_DOCKET_RE.search(docket_data)
    docket = match.group(0).upper() if match else ""

    if not docket and (url := full_doc.get("html_url") or doc.get("html_url")):
        page = _faa_cached_get(url, immutable=True)
        if page.response is not None and page.response_complete:
            plain = BeautifulSoup(page.response.text, "html.parser").get_text(" ", strip=True)
            if m := _FAA_DOCKET_RE.search(plain):
                docket = m.group(0).upper()

    if not docket:
        logger.info("[FAA LIFECYCLE] Docket unavailable for document %s", number)
        return full_doc, "", False

    if docket not in cache:
        results, metadata = _faa_search_pages(
            {
                "conditions[docket_id]": docket,
                "conditions[publication_date][lte]": as_of,
                "order": "newest",
                "fields[]": _FAA_LIFECYCLE_FIELDS,
            },
            limit=20,
        )
        relevant = [
            item for item in results
            if item.get("publication_date") and str(item["publication_date"]) <= as_of
               and docket in {str(v).upper() for v in (
                   [item.get("docket_id")] + (item.get("docket_ids") if isinstance(item.get("docket_ids"), list) else [])
               ) if v}
        ]

        if relevant:
            newest = max(relevant, key=lambda item: (item.get("publication_date", ""), item.get("document_number", "")))
            cache[docket] = (newest, metadata["status"] == "RESULTS_RETRIEVED")
        else:
            cache[docket] = (full_doc, False)

    latest, checked = cache[docket]
    full_doc["lifecycle_latest_document_number"] = latest.get("document_number", "")
    full_doc["lifecycle_latest_publication_date"] = latest.get("publication_date", "")
    full_doc["lifecycle_relation"] = (
        "SAME_DOCUMENT" if latest.get("document_number") == number else "LATER_DOCUMENT_IN_SAME_DOCKET"
    )
    return full_doc, docket, checked

_EASA_PRIMARY_INDEX_PAGES = (
    "https://ad.easa.europa.eu/",
    "https://www.easa.europa.eu/en/domains/aircraft-products/airworthiness-directives-ad/safety-publications-tool-interim-solution",
    "https://www.easa.europa.eu/en/domains/aircraft-products/airworthiness-directives-ad/archive-airworthiness-directives",
)

# Convert EASA publication dates into the standard internal date format.
def _easa_iso_date(value: str) -> str:
    value = str(value or "").strip()
    if match := re.fullmatch(r"(\d{1,2})/(\d{1,2})/(20\d{2})", value):
        month, day, year = map(int, match.groups())
        try:
            return datetime(year, month, day).strftime("%Y-%m-%d")
        except ValueError:
            return ""
    return normalize_date_str(value)

# Distinguish airframe-level from engine-level EASA applicability.
# Engine-only and airframe-level applicability are not interchangeable.
def _easa_applicability(query: str, subject: str, approved_types: str) -> str:
    """
    Determine EASA applicability using centralized aircraft
    and engine identity recognition.

    Returns:
        AIRCRAFT   - Aircraft identity matches the KIT.
        ENGINE_ONLY - Engine matches, aircraft installation unverified.
        NONE       - Direct applicability is not established.
    """

    # Local import prevents circular module dependencies.
    from aero_ews.domain.identity import (
        _detect_aircraft_families,
        _detect_engine_models,
        _detect_exact_variants,
        _detect_specific_variants,
        _engine_models_match,
    )

    query = re.split(
        r"\b(?:excluding|exclude|except(?:\s+for)?|without|not\s+including|kromě|vyjma)\b",
        query or "", maxsplit=1, flags=re.IGNORECASE,
    )[0].strip()
    text = f"{subject} {approved_types}"

    # Aircraft family identification.
    requested_families = _detect_aircraft_families(query)
    source_families = _detect_aircraft_families(text)
    if re.search(r"\bBD-?500-?1A1[01]\b|\bCS(?:100|300)\b", text, re.IGNORECASE):
        source_families = set(source_families) | {"A220"}

    # Aircraft program and generation identification.
    requested_specific = _detect_specific_variants(query)
    source_specific = _detect_specific_variants(text)

    # Exact variant identification.
    requested_exact = _detect_exact_variants(query)
    source_exact = _detect_exact_variants(text)

    # Engine identification.
    requested_engines = _detect_engine_models(query)
    engine_match = _engine_models_match(query, text)

    # A different or unidentified engine cannot establish
    # direct applicability to an engine-specific KIT.
    if requested_engines and not engine_match:
        return "NONE"

    # Basic aircraft family compatibility.
    aircraft_match = bool(requested_families & source_families)

    # Prevent matching different known aircraft programs.
    if requested_specific and source_specific and (not requested_specific & source_specific):
        aircraft_match = False

    # Prevent a generic family match from overriding
    # a known mismatch between exact variants.
    # Generic neo designation may match an N-suffixed
    # Airbus type designation of the same aircraft model.
    neo_query = re.search('\\b(a3(?:19|20|21))[\\s-]*neo\\b', query, re.IGNORECASE)

    neo_cert_match = bool(
        neo_query
        and re.search(
            rf"\b{re.escape(neo_query.group(1))}"
            rf"-\d{{3}}N[A-Z]?\b",
            text,
            re.IGNORECASE,
        )
    )

    if requested_exact and (not requested_exact & source_exact) and (not neo_cert_match):
        aircraft_match = False

    # A KIT naming an individual certified type must not
    # be satisfied by a different certified type.
    cert_pattern = re.compile('\\bA3(?:19|20|21)-\\d{3}N[A-Z]?\\b', re.IGNORECASE)

    requested_cert = {value.upper() for value in cert_pattern.findall(query)}

    source_cert = {value.upper() for value in cert_pattern.findall(text)}

    if requested_cert and requested_cert.isdisjoint(source_cert):
        aircraft_match = False

    if requested_families:
        if aircraft_match:
            return "AIRCRAFT"

        if engine_match:
            return "ENGINE_ONLY"

        return "NONE"

    if requested_engines:
        return "ENGINE_ONLY"

        # Generic manufacturer/supplier/component KIT without a model: require an explicit match in EASA metadata.
        q_lower = query.lower()
        source_lower = text.lower()

        if re.search(r"\bairbus\b", q_lower) and "airbus" not in source_lower:
            return "NONE"
        if re.search(r"\bboeing\b", q_lower) and "boeing" not in source_lower:
            return "NONE"

        generic_stop = {
            "aerospace", "aviation", "aircraft", "engine", "engines", "supply", "chain",
            "shortage", "impact", "production", "delivery", "deliveries", "supplier",
            "suppliers", "labor", "labour", "strike", "status", "current", "latest",
            "issues", "issue", "delays", "delay", "orders", "order", "directive",
            "directives", "airworthiness", "inspection", "certification", "between",
            "acquisition", "manufacturing", "defects", "defect", "quality", "safety",
        }
        anchors = [
            tok for tok in re.findall(r"[a-z0-9-]{4,}", q_lower)
            if tok not in generic_stop and not re.fullmatch(r"20\d{2}", tok)
        ]
        if anchors and any(re.search(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])", source_lower) for tok in anchors):
            return "AIRCRAFT"
        return "NONE"

    def _extract_easa_pdf_text(pdf_bytes: bytes, max_chars: int = 12000) -> str:
        """Extract text from an official EASA AD PDF using whichever local PDF reader is installed."""
        if not pdf_bytes or not pdf_bytes.startswith(b"%PDF"):
            return ""
        for mod_name in ("pypdf", "PyPDF2"):
            try:
                mod = __import__(mod_name)
                reader = mod.PdfReader(io.BytesIO(pdf_bytes))
                parts = []
                for page in reader.pages[:12]:
                    page_txt = page.extract_text() or ""
                    if page_txt.strip():
                        parts.append(page_txt.strip())
                    if sum(len(p) for p in parts) >= max_chars:
                        break
                text = re.sub(r"\s+", " ", "\n".join(parts)).strip()
                if text:
                    return text[:max_chars]
            except Exception:
                continue
        try:
            import fitz  # PyMuPDF
            with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
                parts = [page.get_text("text").strip() for page in list(doc)[:12]]
            text = re.sub(r"\s+", " ", "\n".join(p for p in parts if p)).strip()
            if text:
                return text[:max_chars]
        except Exception:
            pass
        return ""

# Parse EASA directive index metadata across supported page layouts.
# Preserve directive numbers and links from official EASA metadata.
def _easa_parse_table(html_text: str, base_url: str) -> tuple[list[dict], str | None]:
    # Parse official EASA index rows into standardized directive metadata.
    """Parse EASA Safety Publications Tool (ad.easa.europa.eu) and legacy archive tables."""
    soup = BeautifulSoup(html_text, "html.parser")
    records = []

    for table in soup.find_all("table"):
        headers = [re.sub(r"\s+", " ", h.get_text(" ", strip=True)).lower() for h in table.select("thead th")]
        if not headers and (first := table.find("tr")):
            headers = [re.sub(r"\s+", " ", h.get_text(" ", strip=True)).lower()
                       for h in first.find_all("th", recursive=False)]

        if not ("issue date" in headers and "subject" in headers):
            continue

        number_col = "number" if "number" in headers else "class number"
        docs_col = "attachment" if "attachment" in headers else "documents"
        if number_col not in headers or docs_col not in headers:
            continue

        for tr in table.find_all("tr"):
            cells = tr.find_all("td", recursive=False)
            if len(cells) < len(headers):
                continue

            cols = {header: cells[i] for i, header in enumerate(headers)}
            number = cols[number_col].get_text(" ", strip=True)
            subject_cell = cols["subject"]
            is_pad = bool(subject_cell.find("img", attrs={"alt": re.compile(r"^PAD$", re.IGNORECASE)}))

            if is_pad:
                if not re.fullmatch(r"(?:20)?\d{2}-\d{3,4}(?:[RC]\d+)?", number):
                    continue
            elif not re.fullmatch(r"20\d{2}-\d{4}(?:[RC]\d+)?", number):
                continue

            if "issued by" in cols:
                issuer_cell = cols["issued by"]
                issuer = issuer_cell.get_text(" ", strip=True).upper()
                if not issuer and (flag := issuer_cell.find("img")):
                    issuer = str(flag.get("alt") or flag.get("title") or "").strip().upper()
                if issuer != "EU":
                    continue
            if "ad class" in cols and cols["ad class"].get_text(" ", strip=True).upper() not in {"AD", "PAD"}:
                continue

            published = _easa_iso_date(cols["issue date"].get_text(" ", strip=True))
            if not published:
                continue

            for comment_link in subject_cell.find_all("a"):
                if "send comment" in comment_link.get_text(" ", strip=True).lower():
                    comment_link.decompose()
            subject = re.sub(r"\s+", " ", subject_cell.get_text(" ", strip=True))
            types = cols.get("approval holder / type designation")
            applicability = re.sub(r"\s+", " ", types.get_text(" ", strip=True)) if types else ""
            effective = cols.get("effective date")
            effective_date = _easa_iso_date(effective.get_text(" ", strip=True)) if effective else ""

            pdf_url = ""
            for a in cols[docs_col].find_all("a", href=True):
                candidate = urljoin(base_url, a["href"])
                host = (urlparse(candidate).hostname or "").lower()
                is_official = host == "easa.europa.eu" or host.endswith(".easa.europa.eu")
                is_pdf = ".pdf" in candidate.lower() or "pdf" in a.get_text(" ", strip=True).lower()
                if is_official and is_pdf:
                    pdf_url = candidate
                    break
            if not pdf_url and (detail_a := cols[number_col].find("a", href=True)):
                candidate = urljoin(base_url, detail_a["href"])
                host = (urlparse(candidate).hostname or "").lower()
                if host == "easa.europa.eu" or host.endswith(".easa.europa.eu"):
                    pdf_url = candidate

            if pdf_url:
                records.append({
                    "number": number, "published": published, "subject": subject,
                    "applicability": applicability, "effective": effective_date,
                    "pdf_url": pdf_url, "is_pad": is_pad,
                })

    next_url = None
    for a in soup.find_all("a"):
        label = a.get_text(" ", strip=True).lower()
        relation = str(a.get("rel", "")).lower()
        if label in {"next", "next ›", "next »", "›", "»"} or "next" in relation:
            if a.get("href"):
                candidate = urljoin(base_url, a["href"])
                if urlparse(candidate).netloc == urlparse(base_url).netloc:
                    next_url = candidate
                    break
            elif onclick := str(a.get("onclick") or ""):
                if page_match := re.search(r"pageNumber\s*=\s*['\"](\d+)['\"]", onclick):
                    parsed_base = urlparse(base_url)
                    prefix = re.sub(r"page-\d+.*$", "", parsed_base.path).rstrip("/")
                    next_url = f"{parsed_base.scheme}://{parsed_base.netloc}{prefix}/page-{page_match.group(1)}"
                    break

    return records, next_url

# Read official EASA CSV exports as structured metadata.
# CSV rows are index metadata, not the complete directive text.
def _easa_biweekly_csv_rows(index_html: str, base_url: str, max_archives: int = 8):
    """Read available official EASA biweekly CSV exports (metadata only)."""
    soup = BeautifulSoup(index_html, "html.parser")
    archive_urls = []

    for row in soup.find_all("tr"):
        if len(row.find_all(["td", "th"])) < 4:
            continue
        for a in row.find_all("a", href=True):
            label = a.get_text(" ", strip=True).lower()
            if "csv" in label or "cvs" in label:
                target = urljoin(base_url, a["href"])
                host = (urlparse(target).hostname or "").lower()
                if host == "easa.europa.eu" or host.endswith(".easa.europa.eu"):
                    archive_urls.append(target)

    archive_urls = list(dict.fromkeys(archive_urls))[:max_archives]
    parsed, issues = [], []

    for url in archive_urls:
        response = safe_http_get(url, source_id="SRC_002", timeout=15, max_bytes=10_000_000, check_robots=True)
        if response is None or response.status_code != 200:
            issues.append("CSV_ARCHIVE_UNAVAILABLE")
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                for member in z.infolist()[:30]:
                    if not member.filename.lower().endswith(".csv"):
                        continue
                    if member.file_size > 4_000_000:
                        issues.append("CSV_MEMBER_TOO_LARGE")
                        continue

                    raw = z.read(member)
                    try:
                        content = raw.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        content = raw.decode("cp1252", errors="replace")

                    dialect = csv.excel
                    try:
                        dialect = csv.Sniffer().sniff(content[:3000], delimiters=",;\t")
                    except csv.Error:
                        pass

                    reader = csv.DictReader(io.StringIO(content), dialect=dialect)

                    if reader.fieldnames and re.match(
                            r"^(?:[A-Z]{2}-)?20\d{2}-\d{2}",
                            reader.fieldnames[0].strip()
                    ):
                        first_row = list(reader.fieldnames)
                        names = [
                            "AD number", "Issue date", "Approval holder",
                            "Type designation", "Subject"
                        ]
                        reader.fieldnames = names + [f'Other {i}' for i in range(len(first_row) - 5)]
                        csv_rows = [dict(zip(reader.fieldnames, first_row)), *reader]
                    else:
                        csv_rows = list(reader)

                    if not reader.fieldnames:
                        issues.append("CSV_HEADERS_MISSING")
                        continue

                    logger.info("[EASA CSV] Archive=%s columns=%s", url, reader.fieldnames)

                    for row in csv_rows[:4000]:
                        normalized = {
                            re.sub(r"[^a-z0-9]+", " ", str(k or "").lower()).strip(): str(v or "").strip()
                            for k, v in row.items()
                        }
                        match = re.search(r"\b20\d{2}-\d{4}(?:[RC]\d+)?\b", " ".join(normalized.values()))
                        if not match:
                            continue

                        # Read candidate CSV fields using recognized header aliases.
                        def field(*names):
                            return next((v for k, v in normalized.items() if any(n in k for n in names) and v), "")

                        issuer = field("issued by", "issuing state")
                        if issuer and issuer.strip().upper() not in {"EU", "EASA"}:
                            continue

                        published = _easa_iso_date(field("issue date", "publication date", "date issued"))
                        subject = field("subject", "description", "title")
                        types = field("approval holder", "type designation", "product", "affected")
                        if not published or not subject or not types:
                            continue

                        number = match.group(0)
                        parsed.append({
                            "number": number,
                            "published": published,
                            "subject": subject,
                            "applicability": types,
                            "effective": _easa_iso_date(field("effective date")),
                            "pdf_url": f"{url}#ad={number}",
                            "metadata_only": True,
                        })
        except (ValueError, OSError, zipfile.BadZipFile) as exc:
            issues.append(f"CSV_ARCHIVE_INVALID:{type(exc).__name__}")

    if not archive_urls:
        issues.append("NO_BIWEEKLY_CSV_LINKS")
    return parsed, issues

# Collect current EASA directive metadata from the official index.
# Index records cannot substitute for reading the underlying AD PDF.
def _extract_easa_pdf_text(pdf_bytes: bytes, max_chars: int = 12000) -> str:
    """Extract text from an official EASA AD PDF using whichever local PDF reader is installed."""
    if not pdf_bytes or not pdf_bytes.startswith(b"%PDF"):
        return ""
    for mod_name in ("pypdf", "PyPDF2"):
        try:
            mod = __import__(mod_name)
            reader = mod.PdfReader(io.BytesIO(pdf_bytes))
            parts = []
            for page in reader.pages[:12]:
                page_txt = page.extract_text() or ""
                if page_txt.strip():
                    parts.append(page_txt.strip())
                if sum(len(p) for p in parts) >= max_chars:
                    break
            text = re.sub(r"\s+", " ", "\n".join(parts)).strip()
            if text:
                return text[:max_chars]
        except Exception:
            continue
    try:
        import fitz
        with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
            parts = [page.get_text("text").strip() for page in list(doc)[:12]]
        text = re.sub(r"\s+", " ", "\n".join(p for p in parts if p)).strip()
        if text:
            return text[:max_chars]
    except Exception:
        pass
    return ""


def _collect_easa_primary_index(query: str, limit: int) -> tuple[str, int]:
    # Collect EASA directives without assuming an index entry provides the full PDF.
    """Collect official EASA AD index metadata from ad.easa.europa.eu."""
    output = ">> EASA OFFICIAL AD INDEX (METADATA ONLY; PDF NOT READ):\n"
    accepted = examined = pages = 0
    seen_ad, failures, advisories = set(), [], []
    oldest_dates: list[str] = []

    start, end = get_time_window_utc()
    span = (end - start).days if start else 365
    max_archive_pages = min(25, max(1, int(os.getenv("EWS_EASA_ARCHIVE_MAX_PAGES", "10" if span <= 90 else "20"))))

    for first_url in _EASA_PRIMARY_INDEX_PAGES[:1]:
        is_sp_tool = "ad.easa.europa.eu" in first_url
        paginated = is_sp_tool or "archive-airworthiness-directives" in first_url
        url = first_url
        visited = set()
        max_pages = max_archive_pages if paginated else 1

        for _ in range(max_pages):
            if not url or url in visited or accepted >= limit:
                break
            visited.add(url)

            with _COLLECTION_LOCK:
                index_html = EASA_PAGE_CACHE.get(url)
            if index_html is None:
                response = safe_http_get(url, source_id="SRC_002", timeout=15, check_robots=True, max_bytes=5_000_000)
                if response is None or response.status_code != 200:
                    failures.append("ACCESS_RESTRICTED" if response is not None
                                    and response.status_code in {401, 403} else f"HTTP/COMPLIANCE:{url}")
                    break
                index_html = response.text
                with _COLLECTION_LOCK:
                    EASA_PAGE_CACHE[url] = index_html

            records, next_page = _easa_parse_table(index_html, url)
            pages += 1
            examined += len(records)

            if not is_sp_tool and os.getenv("EWS_EASA_CSV_ENABLED", "1") == "1" and index_html and accepted < limit:
                csv_rows, csv_issues = _easa_biweekly_csv_rows(index_html, first_url)
                advisories.extend(csv_issues)
                examined += len(csv_rows)
                records.extend(csv_rows)

            dated_rows = [str(r.get("published", "")) for r in records
                          if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r.get("published", "")))]
            if dated_rows:
                oldest_dates.append(min(dated_rows))

            logger.info("[EASA PRIMARY AUDIT] page=%s extracted_rows=%d next=%s", url, len(records), bool(next_page))
            if not records:
                failures.append(f"NO_PARSEABLE_ROWS:{url}")
                break

            for row in records:
                if accepted >= limit:
                    break
                if row["number"] in seen_ad:
                    continue
                seen_ad.add(row["number"])

                if not is_date_within_scope(row["published"]):
                    continue
                scope = _easa_applicability(query, row["subject"], row["applicability"])
                if scope == "NONE" or row["pdf_url"] in COLLECTED_URLS:
                    continue

                is_pad = bool(row.get("is_pad"))
                kind_label = "EASA PAD" if is_pad else "EASA AD"
                stage_label = "PROPOSED" if is_pad else "FINAL_ISSUED"
                note = (
                    "ENGINE-LEVEL AD: aircraft installation NOT established by this index."
                    if scope == "ENGINE_ONLY"
                    else "AIRCRAFT-LEVEL AD: exact variant and technical applicability require PDF review."
                )
                pdf_text = ""
                pdf_truncated = False
                pdf_url = str(row.get("pdf_url") or "")
                if (
                        os.getenv("EWS_EASA_FETCH_PDF_TEXT", "1") == "1"
                        and pdf_url.startswith("https://")
                        and "#ad=" not in pdf_url
                        and ".pdf" in pdf_url.lower()
                ):
                    pdf_resp = safe_http_get(
                        pdf_url, source_id="SRC_002", timeout=15,
                        max_bytes=5_000_000, check_robots=True,
                    )
                    if pdf_resp is not None and pdf_resp.status_code == 200 and pdf_resp.content:
                        pdf_text = _extract_easa_pdf_text(pdf_resp.content, max_chars=12000)
                        pdf_truncated = bool(
                            getattr(pdf_resp, "aero_content_truncated", False)
                            or len(pdf_text) >= 12000
                        )

                has_pdf_text = len(pdf_text) >= 200
                text = (
                        (f"Official EASA {kind_label} PDF text extracted. "
                         if has_pdf_text else
                         "Official EASA Safety Publications Tool index entry; PDF text NOT extracted. ")
                        + f"Regulatory Stage: {stage_label}. "
                        + f"{kind_label}: {row['number']}. Issued: {row['published']}. Subject: {row['subject']}. "
                        + f"Approval Holder / Type Designation: {row['applicability']}. "
                        + f"Effective date: {row['effective'] or 'UNKNOWN'}. Applicability class: {scope}. {note}"
                        + (f"\nOfficial EASA AD Full Text: {pdf_text}" if has_pdf_text else "")
                )
                doc = register_collected_document(
                    source_id="SRC_002", connector_name="EASA Official Index",
                    url=pdf_url, title=f"{kind_label} {row['number']}: {row['subject']}",
                    raw_text=text, published_at=row["published"], query_used=query,
                )
                doc["origin_type"] = "PRIMARY_OFFICIAL_FULL_TEXT" if has_pdf_text else "PRIMARY_OFFICIAL_INDEX_METADATA"
                doc["verified_domain"] = True
                doc["regulatory_stage"] = stage_label
                doc["regulatory_applicability_scope"] = scope
                doc["content_status"] = (
                    ("PARTIAL_TEXT" if pdf_truncated else "FULL_TEXT") if has_pdf_text else "METADATA_ONLY"
                )
                doc["content_truncated"] = bool(has_pdf_text and pdf_truncated)
                doc["regulatory_record_type"] = (
                    ("PROPOSED_AD" if is_pad else "AIRWORTHINESS_DIRECTIVE")
                    if has_pdf_text else
                    ("PROPOSED_AD_INDEX" if is_pad else "AIRWORTHINESS_DIRECTIVE_INDEX")
                )
                doc["regulatory_evidence_role"] = (
                    "OFFICIAL_EASA_AD_PDF_TEXT" if has_pdf_text else "INDEX_METADATA_ONLY; CHECK_APPLICABLE_PDF"
                )

                output += (
                    f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_002\n"
                    f"DATE: {doc['published_at']}\nTitle: {doc['title']}\n"
                    f"Link: {doc['url']}\nSummary: {doc['text']}\n---\n"
                )
                accepted += 1

            if paginated and start and dated_rows and min(dated_rows) < start.date().isoformat():
                url = None
            else:
                url = next_page if paginated else None

        if paginated and len(visited) >= max_pages and url and accepted < limit:
            advisories.append(f"PAGINATION_BUDGET_REACHED:pages={pages}")

    oldest_seen = min(oldest_dates, default="")
    if start and oldest_seen and start.date().isoformat() < oldest_seen:
        advisories.append(f"PARTIAL_COVERAGE:oldest_scanned={oldest_seen}")

    logger.info("[EASA PRIMARY AUDIT] accepted=%d examined=%d pages=%d issues=%s advisories=%s",
                accepted, examined, pages, failures or "none", advisories or "none")
    if failures:
        logger.warning("[EASA COVERAGE] Official archive failure: %s", failures)

    record_connector_telemetry(
        "EASA Official Index", "SRC_002", query, examined, accepted, 0,
        error="; ".join(failures) if failures else None,
        coverage_note="; ".join(dict.fromkeys(advisories)) if advisories else None,
        operational_status=("ACCESS_RESTRICTED" if "ACCESS_RESTRICTED" in failures
                            else "TEMPORARILY_UNAVAILABLE" if failures and not pages
                            else "PARTIAL_COVERAGE" if advisories and not failures
                            else "AVAILABLE"),
        search_outcome=("RETRIEVAL_FAILED" if failures and not pages
                        else "PARTIAL_RESULT" if (failures or advisories)
                        else "RESULTS_RETRIEVED" if accepted else "NO_MATCH"),
    )
    return (output if accepted else "", accepted)

def _faa_model_mentioned(models: list[str], text: str) -> bool:
    """Use the same variant identity checks as NewsAPI and manufacturer PR."""
    return any(_model_matches(identity, text)
               for model in models for identity in _model_identities(model))


def _faa_newsroom_model_match(models: list[str], title: str, body: str) -> bool:
    """Require an exact variant in the article body and its title or certification statement."""
    if not models:
        return True
    sentences = re.split(r"(?<=[.!?])\s+", body)
    return any(
        _faa_model_mentioned([model], body) and (
            _faa_model_mentioned([model], title) or any(
                _faa_model_mentioned([model], sentence) and _FAA_CERTIFICATION_INTENT.search(sentence)
                for sentence in sentences
            )
        ) for model in models
    )


def _collect_faa_certification_news(query: str, limit: int) -> tuple[str, int]:
    """Search FAA announcements separately; an article is not a verified type certificate."""
    models = [identity.aliases[0] for identity in _model_identities(query)]
    entity = lookup_supplier_in_registry(query) if not models else None
    search = models[0] if models else (entity["official_name"] if entity else query[:80])
    requested_docket = _FAA_DOCKET_RE.search(query)
    requested_document = _FAA_NUMBER_RE.search(query)
    listing_url = "https://www.faa.gov/newsroom/press_releases"
    candidates: dict[str, tuple[str, str]] = {}
    errors: list[str] = []
    fetched = False

    def failure(result: HTTPResult) -> str:
        if result.status_code in {401, 403} or result.error_type in {
            "ROBOTS_OR_TDM_BLOCKED", "HTML_TDM_BLOCKED", "RESPONSE_TDM_BLOCKED",
            "SOURCE_POLICY_BLOCKED", "SOURCE_POLICY_OR_HOST_BLOCKED",
        }:
            return "ACCESS_BLOCKED"
        if result.status_code == 429:
            return "RATE_LIMITED"
        return result.error_type or f"HTTP_{result.status_code}"

    for page in range(min(4, max(1, int(os.getenv("EWS_FAA_NEWS_MAX_PAGES", "2"))))):
        result = _safe_http_request(
            listing_url, "SRC_001", params={"keys": search, "page": page},
            check_robots=True, timeout=15, max_bytes=1_500_000,
        )
        if not result.response_complete or result.status_code != 200 or result.response is None:
            errors.append(failure(result))
            break
        fetched = True
        new = 0
        soup = BeautifulSoup(result.response.text, "html.parser")
        for anchor in soup.select("a[href]"):
            link = urljoin(listing_url, anchor["href"])
            parsed = urlparse(link)
            if (parsed.scheme != "https" or parsed.hostname not in {"faa.gov", "www.faa.gov"}
                    or not re.fullmatch(r"/newsroom/[a-z0-9-]+/?", parsed.path, re.IGNORECASE)):
                continue
            title = anchor.get_text(" ", strip=True)
            if len(title) < 15 or link in candidates:
                continue
            card = anchor.find_parent("article") or anchor.parent.parent or anchor
            candidates[link] = (title, normalize_date_str(card.get_text(" ", strip=True)))
            new += 1
            if len(candidates) >= max(limit * 4, 20):
                break
        if not new or len(candidates) >= max(limit * 4, 20):
            break

    # A blocked listing must not trigger an alternate route around access restrictions.
    if not candidates and "ACCESS_BLOCKED" not in errors:
        rss = _safe_http_request(
            listing_url + "/rss", "SRC_001", check_robots=True, timeout=12,
        )
        if rss.status_code == 200 and rss.response_complete and rss.response is not None:
            fetched = True
            for entry in feedparser.parse(rss.response.content).entries[:max(limit * 3, 15)]:
                link = str(entry.get("link") or "")
                candidates[link] = (str(entry.get("title") or ""),
                                    normalize_date_str(entry.get("published") or entry.get("updated") or ""))
        else:
            errors.append(failure(rss))

    output, accepted, certificate_reports, examined = "", 0, 0, 0
    for link, (title, listed_date) in candidates.items():
        parsed = urlparse(link)
        if (accepted >= limit or examined >= max(limit * 3, 6) or link in COLLECTED_URLS
                or parsed.scheme != "https" or parsed.hostname not in {"faa.gov", "www.faa.gov"}
                or not re.fullmatch(r"/newsroom/[a-z0-9-]+/?", parsed.path, re.IGNORECASE)):
            continue
        examined += 1
        page = _safe_http_request(link, "SRC_001", check_robots=True, timeout=15, max_bytes=2_000_000)
        if not page.response_complete or page.status_code != 200 or page.response is None:
            errors.append(failure(page))
            continue
        raw_html = page.response.text
        body = _extract_news_article_body(raw_html)
        publication = extract_article_date(raw_html, body, link, listed_date)
        if (len(body) < 120 or publication == "DATE_UNKNOWN" or not is_date_within_scope(publication)
                or not _FAA_CERTIFICATION_INTENT.search(f"{title} {body}")
                or not _faa_newsroom_model_match(models, title, body)
                or requested_docket and requested_docket.group().upper() not in body.upper()
                or requested_document and requested_document.group() not in body):
            continue
        if entity:
            searchable = _supplier_name_key(f"{title} {body}")
            aliases = (entity["official_name"], *entity.get("aliases", []))
            if not any(re.search(rf"(?<![a-z0-9]){re.escape(_supplier_name_key(alias))}(?![a-z0-9])",
                                 searchable) for alias in aliases if len(alias) >= 4 and not any(c.isdigit() for c in alias)):
                continue

        issued_match = re.search(
            r"\b(?:issued|granted|approved)\b[^.!?]{0,100}\b(?:amended\s+)?type\s+certificate\b"
            r"|\btype\s+certificate\b[^.!?]{0,100}\b(?:issued|granted|approved)\b", body, re.IGNORECASE,
        )
        issuance = bool(issued_match and not re.search(
            r"\b(?:not|never|without|pending|proposed|expected|planned)\b.{0,30}"
            r"\b(?:issued|granted|approved)\b",
            body[max(0, issued_match.start() - 35):issued_match.end()], re.IGNORECASE,
        ))
        category = "FAA_TYPE_CERTIFICATION" if issuance else "FAA_NEWSROOM_ANNOUNCEMENT"
        doc = register_collected_document(
            source_id="SRC_001", connector_name="FAA Type Certification" if issuance else "FAA Newsroom",
            url=link, title=title, raw_text=body, published_at=publication, query_used=query,
        )
        doc.update(
            content_status="FULL_TEXT", origin_type="PRIMARY_OFFICIAL_ANNOUNCEMENT",
            verified_domain=True, faa_record_category=category, regulatory_authority="FAA",
            regulatory_publication_date=publication, regulatory_decision_date="NOT_ESTABLISHED",
            regulatory_decision_type=("TYPE_CERTIFICATE_ISSUANCE_REPORTED" if issuance
                                      else "CERTIFICATION_STATUS_ANNOUNCEMENT"),
            regulatory_record_type="REGULATOR_NEWSROOM_ANNOUNCEMENT",
            regulatory_evidence_role="OFFICIAL_STATEMENT_NOT_TYPE_CERTIFICATE",
            primary_evidence_url=link, certificate_document_verified=False,
            certificate_verification_status="OFFICIAL_STATEMENT_ONLY",
        )
        output += (f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_001\nDATE: {publication}\n"
                   f"Category: {category} | Decision: {doc['regulatory_decision_type']}\n"
                   f"Title: {doc['title']}\nLink: {link}\nCONTENT_STATUS: FULL_TEXT\n"
                   f"Certificate document independently verified: NO\nSummary: {doc['text'][:1500]}\n---\n")
        accepted += 1
        certificate_reports += issuance

    blocked = "ACCESS_BLOCKED" in errors
    if blocked and not accepted:
        record_connector_telemetry(
            "FAA Newsroom", "SRC_001", query, len(candidates), 0,
            error=None,
            coverage_note="OPTIONAL_FAA_NEWSROOM_SKIPPED: www.faa.gov robots.txt HTTP 403 (Federal Register API remains primary SRC_001)",
            operational_status="UNAVAILABLE_OPTIONAL",
            search_outcome="NOT_EXECUTED",
        )
        return "", 0
    status = ("PARTIAL_RESULT" if accepted and errors else "RESULTS_RETRIEVED" if accepted
    else "RETRIEVAL_FAILED" if not fetched
    else "RETRIEVAL_INCOMPLETE" if errors else "NO_MATCH")
    record_connector_telemetry(
        "FAA Newsroom", "SRC_001", query, len(candidates), accepted,
        error="; ".join(dict.fromkeys(errors)) if errors else None,
        coverage_note=f"type_certificate_issuance_reported={certificate_reports}; certificate_document_verified=0",
        operational_status=("RATE_LIMITED" if "RATE_LIMITED" in errors
                            else "AVAILABLE" if fetched else "TEMPORARILY_UNAVAILABLE"),
        search_outcome=status,
    )
    return (">> FAA Official Certification Announcements (not certificates):\n" + output if accepted
            else "", accepted)


# Gather FAA and EASA notices while preserving scope and lifecycle metadata.
# FAA/EASA authority does not by itself prove applicability to the requested variant.
# Authority of origin does not prove exact KIT applicability.
@tool("Scrape EASA and FAA Regulations")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_regulatory_agencies(query: str = "Airbus") -> str:
    # Aggregate FAA and EASA notices, normalizing applicability and timing.
    """Retrieve airworthiness directives and regulatory notices from FAA and EASA."""
    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    scope_days = get_scope_days()
    requested_document = _FAA_NUMBER_RE.search(query)
    requested_docket = _FAA_DOCKET_RE.search(query)
    exact_number = requested_document.group(0) if requested_document else ""
    exact_docket = requested_docket.group(0).upper() if requested_docket else ""
    remaining_query = _FAA_NUMBER_RE.sub(" ", _FAA_DOCKET_RE.sub(" ", query)).strip()
    native_query = re.sub(
        r"(?<!\w)-?(?:site|inurl|filetype):\S+", " ", remaining_query, flags=re.IGNORECASE,
    )
    native_query = re.sub(r"\b(?:FAA|EASA|NTSB)\b", " ", native_query, flags=re.IGNORECASE).strip()
    certification_query = bool(re.search(
        r"\b(?:certif\w*|approv\w*|type\s+certificate)\b",
        query, re.IGNORECASE,
    ))
    exact_models = _model_tokens(remaining_query) if certification_query else []
    required_words, _ = parse_query_intent(native_query) if native_query else ([], "")
    search_term = _faa_native_term(native_query) if native_query else ""

    logger.info(
        f"[OSINT GATHERER] Querying FAA and EASA databases for: '{query}' (limit: {limit}, scope: {scope_days or 'all'} days)")
    extracted_text = f"--- REGULATORY DIRECTIVES AND NOTICES (FAA & EASA) FOR '{query}' ---\n"

    retrieval_status = "RETRIEVAL_FAILED"
    try:
        params: dict[str, Any] = {
            "conditions[agencies][]": "federal-aviation-administration",
            "order": "newest",
            "fields[]": _FAA_LIFECYCLE_FIELDS,
            "conditions[publication_date][lte]": end_utc.strftime("%Y-%m-%d"),
        }
        if start_utc is not None:
            params["conditions[publication_date][gte]"] = start_utc.strftime("%Y-%m-%d")

        docs: list[dict[str, Any]] = []
        audits: list[dict[str, Any]] = []
        if exact_number:
            detail_url = f"https://www.federalregister.gov/api/v1/documents/{exact_number}.json"
            candidate, http = _faa_json_result(
                detail_url,
                params={"fields[]": _FAA_LIFECYCLE_FIELDS}, immutable=True,
            )
            direct_calls = 1
            if candidate is None and http.payload_classification in {
                "UNEXPECTED_SCHEMA", "API_ERROR_RESPONSE",
            }:
                # Retry the same immutable document identity without optional fields.
                # A blocked or unavailable source must never be bypassed.
                candidate, http = _faa_json_result(detail_url, immutable=False)
                direct_calls += 1
            identity_ok = bool(candidate and candidate.get("document_number") == exact_number)
            date_known = bool(identity_ok and candidate.get("publication_date"))
            in_scope = bool(date_known and is_date_within_scope(candidate.get("publication_date")))
            if in_scope:
                docs.append(candidate)
            blocked = http.payload_classification == "ACCESS_BLOCKED"
            direct_status = (
                "RESULTS_RETRIEVED" if in_scope else
                "NO_RESULTS" if date_known and not in_scope else
                "ACCESS_BLOCKED" if blocked else
                "SOURCE_UNAVAILABLE" if http.payload_classification in {
                    "SOURCE_UNAVAILABLE", "HTTP_ERROR"
                } and http.status_code not in {400, 404, 414, 422} else
                "RETRIEVAL_FAILED"
            )
            audits.append({
                "status": direct_status, "declared_count": 1 if identity_ok else 0,
                "processed_count": int(in_scope), "access_restricted": blocked,
                "last_error": ("OUTSIDE_TIME_SCOPE" if date_known and not in_scope
                               else "MISSING_PUBLICATION_DATE" if identity_ok and not date_known
                               else (http.error_type or "IDENTIFIER_MISMATCH") if not identity_ok
                               else ""),
                "request_calls": direct_calls,
                "attempts": [{"http_status": http.status_code,
                              "response_classification": http.payload_classification,
                              "response_schema": http.payload_shape,
                              "error_code": http.error_type}],
            })

        if exact_docket:
            docket_docs, audit = _faa_search_pages({**params, "conditions[docket_id]": exact_docket}, limit)
            docs.extend(docket_docs)
            audits.append(audit)

        if search_term and not (exact_docket or exact_number):
            general_docs, audit = _faa_search_pages({**params, "conditions[term]": search_term}, limit)
            docs.extend(general_docs)
            audits.append(audit)
        elif not exact_docket and not exact_number:
            general_docs, audit = _faa_search_pages({**params, "conditions[term]": _faa_native_term(query)}, limit)
            docs.extend(general_docs)
            audits.append(audit)

        docs = list({d["document_number"]: d for d in reversed(docs)
                     if d.get("document_number")}.values())[::-1]
        if (not docs and not exact_docket and not exact_number and not certification_query
                and audits and all(a["status"] == "NO_RESULTS" for a in audits)):
            engine_topic = bool(re.search(
                r"\b(?:engine|engines|turbine|hpt|hpc|propulsion|gearbox|gtf|leap|pw1100g)\b",
                query, re.IGNORECASE,
            ))
            domain_info = get_program_engine_domain(query) if engine_topic else {
                "engine_models": (), "engine_manufacturers": (),
            }
            fallback_terms: list[str] = []
            if engine_topic and (domain_info["engine_models"] or domain_info["engine_manufacturers"]):
                fallback_terms.extend(domain_info["engine_models"][:2])
                fallback_terms.extend(domain_info["engine_manufacturers"][:3])
            else:
                entity = lookup_supplier_in_registry(query)
                broad_term = (
                    re.sub(r"\s*\([^)]*\)", "", entity["official_name"]).strip()
                    if entity else next(iter(_model_tokens(query)), "")
                )
                if broad_term:
                    fallback_terms.append(broad_term)

            for broad_term in list(dict.fromkeys(fallback_terms))[:4]:
                if broad_term.casefold() == search_term.casefold():
                    continue
                fb_docs, audit = _faa_search_pages({**params, "conditions[term]": broad_term}, limit)
                audits.append(audit)
                if fb_docs:
                    docs.extend(fb_docs)
                    logger.info("[FAA RECALL] Broad query %r returned %d records", broad_term, len(fb_docs))
                    if len(docs) >= limit * 2:
                        break
            docs = list({d["document_number"]: d for d in reversed(docs)
                         if d.get("document_number")}.values())[::-1]

        if docs:
            faa_count = faa_rejected = 0
            docket_cache: dict[str, tuple[dict[str, Any], bool]] = {}
            faa_block = ">> FAA (Federal Aviation Administration - Federal Register):\n"

            for found_doc in docs:
                if faa_count >= limit:
                    break
                title = str(found_doc.get("title") or "")
                abstract = str(found_doc.get("abstract") or "")
                if (certification_query and exact_models and not (exact_docket or exact_number)
                        and not _faa_model_mentioned(
                    exact_models, f"{title} {abstract}"
                )):
                    continue
                doc, docket, checked = _faa_resolve_docket(found_doc, end_utc.strftime("%Y-%m-%d"), docket_cache)
                identifier_match = ((exact_number and doc.get("document_number") == exact_number)
                                    or (exact_docket and docket == exact_docket))
                if exact_docket and docket != exact_docket:
                    continue  # Other dockets are not evidence for a specifically requested docket.
                if not identifier_match and not any(rw in f"{title} {abstract}".lower() for rw in required_words):
                    continue
                link = doc.get("html_url") or ""
                pub_date = doc.get("publication_date") or "DATE_UNKNOWN"

                if not link or link in COLLECTED_URLS:
                    continue
                if not is_date_within_scope(pub_date):
                    faa_rejected += 1
                    continue

                doc_type = str(doc.get("type") or "").strip().upper()
                action = str(doc.get("action") or "").strip().lower()
                effective_on = str(doc.get("effective_on") or "")

                is_proposed = doc_type in {"PRORULE",
                                           "PROPOSED RULE"} or "notice of proposed rulemaking" in action or action.startswith(
                    "proposed rule")
                is_final = doc_type == "RULE" or action.startswith("final rule")

                withdrawn = bool(re.search(
                    r"\b(?:withdraw(?:n|s|al|ing)?|rescinds?|rescission)\b",
                    f"{action} {doc.get('abstract') or ''}", re.IGNORECASE,
                ) and re.search(
                    r"\b(?:nprm|notice of proposed rulemaking|proposed rule|proposal)\b",
                    f"{action} {doc.get('abstract') or ''}", re.IGNORECASE,
                ))
                if withdrawn:
                    stage = "WITHDRAWN"
                elif is_proposed:
                    stage = "PROPOSED"
                elif is_final:
                    stage = "EFFECTIVE" if (
                            effective_on and effective_on <= end_utc.strftime("%Y-%m-%d")) else "FINAL_ISSUED"
                else:
                    stage = "UNKNOWN"

                summary = str(doc.get("abstract") or "").replace("\n", " ").strip()
                old_url = found_doc.get("html_url") or ""
                history = f"Related earlier document: {old_url}\n" if (old_url and old_url != link) else ""
                latest_number = doc.get("lifecycle_latest_document_number") or ""
                if latest_number and latest_number != doc.get("document_number"):
                    history += f"Later document in same docket: {latest_number} (separate publication)\n"

                raw_text = (
                    f"Regulatory Stage: {stage}\n"
                    f"Regulatory Lifecycle Check: {'VERIFIED' if checked else 'UNVERIFIED'}\n"
                    f"FAA Docket: {docket or 'UNKNOWN'}\n"
                    f"Federal Register Document: {doc.get('document_number', 'UNKNOWN')}\n"
                    f"Publication Date: {pub_date}\n"
                    f"Effective Date: {effective_on or 'UNKNOWN'}\n"
                    f"{history}Official Summary: {summary}"
                )
                content_status = "SUMMARY_ONLY"
                # Only URLs furnished by the official API are eligible, never constructed guesses.
                full_url = str(doc.get("raw_text_url") or doc.get("html_url") or "")
                full_host = (urlparse(full_url).hostname or "").lower()
                if full_url.startswith("https://") and full_host in {
                    "federalregister.gov", "www.federalregister.gov",
                } and os.getenv("EWS_FAA_FETCH_FULL_TEXT", "1") == "1":
                    full_page = _faa_cached_get(
                        full_url, immutable=True, max_bytes=8_000_000, check_robots=True,
                    )
                    if full_page.response is not None and full_page.response_complete:
                        full_text = _faa_full_text(full_page.response, full_url)
                        if len(full_text) >= 500:
                            raw_text += "\nOfficial Full Text: " + full_text
                            content_status = "FULL_TEXT"
                doc_rec = register_collected_document(
                    source_id="SRC_001", connector_name="FAA Federal Register", url=link,
                    title=doc.get("title") or title, raw_text=raw_text, published_at=pub_date, query_used=query,
                )
                obligation = ""
                if content_status in {"FULL_TEXT", "PARTIAL_TEXT"} and stage in {"EFFECTIVE", "FINAL_ISSUED"}:
                    match = re.search(
                        r"(?i)\b(?:compliance time|within \d+ (?:calendar )?days? after (?:the )?effective date)"
                        r"[^.!?\n]{0,250}[.!?]", raw_text,
                    )
                    obligation = match.group(0) if match else ""
                airworthiness_directive = bool(re.search(
                    r"\bairworthiness\s+directiv\w*\b|\bAD\s+20\d{2}",
                    f"{doc.get('title') or ''} {doc.get('abstract') or ''}", re.IGNORECASE,
                ))
                doc_rec.update(
                    content_status=content_status,
                    content_truncated=content_status == "PARTIAL_TEXT",
                    content_limit_reason=(
                        "HTTP_MAX_BYTES" if content_status == "PARTIAL_TEXT" else ""
                    ),
                    regulatory_stage=stage,
                    regulatory_publication_date=pub_date,
                    regulatory_effective_date=effective_on or "DATE_UNKNOWN",
                    regulatory_compliance_deadline="NOT_ESTABLISHED",
                    regulatory_obligation_quote_candidate=obligation,
                    faa_document_number=doc.get("document_number", ""),
                    faa_docket_id=docket,
                    faa_latest_docket_document_number=latest_number,
                    faa_lifecycle_relation=doc.get("lifecycle_relation", "UNKNOWN"),
                    faa_record_category=("FAA_AIRWORTHINESS_DIRECTIVE" if airworthiness_directive
                                         else "FAA_FEDERAL_REGISTER_NOTICE"),
                    regulatory_record_type=("AIRWORTHINESS_DIRECTIVE" if airworthiness_directive
                                            else "FEDERAL_REGISTER_RULE_OR_NOTICE"),
                    regulatory_evidence_role="PUBLICATION_NOT_AUTOMATIC_TYPE_CERTIFICATION",
                    requested_identifier_match=bool(identifier_match),
                )
                faa_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_001\n"
                    f"DATE: {doc_rec['published_at']}\n"
                    f"Document Type: {doc_type} | Regulatory Stage: {stage}\n"
                    f"Title: {doc_rec['title']}\nLink: {link}\n"
                    f"CONTENT_STATUS: {content_status}\n"
                    f"Summary: {doc_rec['text'][:5000]}\n---\n"
                )
                faa_count += 1

            hard_errors = [
                f"{a['status']}:{a.get('last_error') or 'UNKNOWN'}" for a in audits
                if a["status"] in {"SOURCE_UNAVAILABLE", "RETRIEVAL_FAILED", "ACCESS_BLOCKED"}
            ]
            partial_only = any(a["status"] == "PARTIAL_COVERAGE" for a in audits) and not hard_errors
            retrieval_status = (
                "ACCESS_BLOCKED" if any(a.get("access_restricted") for a in audits)
                else "PARTIAL_COVERAGE" if (partial_only or hard_errors)
                else "RESULTS_RETRIEVED"
            )
            record_connector_telemetry(
                "FAA Federal Register", "SRC_001", query, len(docs), faa_count, faa_rejected,
                coverage_note=(f"{retrieval_status}; api_declared={sum(a['declared_count'] for a in audits)}; "
                               f"retrieved={len(docs)}; accepted={faa_count}; "
                               f"pagination_complete={all(a.get('pagination_complete', True) for a in audits)}"),
                diagnostics={"page_audits": audits},
                error="; ".join(hard_errors) if hard_errors else None,
                operational_status=(
                    "ACCESS_RESTRICTED" if any(a.get("access_restricted") for a in audits)
                    else "TEMPORARILY_UNAVAILABLE" if hard_errors
                    else "PARTIAL_COVERAGE" if partial_only
                    else "AVAILABLE"
                ),
                search_outcome="PARTIAL_RESULT" if (partial_only or hard_errors)
                else "RESULTS_RETRIEVED" if faa_count else "NO_MATCH",
            )
            if faa_count > 0:
                extracted_text += faa_block
        else:
            retrieval_status = ("ACCESS_BLOCKED" if any(a.get("access_restricted") for a in audits)
                                else "SOURCE_UNAVAILABLE" if any(
                    a["status"] == "SOURCE_UNAVAILABLE" for a in audits)
                else "RETRIEVAL_FAILED" if any(
                    a["status"] == "RETRIEVAL_FAILED" for a in audits)
                else "PARTIAL_COVERAGE" if any(
                    a["status"] == "PARTIAL_COVERAGE" for a in audits) else "NO_RESULTS")
            record_connector_telemetry(
                "FAA Federal Register", "SRC_001", query,
                coverage_note=(f"{retrieval_status}; api_declared={sum(a['declared_count'] for a in audits)}; retrieved=0"),
                diagnostics={"page_audits": audits},
                error="; ".join(f"{a['status']}:{a.get('last_error') or 'UNKNOWN'}" for a in audits
                                if a["status"] not in {"RESULTS_RETRIEVED", "NO_RESULTS"}) or None,
                operational_status="ACCESS_BLOCKED" if any(a.get("access_restricted") for a in audits)
                                   else "TEMPORARILY_UNAVAILABLE" if retrieval_status != "NO_RESULTS"
                                   else "AVAILABLE",
                search_outcome="ACCESS_BLOCKED" if retrieval_status == "ACCESS_BLOCKED"
                               else "SOURCE_UNAVAILABLE" if retrieval_status == "SOURCE_UNAVAILABLE"
                               else "PARTIAL_RESULT" if retrieval_status == "PARTIAL_COVERAGE"
                               else "RETRIEVAL_FAILED" if retrieval_status == "RETRIEVAL_FAILED" else "NO_MATCH",
            )
    except Exception as e:
        logger.error(f"[OSINT GATHERER] Federal Register FAA API error: {e}")
        record_connector_telemetry("FAA Federal Register", "SRC_001", query, error=str(e),
                                   operational_status="TEMPORARILY_UNAVAILABLE",
                                   search_outcome="RETRIEVAL_FAILED")

    easa_only_query = (
            bool(re.search(r"\b(?:easa|caac|tcca|anac|uk\s+caa|european)\b", query, re.IGNORECASE))
            and not bool(
        re.search(r"\b(?:faa|federal\s+aviation\s+administration|20\d{2}-\d{5}|faa-20\d{2})\b", query, re.IGNORECASE))
    )
    if easa_only_query:
        logger.info("[FAA NEWSROOM ROUTING] Skipped FAA Newsroom for non-FAA/EASA-specific query.")
    elif certification_query and os.getenv("EWS_FAA_NEWSROOM_ENABLED", "0") == "1":
        try:
            newsroom, _ = _collect_faa_certification_news(query, limit)
            extracted_text += newsroom
        except Exception as exc:
            logger.warning("[FAA NEWSROOM] Certification search unavailable: %s", exc)
            record_connector_telemetry("FAA Newsroom", "SRC_001", query, error=None,
                                       coverage_note=f"OPTIONAL_FAA_NEWSROOM_ERROR: {exc}",
                                       operational_status="UNAVAILABLE_OPTIONAL",
                                       search_outcome="NOT_EXECUTED")

    primary_count = 0

    faa_only_query = (
            bool(re.search(r"\b(?:faa|20\d{2}-\d{5})\b", query, re.IGNORECASE))
            and not bool(re.search(r"\b(?:easa|european|airbus|a320|a321|a350|a330|a220)\b", query, re.IGNORECASE))
    )
    easa_env_enabled = os.getenv("EWS_EASA_SAFETY_PUBLICATIONS_ENABLED", "1") == "1"
    if faa_only_query:
        logger.info("[EASA ROUTING] Skipped EASA Official Index for FAA-specific query.")
    elif not easa_env_enabled:
        record_connector_telemetry(
            "EASA Official Index", "SRC_002", query,
            coverage_note="DISABLED_BY_CONFIG: EWS_EASA_SAFETY_PUBLICATIONS_ENABLED=0",
            operational_status="DISABLED_BY_CONFIG", search_outcome="NOT_EXECUTED",
        )
    elif not is_source_allowed("SRC_002"):
        record_connector_telemetry(
            "EASA Official Index", "SRC_002", query,
            coverage_note="POLICY_REQUIRES_REVIEW: set EWS_TEST_REVIEW_SOURCES=1 or approve SRC_002 in registry.py",
            operational_status="POLICY_REQUIRES_REVIEW", search_outcome="NOT_EXECUTED",
        )
    else:
        try:
            primary_block, primary_count = _collect_easa_primary_index(query, limit)
            if primary_count:
                extracted_text += primary_block
        except Exception as exc:
            logger.warning('[EASA INDEX] Source unavailable: %s', exc)
            record_connector_telemetry('EASA Official Index', 'SRC_002', query, error=str(exc),
                                       operational_status="TEMPORARILY_UNAVAILABLE",
                                       search_outcome="RETRIEVAL_FAILED")

    if "Title:" not in extracted_text:
        if retrieval_status in {"ACCESS_BLOCKED", "RETRIEVAL_FAILED", "SOURCE_UNAVAILABLE", "PARTIAL_COVERAGE"}:
            return (f"FAA {retrieval_status}; absence of relevant records NOT established for '{query}' "
                    "(EASA separately subject to its source status).")
        return (f"FAA {retrieval_status}; no qualifying records for '{query}' "
                "in the selected time scope (EASA separately subject to its source status).")

    logger.warning(f"[OSINT DEBUG] Regulatory module returned records for '{query}'.")
    return extracted_text

# Collect official aerospace manufacturer announcements and release timestamps.
# A manufacturer release is primary evidence of its statement, not all implied impacts.
@tool("Scrape Manufacturer PR News")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_manufacturer_pr_news(query: str = "Aviation") -> str:
    # Collect primary-source aerospace announcements with publication metadata.
    """Fetch only configured, approved manufacturer announcements."""
    original_query = query.replace(",", "").replace("  ", " ").strip()
    required_words, safe_query = parse_query_intent(original_query)
    limit_per_feed = get_dynamic_limit()
    scope_days = get_scope_days()
    logger.info(
        f"[OSINT GATHERER] Fetching manufacturer PR feeds for: '{safe_query}' (limit: {limit_per_feed}, scope: {scope_days or 'all'} days)"
    )
    extracted_text = f"--- OFFICIAL MANUFACTURER PRESS RELEASES FOR '{safe_query}' ---\n"

    feeds = {
        "Airbus": ("SRC_005", "https://www.airbus.com/en/generate-rss-feeds?type=all-press-releases"),
        "Boeing": ("SRC_030", "https://boeing.mediaroom.com/news-releases-statements?pagetemplate=rss"),
    }
    # Volitelné oficiální RSS kanály výrobců motorů (konfigurovatelné v .env, aby se nehádaly neověřené URL).
    if rtx_rss := os.getenv("EWS_RTX_RSS_URL", "").strip():
        feeds["RTX / Pratt & Whitney"] = ("SRC_011", rtx_rss)
    if ge_rss := os.getenv("EWS_GE_RSS_URL", "").strip():
        feeds["GE Aerospace"] = ("SRC_010", ge_rss)

    mentioned = set()
    if re.search(r"\bairbus\b", original_query, re.IGNORECASE):
        mentioned.add("Airbus")
    if re.search(r"\bboeing\b", original_query, re.IGNORECASE):
        mentioned.add("Boeing")
    if "RTX / Pratt & Whitney" in feeds and re.search(
            r"\b(?:pratt\s*(?:&|and)?\s*whitney|rtx|pw1100g|pw1500g|gtf|international\s+aero\s+engines)\b",
            original_query, re.IGNORECASE,
    ):
        mentioned.add("RTX / Pratt & Whitney")
    if "GE Aerospace" in feeds and re.search(
            r"\b(?:ge\s+aerospace|general\s+electric|cfm|leap-?1[abc]|genx|ge9x)\b",
            original_query, re.IGNORECASE,
    ):
        mentioned.add("GE Aerospace")

    targets = _model_identities(original_query)
    unknown_models = [target for target in targets if target.kind == "unknown_technical_identifier"]
    aircraft_models = [target for target in targets if target.kind == "aircraft_model"]
    inferred = {"Boeing" if re.match(r"(?:B)?7\d{2}", target.canonical_id, re.IGNORECASE) else "Airbus"
                for target in aircraft_models if re.match(r"(?:B)?7\d{2}|A\d{3}", target.canonical_id, re.IGNORECASE)}
    if re.search(r"\b(?:engine|engines|turbine|propulsion|gtf|leap|pw1100g)\b", original_query, re.IGNORECASE):
        domain_oems = " ".join(get_program_engine_domain(original_query)["engine_manufacturers"]).lower()
        if "RTX / Pratt & Whitney" in feeds and ("pratt" in domain_oems or "international aero engines" in domain_oems):
            inferred.add("RTX / Pratt & Whitney")
        if "GE Aerospace" in feeds and ("ge aerospace" in domain_oems or "cfm" in domain_oems):
            inferred.add("GE Aerospace")

    selection_status, selection_reason = "SOURCE_SELECTED", "EXPLICIT_MANUFACTURER" if mentioned else "AIRCRAFT_IDENTITY"
    if not mentioned:
        mentioned = inferred
    else:
        # U motorového KITu přidej ke jmenovanému OEM draku i odpovídající výrobce motorů.
        mentioned |= (inferred - {"Airbus", "Boeing"})
    if unknown_models and not mentioned:
        selection_status, selection_reason = "ENTITY_UNRESOLVED", "UNKNOWN_TECHNICAL_IDENTIFIER"
    elif mentioned and inferred and not (mentioned & inferred):
        selection_status, selection_reason = "ENTITY_UNRESOLVED", "MANUFACTURER_MODEL_CONFLICT"
    elif not mentioned:
        selection_status, selection_reason = (
            "SOURCE_NOT_CONFIGURED", "NO_APPROVED_MANUFACTURER_CONNECTOR"
        ) if (find_supplier_mentions(original_query) or any(t.kind == "engine_model" for t in targets)
              or any(re.search(rf"\b{re.escape(name)}\b", original_query, re.IGNORECASE)
                     for name in GENERIC_MANUFACTURERS - feeds.keys())) else (
            "ENTITY_UNRESOLVED", "NO_IDENTIFIABLE_OEM_OR_PROGRAM"
        )
    elif re.search(r"\b(?:airworthiness\s+directives?|inspection\s+requirements?|"
                   r"regulatory\s+compliance\s+deadline)\b", original_query, re.IGNORECASE) and not re.search(
            r"\b(?:press|statement|news|announc\w*)\b", original_query, re.IGNORECASE):
        selection_status, selection_reason = "SOURCE_NOT_RELEVANT", "OFFICIAL_REGULATORY_EVIDENCE_REQUIRED"
    if selection_status != "SOURCE_SELECTED":
        record_connector_telemetry(
            "Official Industry PR", "", original_query,
            operational_status=selection_status, search_outcome="NOT_EXECUTED",
            coverage_note=selection_reason,
        )
        return f"Official Industry PR: {selection_status} ({selection_reason}; no HTTP request)."
    feeds = {name: item for name, item in feeds.items() if name in mentioned}
    for brand, (source_id, _) in feeds.items():
        record_connector_telemetry(
            f"Official Industry PR / {brand}", source_id, original_query,
            operational_status="SOURCE_SELECTED", search_outcome="NOT_EXECUTED",
            diagnostics={"selection_reason": selection_reason, "selected_manufacturer": brand},
        )

    total_processed = accessible_feeds = parse_failures = 0
    blocked_feeds = unavailable_feeds = partial_feeds = 0
    noise_tokens = ("#shorts", "compilation", "takeoff", "landing", "cabin", "trip report", "flight simulator", "msfs")

    for i, (brand, (source_id, url)) in enumerate(feeds.items()):
        if total_processed >= limit_per_feed:
            break

        remaining = limit_per_feed - total_processed
        brand_quota = max(1, (remaining + len(feeds) - i - 1) // (len(feeds) - i))

        try:
            if not is_source_allowed(source_id):
                blocked_feeds += 1
                record_connector_telemetry(
                    f"Official Industry PR / {brand}", source_id, original_query,
                    operational_status="ACCESS_RESTRICTED", search_outcome="NOT_EXECUTED",
                    error="SOURCE_POLICY_RESTRICTED",
                )
                continue

            feed_result = _safe_http_request(url, source_id=source_id, timeout=12, check_robots=True)
            resp = feed_result.response
            if resp is None or resp.status_code != 200:
                restricted = feed_result.status_code in {401, 403} or feed_result.error_type in {
                    "SOURCE_POLICY_BLOCKED", "ROBOTS_OR_TDM_BLOCKED", "RESPONSE_TDM_BLOCKED",
                    "HTML_TDM_BLOCKED",
                }
                blocked_feeds += bool(restricted)
                unavailable_feeds += not restricted
                record_connector_telemetry(
                    f"Official Industry PR / {brand}", source_id, original_query,
                    operational_status="ACCESS_RESTRICTED" if restricted else "TEMPORARILY_UNAVAILABLE",
                    search_outcome="ACCESS_BLOCKED" if restricted else "RETRIEVAL_FAILED",
                    error=feed_result.error_type or f"RSS_HTTP_{feed_result.status_code}",
                )
                continue
            accessible_feeds += 1
            feed = feedparser.parse(resp.content)
            if not feed.entries:
                parse_failures += bool(feed.bozo)
                record_connector_telemetry(
                    f"Official Industry PR / {brand}", source_id, original_query,
                    operational_status="TEMPORARILY_UNAVAILABLE" if feed.bozo else "AVAILABLE",
                    search_outcome="RETRIEVAL_FAILED" if feed.bozo else "NO_MATCH",
                    error="RSS_PARSE_ERROR" if feed.bozo else None,
                )
                continue

            brand_block = f"\n>> {brand} Official Newsroom:\n"
            brand_count = brand_rejected = screened_out = detail_blocked = detail_unavailable = metadata_only = 0
            examined_count = 0
            candidate_outcomes: dict[str, str] = {}
            candidate_budget = min(100, max(50, brand_quota * 10))
            technical_query = bool(re.search(
                r"\b(?:engine|engines|defect|problem|problems|issue|issues|inspect|turbine|delay|shortage|ground|safety)\b",
                original_query, re.IGNORECASE,
            )) and not bool(re.search(r"\b(?:order|orders|delivery|deliveries|contract|fleet)\b", original_query, re.IGNORECASE))
            commercial_pr_re = re.compile(
                r"\b(?:orders?\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|additional|more)|"
                r"firm\s+order|places?\s+(?:an?\s+|firm\s+)?orders?|takes\s+delivery|share\s+buyback)\b",
                re.IGNORECASE,
            )
            topic_words = {word.casefold() for word in required_words
                           if len(word) >= 4 and word.casefold() not in {
                               "airbus", "boeing", "risks", "risk", "aviation", "aerospace", "news", "latest"
                           } and not any(ch.isdigit() for ch in word)}
            for entry in feed.entries[:candidate_budget]:
                if brand_count >= brand_quota:
                    break
                examined_count += 1

                link = entry.get("link", f"https://www.{brand.lower()}.com")
                if link in COLLECTED_URLS:
                    candidate_outcomes[link] = "DUPLICATE"
                    continue

                raw_date = entry.get("published") or entry.get("updated") or ""

                numeric_date = re.search('\\b(\\d{1,2})/(\\d{1,2})/(20\\d{2})\\b', raw_date)

                if numeric_date:
                    month, day, year = map(int, numeric_date.groups())
                    try:
                        pub_date = datetime(year, month, day).date().isoformat()
                    except ValueError:
                        pub_date = "DATE_UNKNOWN"
                else:
                    pub_date = normalize_date_str(raw_date) or "DATE_UNKNOWN"

                if not is_date_within_scope(pub_date):
                    brand_rejected += 1
                    candidate_outcomes[link] = "DATE_OUT_OF_SCOPE"
                    continue

                title = entry.get("title", "Untitled release")
                if any(k in title.lower() for k in noise_tokens):
                    candidate_outcomes[link] = "UNRELATED_RELEASE_TYPE"
                    continue
                if technical_query and commercial_pr_re.search(title):
                    screened_out += 1
                    candidate_outcomes[link] = "COMMERCIAL_ORDER_PR_SKIPPED"
                    continue

                raw_rss_content = ""
                if isinstance(entry.get("content"), list) and entry["content"]:
                    raw_rss_content = str(entry["content"][0].get("value") or "")
                raw_rss_html = raw_rss_content or entry.get("summary") or entry.get("description") or ""
                full_rss_text = BeautifulSoup(raw_rss_html, "html.parser").get_text("\n", strip=True)[:6000]
                desc = full_rss_text[:400]
                metadata_text = f"{title} {desc}"
                if (targets and not any(_model_matches(target, metadata_text) for target in targets)
                        or not targets and topic_words and not any(
                            re.search(rf"\b{re.escape(word)}\w*\b", metadata_text, re.IGNORECASE)
                            for word in topic_words)):
                    screened_out += 1
                    candidate_outcomes[link] = "RSS_METADATA_NOT_RELEVANT"
                    continue  # Screen RSS metadata before requesting full article HTML.
                host = (urlparse(link).hostname or "").lower()
                domains = {
                    "Airbus": ("airbus.com",),
                    "Boeing": ("boeing.com", "boeing.mediaroom.com"),
                    "RTX / Pratt & Whitney": ("rtx.com", "prattwhitney.com"),
                    "GE Aerospace": ("geaerospace.com", "cfmaeroengines.com"),
                }
                official = any(host == d or host.endswith("." + d) for d in domains.get(brand, ()))
                if not official:
                    brand_rejected += 1
                    candidate_outcomes[link] = "UNAPPROVED_HOST"
                    continue
                doc_source_id = source_id

                body = ""
                detail_result = _safe_http_request(link, source_id=doc_source_id, timeout=8,
                                                   check_robots=True)
                page = detail_result.response
                if page is None or page.status_code != 200:
                    if detail_result.status_code in {401, 403} or detail_result.error_type in {
                        "SOURCE_POLICY_BLOCKED", "ROBOTS_OR_TDM_BLOCKED", "RESPONSE_TDM_BLOCKED",
                        "HTML_TDM_BLOCKED",
                    }:
                        detail_blocked += 1
                    else:
                        detail_unavailable += 1
                rss_body_used = False
                if (page is not None and page.status_code == 200
                        and "html" in page.headers.get("Content-Type", "").lower()):
                    extracted = _extract_news_article_body(page.text)

                    title_terms = {
                        w for w in re.findall(r"[a-z0-9]{3,}", title.lower())
                        if w not in {"boeing", "airbus", "with", "from", "this", "that", "for", "and", "the"}
                    }

                    body_terms = set(re.findall(r"[a-z0-9]{3,}", extracted.lower()))
                    min_overlap = min(2, len(title_terms)) if len(extracted) < 400 else min(1, len(title_terms))

                    if len(extracted) >= 220 and len(title_terms & body_terms) >= min_overlap:
                        body = extracted

                if not body and len(full_rss_text) >= 220 and full_rss_text.casefold() != title.strip().casefold():
                    body = full_rss_text
                    rss_body_used = True

                if targets and not any(_model_matches(target, f"{title} {desc} {body}")
                                       for target in targets):
                    brand_rejected += 1
                    candidate_outcomes[link] = "MODEL_NOT_VERIFIED"
                    continue

                raw_text = body if body else (
                        "[OFFICIAL_RSS_METADATA_ONLY: "
                        "FULL ARTICLE UNAVAILABLE]\n"
                        + (desc or title)
                )
                metadata_only += not bool(body)

                doc_rec = register_collected_document(
                    source_id=doc_source_id,
                    connector_name=f"Official Industry PR / {brand}",
                    url=link,
                    title=title,
                    raw_text=raw_text,
                    published_at=pub_date,
                    query_used=original_query,
                )

                doc_rec["content_status"] = (
                    "PARTIAL_TEXT" if rss_body_used else
                    ("PARTIAL_TEXT" if getattr(page, "aero_content_truncated", False) else "FULL_TEXT")
                    if body else "METADATA_ONLY"
                )
                doc_rec["content_truncated"] = bool(
                    body and not rss_body_used and getattr(page, "aero_content_truncated", False))
                doc_rec["content_limit_reason"] = (
                    "RSS_BODY_EXCERPT" if rss_body_used else
                    "HTTP_MAX_BYTES" if doc_rec["content_truncated"] else ""
                )
                doc_rec["origin_type"] = (
                    "PRIMARY_OFFICIAL_RSS_BODY" if rss_body_used else
                    "PRIMARY_OFFICIAL_FULL_TEXT" if body else "OFFICIAL_RSS_METADATA_ONLY"
                )
                doc_rec.update(verified_domain=True, event_date="NOT_ESTABLISHED",
                               event_date_basis="PUBLICATION_DATE_ONLY")
                brand_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: {doc_source_id}\n"
                    f"DATE: {doc_rec['published_at']}\nTitle: {doc_rec['title']}\n"
                    f"Link: {link}\nCONTENT_STATUS: {doc_rec['content_status']}\n"
                    f"Summary: {doc_rec['text'][:5000]}\n---\n"
                )
                brand_count += 1
                total_processed += 1
                candidate_outcomes[link] = "COLLECTED_METADATA_ONLY" if not body else "COLLECTED_FULL_TEXT"

            # Outside the "for entry in feed.entries" loop.
            if brand_count:
                extracted_text += brand_block

            partial_feeds += bool(feed.bozo or len(feed.entries) > examined_count or
                                  detail_blocked or detail_unavailable or metadata_only)
            record_connector_telemetry(
                f"Official Industry PR / {brand}",
                source_id,
                safe_query,
                found_count=len(feed.entries),
                accepted_count=brand_count,
                rejected_out_of_scope=brand_rejected,
                operational_status="AVAILABLE",
                search_outcome=("PARTIAL_RESULT" if feed.bozo or len(feed.entries) > examined_count
                                or metadata_only or detail_blocked or detail_unavailable else
                                "RESULTS_RETRIEVED" if brand_count else
                                "NO_MATCH"),
                coverage_note=("RSS_METADATA_SCREENING_NOT_FULL_TEXT_VERIFICATION"
                               if screened_out or metadata_only or detail_blocked or detail_unavailable else None),
                diagnostics={"rss_candidates_examined": examined_count,
                             "rss_metadata_rejected": screened_out,
                             "rss_candidates_unexamined": max(0, len(feed.entries) - examined_count),
                             "candidate_outcomes": candidate_outcomes,
                             "metadata_only_records": metadata_only,
                             "article_access_blocked": detail_blocked,
                             "article_unavailable": detail_unavailable},
            )

        except Exception as e:
            logger.error(f"[OSINT GATHERER] PR feed error for {brand}: {e!s}")
            record_connector_telemetry(
                f"Official Industry PR / {brand}", source_id, original_query,
                operational_status="TEMPORARILY_UNAVAILABLE", search_outcome="RETRIEVAL_FAILED",
                error=str(e),
            )

    # Optional historical Boeing archive – metadata only.
    if "Boeing" in feeds and os.getenv("EWS_BOEING_ARCHIVE_APPROVED") == "1":
        start, end = get_time_window_utc()

        if start and (end - start).days > 90:
            max_years = min(5, int(os.getenv("EWS_BOEING_MAX_YEARS", "2")))

            for year in range(end.year, max(start.year, end.year - max_years + 1) - 1, -1):
                if total_processed >= limit_per_feed:
                    break

                url = f'https://boeing.mediaroom.com/news-releases-statements?year={year}'

                resp = safe_http_get(url, source_id='SRC_030', timeout=12, check_robots=True)
                if resp is None or resp.status_code != 200:
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                for a in soup.select("a[href]"):
                    if total_processed >= limit_per_feed:
                        break

                    link = urljoin(resp.url, a["href"])
                    match = re.search(r"/(20\d{2}-\d{2}-\d{2})-", link)
                    title = a.get_text(" ", strip=True)

                    if (
                            not match
                            or urlparse(link).hostname != "boeing.mediaroom.com"
                            or link in COLLECTED_URLS
                            or not is_date_within_scope(match.group(1))
                            or len(title) < 15
                            or (
                            required_words
                            and not any(w in title.lower() for w in required_words)
                    )
                    ):
                        continue

                    doc = register_collected_document(
                        "SRC_030", "Official Industry PR",
                        link, title, title, match.group(1), original_query,
                    )
                    doc["origin_type"] = "PRIMARY_OFFICIAL_INDEX_METADATA"

                    extracted_text += (
                        f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_030\n"
                        f"DATE: {doc['published_at']}\n"
                        f"Title: {doc['title']}\n"
                        f"Link: {link}\n"
                        f"Summary: {doc['text']}\n---\n"
                    )
                    total_processed += 1

    logger.warning(f"[OSINT DEBUG] PR module downloaded {total_processed} releases.")
    if total_processed:
        return extracted_text
    if not accessible_feeds:
        return ("Official Industry PR: SOURCE_ACCESS_BLOCKED (access/policy restriction)"
                if blocked_feeds and not unavailable_feeds else
                "Official Industry PR: SOURCE_UNAVAILABLE (no feed successfully retrieved)")
    if parse_failures:
        return "Official Industry PR: PARTIAL_RESULT (one or more RSS feeds could not be parsed)"
    if partial_feeds:
        return "Official Industry PR: PARTIAL_RESULT (candidate limit or article access prevented full coverage)"
    return "Official Industry PR: NO_MATCH (accessible feeds searched; no applicable releases)"

# Find public aviation posts and suppress automated tracking chatter.
# Treat community posts as leads until independently corroborated.
@tool("Search Aviation Bluesky")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def search_bluesky_aviation(query: str) -> str:
    # Collect public community signals while excluding routine automated tracking.
    """Search Bluesky posts via AT Protocol and filter out automated flight tracking bots."""
    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    logger.info(f"[OSINT GATHERER] Querying Bluesky API for: '{query}' (limit: {limit})")

    handle, password = os.getenv("BLUESKY_HANDLE"), os.getenv("BLUESKY_PASSWORD")
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AeroEWS/2.0"}

    if handle and password:
        auth_resp = None
        try:
            auth_resp = requests.post(
                "https://bsky.social/xrpc/com.atproto.server.createSession",
                json={"identifier": handle, "password": password}, timeout=10,
            )
            _note_http_request("SRC_007", auth_resp.status_code)
            auth_resp.raise_for_status()
            headers["Authorization"] = f"Bearer {auth_resp.json().get('accessJwt')}"
        except Exception as e:
            if auth_resp is None and isinstance(e, requests.RequestException):
                _note_http_request("SRC_007", None, timed_out=isinstance(e, requests.Timeout))
            logger.error(f"[OSINT DEBUG] Bluesky authentication failed: {e}")
            blocked = auth_resp is not None and auth_resp.status_code in {401, 403}
            record_connector_telemetry("Bluesky Social Network", "SRC_007", query, error=str(e),
                                       operational_status="ACCESS_BLOCKED" if blocked else "TEMPORARILY_UNAVAILABLE",
                                       search_outcome="NOT_EXECUTED")
            return "Bluesky: ACCESS_BLOCKED (authentication rejected)." if blocked else "Bluesky: SOURCE_UNAVAILABLE (authentication failed)."

    params: dict[str, Any] = {
        "q": query,
        "limit": min(100, limit * 4),
        "until": end_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if start_utc is not None:
        params["since"] = start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        response = safe_http_get(
            "https://bsky.social/xrpc/app.bsky.feed.searchPosts",
            source_id="SRC_007", params=params, headers=headers, timeout=15,
        )
        if response is None or response.status_code in (401, 403):
            blocked = response is not None
            record_connector_telemetry("Bluesky Social Network", "SRC_007", query,
                                       error="ACCESS_BLOCKED" if blocked else "SOURCE_UNAVAILABLE",
                                       operational_status="ACCESS_BLOCKED" if blocked else "TEMPORARILY_UNAVAILABLE",
                                       search_outcome="RETRIEVAL_FAILED")
            return "Bluesky: ACCESS_BLOCKED (request denied)." if blocked else "Bluesky: SOURCE_UNAVAILABLE (request failed)."

        response.raise_for_status()
        posts = response.json().get("posts", []) or []
        logger.info("[BLUESKY AUDIT] HTTP=%s raw_posts=%d query=%r", response.status_code, len(posts), query)

        if not posts:
            _, short_query = parse_query_intent(query)
            fb_candidates = list(dict.fromkeys(
                q for q in (*build_social_video_queries(query), short_query)
                if q and q.casefold() != query.casefold()
            ))
            for fb_q in fb_candidates[:2]:
                fb_resp = safe_http_get(
                    "https://bsky.social/xrpc/app.bsky.feed.searchPosts",
                    source_id="SRC_007", params={**params, "q": fb_q}, headers=headers, timeout=15,
                )
                if fb_resp is not None and fb_resp.status_code == 200:
                    fb_posts = fb_resp.json().get("posts", []) or []
                    logger.info("[BLUESKY FALLBACK] q=%r raw_posts=%d", fb_q, len(fb_posts))
                    if fb_posts:
                        posts = fb_posts
                        break

        official_handles = [
            h.strip()
            for h in os.getenv("BLUESKY_OFFICIAL_HANDLES", "").split(",")
            if h.strip()
        ]

        for account in official_handles[:50]:
            resp = safe_http_get(
                "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed",
                source_id="SRC_007",
                params={"actor": account, "limit": min(limit, 100)},
            )
            if resp is not None and resp.status_code == 200:
                posts.extend(item['post'] for item in resp.json().get('feed', []) if 'post' in item)
        extracted_text = f"--- BLUESKY POSTS FOR '{query}' ---\n"
        count = rejected_scope = rejected_bots = rejected_duplicates = 0
        seen_post_texts = set()
        bot_keywords = (
            "acarsdrama", "tlsflights", "adsbexchange", "adsb.fi", "air to ground message:",
            "boeingtracker", "airbustracker", "zenithboard", "#adsb", "ferried ",
        )

        for post in posts:
            if count >= limit:
                break
            author = post.get("author", {}).get("handle", "Unknown_author")
            record = post.get("record", {})
            raw_pub_date = record.get("createdAt") or post.get("indexedAt", "DATE_UNKNOWN")

            if not is_date_within_scope(raw_pub_date):
                rejected_scope += 1
                continue

            pub_date = raw_pub_date.split("T")[0] if "T" in raw_pub_date else raw_pub_date
            uri = post.get("uri", "")
            post_url = (
                f"https://bsky.app/profile/{author}/post/{uri.split('/')[-1]}"
                if (uri and "/" in uri) else f"https://bsky.app/search?q={urllib.parse.quote(query)}"
            )
            if post_url in COLLECTED_URLS:
                rejected_duplicates += 1
                continue

            text = (record.get("text", "") or post.get("value", {}).get("text", "")).replace("\n", " ").strip()
            if any(b in f"{author} {text}".lower() for b in bot_keywords):
                rejected_bots += 1
                continue
            if is_unrelated_personal_post(text):
                rejected_scope += 1
                continue

            norm_text = re.sub(r"[^a-z0-9]", "", text.lower())[:120]
            if not norm_text or norm_text in seen_post_texts:
                rejected_duplicates += 1
                continue
            seen_post_texts.add(norm_text)

            doc_rec = register_collected_document(
                source_id="SRC_007", connector_name="Bluesky Social Network", url=post_url,
                title="Bluesky community aviation signal (pseudonymized)",
                raw_text=text, published_at=pub_date, query_used=query,
            )
            extracted_text += (
                f"\n--- BLUESKY POST ({doc_rec['doc_id']}) ---\n"
                f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_007\n"
                f"SOURCE_URL: {post_url}\n"
                f"DATE: {doc_rec['published_at']}\n"
                f"AUTHOR: [REDACTED_COMMUNITY_ACCOUNT]\n"
                f"POST TEXT: {doc_rec['text']}\n"
                f"---------------------------\n"
            )
            count += 1

        logger.info(
            "[BLUESKY FILTER AUDIT] raw=%d kept=%d out_of_scope_or_personal=%d bots=%d duplicates_or_empty=%d",
            len(posts), count, rejected_scope, rejected_bots, rejected_duplicates,
        )
        record_connector_telemetry(
            "Bluesky Social Network", "SRC_007", query, len(posts), count, rejected_scope,
            operational_status="AVAILABLE",
            search_outcome="RESULTS_RETRIEVED" if count else "NO_MATCH",
        )
        if count == 0:
            return f"No relevant Bluesky posts found for '{query}'."

        logger.warning(f"[OSINT DEBUG] Bluesky API returned {count} filtered posts.")
        return extracted_text
    except Exception as e:
        logger.error(f"[OSINT GATHERER] Bluesky fetch error: {e!s}")
        record_connector_telemetry("Bluesky Social Network", "SRC_007", query, error=str(e))
        return "Unable to connect to Bluesky server."

_AIRSHOW_IRRELEVANT_PATHS = (
    "/visit/", "/attractions/", "/beauty-n-wellness/", "/shopping/",
    "/accommodation/", "/dining/", "/restaurants/", "/ticketing/", "/hospitality-packages/",
)

# Collect airshow newsroom updates through a governed browser session.
# Bound the crawl and retain only permitted newsroom source records.
@tool("Scrape Airshow Website")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_airshow_website(query: str = "Airbus") -> str:
    # Open permitted airshow sites and traverse bounded newsroom pages.
    """Crawl airshow newsrooms using Playwright and extract relevant article paragraphs."""
    if not is_source_allowed("SRC_006"):
        return "Airshow scraper is disabled by source compliance policy."

    safe_query = query.replace(",", "").replace("  ", " ").strip()
    required_words, specific_search_term = parse_query_intent(safe_query)
    encoded_query = quote_plus(specific_search_term)
    user_limit = get_dynamic_limit()
    scope_days = get_scope_days()
    fast_mode = os.getenv("EWS_AIRSHOW_FAST_MODE", "1") == "1"

    logger.info(
        f"[OSINT GATHERER] Starting airshow scraper for '{safe_query}' "
        f"(required words: {required_words}, max articles: {user_limit}, scope: {scope_days or 'all'} days)"
    )

    extracted_text = f"--- AIRSHOW WEBSITE SCRAPING FOR '{safe_query}' ---\n"
    processed_shows = total_articles = rejected_scope = unknown_dates = 0

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1920, "height": 1080},
            )
            page = context.new_page()
            page.route(
                "**/*",
                lambda route: route.abort()
                if (route.request.resource_type in ("image", "media",
                                                    "font") or "cookiebot.com" in route.request.url.lower())
                else route.continue_(),
            )

            effective_max_pages = min(12, max(MAX_PAGES_PER_AIRSHOW, (user_limit + 4) // 5))

            for airshow_name, url in AIRSHOW_NEWS_URLS.items():
                if total_articles >= user_limit:
                    break

                allowed, reason = check_robots_and_tdm_compliance(url, source_id="SRC_006")
                if not allowed:
                    logger.info(f"[COMPLIANCE] Skipping {airshow_name}: {reason}")
                    continue

                try:
                    RATE_LIMITER.wait_for_slot("SRC_006")
                    logger.info(f"[OSINT DEBUG] Scraping airshow: {airshow_name} ({url})")

                    if "farnboroughairshow.com" in url:
                        urls_to_check = [f"https://www.farnboroughairshow.com/search?search={encoded_query}"] + [
                            f"https://www.farnboroughairshow.com/umbraco/surface/blog/GetBlog?ViewId=1157&category=ALL&viewName=Blog/LoadBlogs&pageNo={p_no}"
                            for p_no in range(1, effective_max_pages + 1)
                        ]
                    elif "siae.fr" in url:
                        urls_to_check = [url]
                    elif "singaporeairshow.com" in url:
                        # Official newsroom contains dated articles directly.
                        urls_to_check = [url]
                    else:
                        urls_to_check = [url]

                    all_raw_texts, candidate_links, visited_listing_urls = [], [], set()
                    idx = 0
                    # Limit crawl depth and track visited listing pages to prevent repeated traversal.
                    while idx < len(urls_to_check) and len(visited_listing_urls) < (effective_max_pages + 1):
                        target_url = urls_to_check[idx]
                        idx += 1

                        if target_url in visited_listing_urls:
                            continue

                        allowed_page, reason_page = check_robots_and_tdm_compliance(
                            target_url,
                            source_id="SRC_006",
                        )

                        if not allowed_page:
                            logger.info(
                                "[AIRSHOW] Listing page skipped: %s (%s)",
                                target_url,
                                reason_page,
                            )
                            continue

                        visited_listing_urls.add(target_url)

                        try:
                            page.goto(target_url, timeout=12000 if fast_mode else 25000, wait_until="domcontentloaded")
                            page.wait_for_timeout(300 if fast_mode else 2000)

                            soup = BeautifulSoup(page.content(), "html.parser")
                            clean_text, links, next_page_urls = extract_clean_blocks(soup, target_url)

                            if "GetBlog" in target_url and not links:
                                break
                            if clean_text:
                                all_raw_texts.append(clean_text)

                            for np_url in next_page_urls:
                                if np_url not in visited_listing_urls and np_url not in urls_to_check:
                                    urls_to_check.append(np_url)

                            for link in links:
                                full_link_url = link["url"]
                                if (
                                        any(path in full_link_url.lower() for path in _AIRSHOW_IRRELEVANT_PATHS)
                                        or IRRELEVANT_URL_REGEX.search(full_link_url)
                                        or IRRELEVANT_TEXT_REGEX.search(link["context"])
                                ):
                                    continue
                                candidate_links.append(link)
                        except Exception as inner_e:
                            logger.debug(f"Subpage {target_url} skipped: {inner_e}")

                    # Prefer the newest explicitly dated newsroom candidates.
                    # Unknown dates remain at the end.
                    candidate_links.sort(key=lambda item: item.get('date') or '', reverse=True)

                    filter_relevant_paragraphs("\n".join(all_raw_texts), required_words)
                    link_date_map = {l["url"]: l.get("date", "") for l in candidate_links if l.get("date")}
                    num_words = [rw for rw in required_words if any(c.isdigit() for c in rw)]
                    tier1_links, tier2_links, tier3_links = [], [], []
                    min_req = min(2, len(required_words))

                    for l in candidate_links:
                        t_text = f"{l['title']} {l['url']}".lower()
                        c_text = l["context"].lower()
                        if any(nw in t_text for nw in num_words) or sum(
                                1 for rw in required_words if rw in t_text) >= min_req:
                            tier1_links.append(l["url"])
                        elif any(nw in c_text for nw in num_words) or sum(
                                1 for rw in required_words if rw in c_text) >= min_req:
                            tier2_links.append(l["url"])
                        elif any(rk in c_text or rk in l["url"].lower() for rk in AIRSHOW_ROUNDUP_KEYWORDS):
                            tier3_links.append(l["url"])

                    remaining_slots = max(1, user_limit - total_articles)
                    if num_words or (scope_days is not None and scope_days <= 14):
                        links_to_open = list(dict.fromkeys(tier1_links + tier2_links))[:remaining_slots]
                    else:
                        links_to_open = list(dict.fromkeys(tier1_links + tier2_links + tier3_links))[
                                        :(remaining_slots + 2)]

                    deep_articles_output, seen_article_bodies = [], set()

                    for article_url in links_to_open:
                        if total_articles >= user_limit:
                            break
                        if article_url in COLLECTED_URLS:
                            continue

                        pre_date = link_date_map.get(article_url, "") or normalize_date_str(article_url)
                        # Skip articles outside the requested monitoring horizon before loading their
                        #   body.
                        if scope_days is not None and pre_date and not is_date_within_scope(pre_date):
                            rejected_scope += 1
                            continue

                        article_allowed, article_reason = check_robots_and_tdm_compliance(
                            article_url,
                            source_id="SRC_006",
                        )
                        if not article_allowed:
                            logger.info(
                                "[AIRSHOW COMPLIANCE] Skipping %s: %s",
                                article_url,
                                article_reason,
                            )
                            continue

                        # Inspect individual article pages only after scope and URL checks.
                        try:
                            logger.info(f"[OSINT DEBUG] -> Opening article: {article_url}")
                            page.goto(article_url, timeout=12000 if fast_mode else 20000, wait_until="domcontentloaded")
                            page.wait_for_timeout(300 if fast_mode else 1200)

                            raw_html = page.content()
                            art_text, _, _ = extract_clean_blocks(BeautifulSoup(raw_html, "html.parser"), article_url)
                            art_filtered = filter_relevant_paragraphs(art_text, required_words)

                            body_hash = re.sub(r"[^a-z0-9]", "", art_filtered.lower())[:300]
                            if len(art_filtered) >= 120 and body_hash not in seen_article_bodies:
                                pub_date = extract_article_date(
                                    raw_html, clean_article_text=art_text, url=article_url,
                                    fallback_date=link_date_map.get(article_url, ""),
                                )
                                if pub_date == "DATE_UNKNOWN":
                                    unknown_dates += 1
                                if not is_date_within_scope(pub_date):
                                    rejected_scope += 1
                                    logger.info(
                                        f"[OSINT DEBUG] Article {article_url} ({pub_date}) skipped (outside time scope).")
                                    continue

                                seen_article_bodies.add(body_hash)

                                article_soup = BeautifulSoup(raw_html, "html.parser")

                                headline_tag = (
                                        article_soup.find("meta", property="og:title")
                                        or article_soup.find("h1")
                                )

                                if headline_tag is not None:
                                    if headline_tag.name == "meta":
                                        headline = headline_tag.get("content", "")
                                    else:
                                        headline = headline_tag.get_text(" ", strip=True)
                                else:
                                    headline = ""

                                doc_rec = register_collected_document(
                                    source_id="SRC_006", connector_name="Airshow Websites", url=article_url,
                                    title=headline[:220] or f"{airshow_name} Newsroom Article",
                                    raw_text=art_filtered,
                                    published_at=pub_date, query_used=safe_query,
                                )
                                deep_articles_output.append(
                                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_006\n"
                                    f"DATE: {doc_rec['published_at']}\nLink: {article_url}\nArticle Content:\n{doc_rec['text'][:1500]}"
                                )
                                total_articles += 1
                        except Exception as art_e:
                            logger.debug(f"Could not load article {article_url}: {art_e}")

                    final_airshow_sections = list(deep_articles_output)

                    if final_airshow_sections:
                        extracted_text += f"\n>> News from {airshow_name} ({url}):\n" + "\n\n".join(
                            final_airshow_sections) + "\n---\n"
                        processed_shows += 1
                    else:
                        extracted_text += f"\n>> {airshow_name} ({url}): No articles found for '{safe_query}' within the selected time scope.\n---\n"

                except Exception as e:
                    logger.error(f"[OSINT GATHERER] Error scraping {airshow_name}: {e}")
                    extracted_text += f"\n>> {airshow_name} ({url}): Failed to load content ({e!s})\n---\n"

            browser.close()

    except Exception as e:
        logger.error(f"[OSINT GATHERER] Playwright error: {e}")
        record_connector_telemetry("Airshow Websites", "SRC_006", safe_query, error=str(e))
        return f"Fatal browser launch error: {e}"

    record_connector_telemetry(
        "Airshow Websites", "SRC_006", safe_query, total_articles + rejected_scope, total_articles, rejected_scope,
        unknown_dates,
        operational_status="AVAILABLE",
        search_outcome="RESULTS_RETRIEVED" if total_articles else "NO_MATCH",
    )
    if processed_shows == 0:
        return f"No information found for '{safe_query}' on any monitored airshow websites within the selected time scope."

    logger.warning(
        f"[OSINT DEBUG] Extracted {total_articles} articles across {processed_shows} airshows (limit: {user_limit}).")
    return extracted_text

YOUTUBE_CACHE_FILE = "youtube_transcript_cache.json"
_YT_CACHE_LOCK = threading.Lock()

# Read a cached transcript to avoid repeated remote retrieval.
def _load_yt_transcript_cache() -> dict[str, str]:
    if not os.path.exists(YOUTUBE_CACHE_FILE):
        return {}
    try:
        with _YT_CACHE_LOCK, open(YOUTUBE_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

# Persist an acquired transcript for reuse by later scans.
def _save_yt_transcript_cache(video_id: str, transcript: str) -> None:
    if not video_id or not transcript or len(transcript) < 60:
        return
    cache = _load_yt_transcript_cache()
    cache[video_id] = transcript
    try:
        with _YT_CACHE_LOCK, open(YOUTUBE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.debug(f"[YT CACHE] Could not write transcript cache: {e}")

# Collect KIT-related videos and recover usable text from transcripts.
# A transcript supports what was said, not independent truth of the claim.
@tool("Search and Extract YouTube")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def extract_youtube_transcript(query: str) -> str:
    # Prefer cached source transcripts and conserve external transcript/model requests.
    """Search YouTube for aviation videos, pre-filter by KIT relevance, and use local transcript caching before Gemini."""
    if not YOUTUBE_API_KEY:
        record_connector_telemetry("YouTube Videos", "SRC_008", query, error="MISSING_YOUTUBE_API_KEY",
                                   operational_status="MISCONFIGURED", search_outcome="NOT_EXECUTED",
                                   diagnostics={"zero_result_reason": "MISSING_API_KEY"})
        return "YouTube: MISCONFIGURED (YOUTUBE_API_KEY is missing)."

    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    required_words, _ = parse_query_intent(query)
    num_model_words = [rw for rw in required_words if any(c.isdigit() for c in rw)]

    logger.info(f"[OSINT GATHERER] Querying YouTube Data API v3 for: '{query}' (limit: {limit})")

    short_yt_queries = build_social_video_queries(query)
    primary_yt_q = short_yt_queries[0] if (len(query.split()) > 5 and short_yt_queries) else query
    search_params: dict[str, Any] = {
        "part": "snippet",
        "q": f"{primary_yt_q} -shorts -compilation -landing -takeoff -flightsimulator -msfs",
        "type": "video",
        "maxResults": min(20, limit * 3),
        "relevanceLanguage": "en",
        "key": YOUTUBE_API_KEY,
        "publishedBefore": end_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if start_utc is not None:
        search_params["publishedAfter"] = start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    diagnostics: dict[str, Any] = {"search_query": search_params["q"], "http_status": None,
                                   "api_error_reason": "", "api_items_returned": 0,
                                   "candidates_accepted": 0, "zero_result_reason": ""}

    def audit(found: int = 0, accepted: int = 0, rejected: int = 0, *,
              state: str = "AVAILABLE", outcome: str = "RESULTS_RETRIEVED", error: str = "") -> None:
        if accepted == 0 and not diagnostics["zero_result_reason"]:
            diagnostics["zero_result_reason"] = outcome
        record_connector_telemetry("YouTube Videos", "SRC_008", query, found, accepted, rejected,
                                   operational_status=state, search_outcome=outcome, error=error or None,
                                   diagnostics=diagnostics)

    try:
        http = _safe_http_request("https://www.googleapis.com/youtube/v3/search", "SRC_008",
                                  params=search_params, timeout=10, max_bytes=400_000)
        diagnostics["http_status"] = http.status_code
        search_resp = http.response
        if http.status_code != 200 or not http.response_complete or search_resp is None:
            reason = http.error_type or "HTTP_ERROR"
            if search_resp is not None and http.status_code and http.status_code >= 400:
                try:
                    api_error = search_resp.json().get("error", {})
                    reason = next((e.get("reason", "") for e in api_error.get("errors", [])
                                   if isinstance(e, dict) and e.get("reason")), reason)
                except (ValueError, AttributeError, TypeError):
                    pass
            diagnostics["api_error_reason"] = reason
            state = ("RATE_LIMITED" if http.status_code == 429 or reason in {
                "quotaExceeded", "rateLimitExceeded", "userRateLimitExceeded"
            } else "ACCESS_BLOCKED" if http.status_code in {401, 403} or reason in {
                "SOURCE_POLICY_BLOCKED", "ROBOTS_OR_TDM_BLOCKED", "RESPONSE_TDM_BLOCKED", "HTML_TDM_BLOCKED"
            } else "TEMPORARILY_UNAVAILABLE" if http.status_code and http.status_code >= 500
                    else "TECHNICAL_ERROR")
            diagnostics["zero_result_reason"] = state
            audit(state=state, outcome="RETRIEVAL_FAILED", error=reason)
            return f"YouTube: {state} (search failed: {reason})."

        payload = search_resp.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise ValueError("INVALID_YOUTUBE_RESPONSE_SCHEMA")
        items = payload["items"]
        if not items:
            for fb_q in short_yt_queries:
                if fb_q.casefold() == primary_yt_q.casefold():
                    continue
                fb_params = {**search_params, "q": f"{fb_q} -shorts -compilation -flightsimulator -msfs"}
                fb_http = _safe_http_request(
                    "https://www.googleapis.com/youtube/v3/search", "SRC_008",
                    params=fb_params, timeout=10, max_bytes=400_000,
                )
                if fb_http.status_code == 200 and fb_http.response_complete and fb_http.response is not None:
                    fb_payload = fb_http.response.json()
                    if isinstance(fb_payload, dict) and fb_payload.get("items"):
                        payload = fb_payload
                        items = fb_payload["items"]
                        diagnostics["search_query"] = fb_params["q"]
                        break
        diagnostics.update(api_response_status="OK", api_items_returned=len(items),
                           api_total_results=(payload.get("pageInfo") or {}).get("totalResults"),
                           has_next_page=bool(payload.get("nextPageToken")))

        videos, rejected_scope, duplicates, malformed = [], 0, 0, 0
        yt_noise = ("#shorts", "compilation", "1:200", "1:400", "scale model", "msfs", "flight simulator",
                    "trip report")

        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("id"), dict) or not isinstance(item.get("snippet"), dict):
                malformed += 1
                continue
            vid_id = item["id"].get("videoId")
            snippet = item["snippet"]
            if (not isinstance(vid_id, str) or not isinstance(snippet.get("title"), str)
                    or not isinstance(snippet.get("publishedAt"), str)
                    or not snippet["title"] or not snippet["publishedAt"]):
                malformed += 1
                continue
            vid_url = f"https://www.youtube.com/watch?v={vid_id}"
            if vid_url in COLLECTED_URLS:
                duplicates += 1
                continue

            title = html.unescape(snippet["title"])
            desc = html.unescape(snippet.get("description") or "")
            combined_meta_low = f"{title} {desc}".lower()

            if (
                    any(noise in combined_meta_low for noise in yt_noise)
                    or (num_model_words and not any(mw.lower() in combined_meta_low for mw in num_model_words))
                    or not is_date_within_scope(snippet["publishedAt"])
            ):
                rejected_scope += 1
                continue

            raw_date = snippet["publishedAt"]
            videos.append({
                "id": vid_id,
                "title": title,
                "channel": snippet.get("channelTitle", ""),
                "desc": desc,
                "date": raw_date.split("T")[0] if "T" in raw_date else raw_date,
                "url": vid_url,
            })
            if len(videos) >= limit:
                break

        diagnostics.update(candidates_accepted=len(videos), duplicates=duplicates,
                           malformed_items=malformed, rejected_out_of_scope=rejected_scope)
        if not videos:
            reason = ("NO_RESULTS" if not items else "ALREADY_COLLECTED" if duplicates == len(items)
                      else "MALFORMED_ITEMS" if malformed == len(items) else "NO_RELEVANT_MATCH")
            diagnostics["zero_result_reason"] = reason
            audit(len(items), rejected=rejected_scope, outcome="NO_MATCH" if reason != "MALFORMED_ITEMS"
                  else "RETRIEVAL_FAILED", state="TECHNICAL_ERROR" if reason == "MALFORMED_ITEMS" else "AVAILABLE")
            return f"YouTube: {reason} (API returned {len(items)} candidates; 0 accepted)."

        if os.getenv("EWS_YOUTUBE_TRANSCRIPTS_APPROVED", "0") != "1":
            results = []

            for v in videos:
                doc = register_collected_document(
                    source_id="SRC_008",
                    connector_name="YouTube Metadata",
                    url=v["url"],
                    title=f"{v['title']} ({v['channel']})",
                    raw_text=v["desc"] or v["title"],
                    published_at=v["date"],
                    query_used=query,
                )

                doc["content_status"] = "METADATA_ONLY"
                results.append(
                    f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_008\n"
                    f"DATE: {doc['published_at']}\n"
                    f"Title: {doc['title']}\n"
                    f"Link: {v['url']}\n"
                    f"Summary: {doc['text']}\n---"
                )

            audit(len(items), len(results), rejected_scope)
            return "\n".join(results)

        extracted_text = f"--- RAW VIDEO TRANSCRIPTS FOR '{query}' ---\n"
        processed_videos = gemini_calls_made = 0
        max_gemini_transcriptions = 2
        # Read persistent transcript cache before invoking external transcript and analysis providers.
        yt_cache = _load_yt_transcript_cache()
        client = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options=types.HttpOptions(timeout=30_000, retry_options=types.HttpRetryOptions(attempts=1)),
        ) if GEMINI_API_KEY else None
        transcript_prompt = (
            "Return ONLY the exact, verbatim transcript of the spoken words in this video. "
            "Do NOT summarize, do NOT analyze, do NOT add introductory or concluding remarks. "
            "I only want the raw text of what is being said."
        )

        for v in videos:
            transcript_text = ""
            used_gemini_fallback = False

            if v["id"] in yt_cache:
                transcript_text = yt_cache[v["id"]]
                logger.info(f"[OSINT GATHERER] Loaded cached transcript for YouTube video {v['id']}.")
            else:
                try:
                    api = YouTubeTranscriptApi()
                    ts_segments = (
                        api.fetch(v["id"], languages=["en", "en-US", "en-GB"]).to_raw_data()
                        if hasattr(api, "fetch")
                        else YouTubeTranscriptApi.get_transcript(v["id"], languages=["en", "en-US", "en-GB"])
                    )
                    transcript_text = re.sub(r"\s+", " ", " ".join(seg.get("text", "") for seg in ts_segments)).strip()
                    _save_yt_transcript_cache(v["id"], transcript_text)
                    logger.info(f"[OSINT GATHERER] Fast transcript fetched via YouTubeTranscriptApi for {v['id']}.")
                except Exception as yt_err:
                    if client is None or gemini_calls_made >= max_gemini_transcriptions:
                        logger.info(
                            f"[OSINT GATHERER] Skipping slow Gemini audio transcription for {v['id']} (budget {max_gemini_transcriptions} reached).")
                        continue
                    logger.debug(f"YouTubeTranscriptApi failed for {v['id']} ({yt_err}), falling back to Gemini.")
                    used_gemini_fallback = True
                    gemini_calls_made += 1
                    try:
                        response = client.models.generate_content(
                            model=os.getenv("EWS_YOUTUBE_GEMINI_MODEL", "gemini-2.5-flash-lite").strip(),
                            contents=types.Content(
                                parts=[
                                    types.Part(file_data=types.FileData(file_uri=v["url"])),
                                    types.Part(text=transcript_prompt),
                                ]
                            ),
                        )
                        if response.text:
                            transcript_text = response.text.replace("\n", " ")
                            _save_yt_transcript_cache(v["id"], transcript_text)
                        else:
                            transcript_text = f"(No transcript returned by Gemini. Video description used): {v['desc']}"
                    except Exception as e:
                        logger.warning(f"Gemini API rate limit or error on video {v['id']}: {str(e)[:50]}")
                        transcript_text = f"(Transcript unavailable. Video description used): {v['desc']}" if v[
                            "desc"] else ""

            if "♪" in transcript_text or len(transcript_text.strip()) < 60:
                if used_gemini_fallback:
                    time.sleep(1)
                continue

            doc_rec = register_collected_document(
                source_id="SRC_008", connector_name="YouTube Videos", url=v["url"],
                title=f"{v['title']} ({v['channel']})", raw_text=transcript_text,
                published_at=v["date"], query_used=query,
            )
            doc_rec["content_status"] = "TRANSCRIPT_AS_RECEIVED" if not used_gemini_fallback else "TEXT_COMPLETENESS_UNVERIFIED"
            extracted_text += (
                f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_008\n"
                f"DATE: {doc_rec['published_at']}\nTitle: {v['title']}\nChannel: {v['channel']}\n"
                f"Link: {v['url']}\nVideo Transcript: {doc_rec['text'][:1500]}\n---\n"
            )
            processed_videos += 1

            if used_gemini_fallback:
                time.sleep(2)

        diagnostics.update(transcripts_accepted=processed_videos, gemini_attempts=gemini_calls_made)
        if not processed_videos:
            diagnostics["zero_result_reason"] = "NO_USABLE_TRANSCRIPT"
        audit(len(items), processed_videos, rejected_scope,
              outcome="RESULTS_RETRIEVED" if processed_videos else "NO_USABLE_TRANSCRIPT")
        logger.info(f"[OSINT GATHERER] YouTube processing completed for {processed_videos} videos.")
        return extracted_text

    except Exception as e:
        logger.error("[OSINT GATHERER] YouTube processing error: %s", type(e).__name__)
        diagnostics["zero_result_reason"] = "TECHNICAL_ERROR"
        audit(state="TECHNICAL_ERROR", outcome="RETRIEVAL_FAILED", error=type(e).__name__)
        return "YouTube: TECHNICAL_ERROR (search or response processing failed)."