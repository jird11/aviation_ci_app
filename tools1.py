# OSINT connectors and collection controls for aerospace monitoring.
# Source governance, date normalization, retrieval safety, and provenance are centralized here.


import csv
import io
import zipfile
import email.utils
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.robotparser
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
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

NEWS_API_KEY = os.getenv("NEWS_API_KEY")
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")




# Supported UTC lookback periods for collection and historical simulation.
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


# Normalize user-facing time-window labels to a stable internal enumeration.
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




# Recorded access-governance status; this metadata is not a legal-compliance guarantee.
class SourceLegalStatus(str, Enum):
    ALLOWED = "ALLOWED"
    RESTRICTED = "RESTRICTED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    DISABLED = "DISABLED"


_SRC_DEFAULTS = {
    "last_legal_review_date": "2026-10-15",
    "tdm_opt_out": False,
    "last_success_at": None,
    "success_count": 0,
    "failure_count": 0,
}

SOURCE_REGISTRY: Dict[str, Dict[str, Any]] = {
    k: {**_SRC_DEFAULTS, "source_id": k, **v}
    for k, v in {
        "SRC_001": {
            "name": "FAA Federal Register",
            "domain": "federalregister.gov",
            "source_type": "REGULATORY",
            "origin": "PRIMARY",
            "access_method": "API",
            "allowed_access_method": "API (Official REST Endpoint)",
            "tos_url": "https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/developer-resources",
            "usage_restrictions": "Public domain (17 U.S.C. 105); unrestricted retention, processing, and internal/external redistribution.",
            "tdm_copyright_basis": "Public Domain (No copyright / TDM restrictions)",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (official regulatory records; minimal personal data)",
            "verified_domain": True,
            "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "US Government Public Domain / Federal Register API",
            "rate_limit_rpm": 30,
            "min_interval_sec": 1.0,
        },
        "SRC_002": {
            "name": "EASA Safety & Regulatory Monitor (via RSS Proxy)",
            "domain": "easa.europa.eu",
            "technical_host": "news.google.com",
            "source_type": "REGULATORY",
            "origin": "PRIMARY_VIA_AGGREGATOR",
            "access_method": "RSS",
            "allowed_access_method": "RSS (Metadata & Short Snippets Only)",
            "tos_url": "https://www.easa.europa.eu/en/legal-notice",
            "usage_restrictions": "Store metadata, headlines, and short excerpts only; attribute EASA; no commercial redistribution of full texts.",
            "tdm_copyright_basis": "EU Directive 2019/790 Art. 3/4 TDM & EASA Legal Notice",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (institutional safety notices)",
            "verified_domain": True,
            "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "Metadata & public safety notices via RSS search index",
            "rate_limit_rpm": 20,
            "min_interval_sec": 1.5,
        },
        "SRC_003": {
            "name": "NTSB Aviation Investigation Monitor (via RSS Proxy)",
            "domain": "ntsb.gov",
            "technical_host": "news.google.com",
            "source_type": "REGULATORY",
            "origin": "PRIMARY_VIA_AGGREGATOR",
            "access_method": "RSS",
            "allowed_access_method": "RSS (Metadata & Short Snippets Only)",
            "tos_url": "https://www.ntsb.gov/Pages/policies.aspx",
            "usage_restrictions": "US Government public safety notices; retain metadata and short summaries; cite original NTSB link.",
            "tdm_copyright_basis": "Public Domain (US Federal Agency) / RSS Aggregation",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (exclude victim/crew private PII)",
            "verified_domain": True,
            "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "Public safety investigation notices",
            "rate_limit_rpm": 20,
            "min_interval_sec": 1.5,
        },
        "SRC_004": {
            "name": "News API Global Media",
            "domain": "newsapi.org",
            "source_type": "MEDIA_AGGREGATOR",
            "origin": "SECONDARY",
            "access_method": "API",
            "allowed_access_method": "API + Approved robots.txt/TDM-compliant Snippet Extraction",
            "tos_url": "https://newsapi.org/terms",
            "usage_restrictions": "Internal academic/CI analysis only; store short verbatim quotes (<450 chars) & URLs; no full-article republication.",
            "tdm_copyright_basis": "NewsAPI ToS + EU Directive 2019/790 Art. 4 (subject to publisher TDM-Reservation opt-out)",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (redact reporter/contact PII)",
            "verified_domain": True,
            "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "NewsAPI Developer/Academic Terms - snippet & link indexing",
            "rate_limit_rpm": 20,
            "min_interval_sec": 1.5,
        },
        "SRC_005": {
            "name": "OEM Official Press Releases (Airbus, Boeing, COMAC)",
            "domain": "airbus.com,boeing.mediaroom.com,comac.cc",
            "technical_host": "news.google.com",
            "source_type": "OEM_PR",
            "origin": "PRIMARY_VIA_AGGREGATOR",
            "access_method": "RSS",
            "allowed_access_method": "RSS (Public Corporate Press Releases)",
            "tos_url": "https://www.airbus.com/en/terms-of-use",
            "usage_restrictions": "Public investor/media releases; retain title, link, and short summary for internal CI monitoring.",
            "tdm_copyright_basis": "Corporate PR Public Press License / EU Directive 2019/790 Art. 4",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (corporate spokespersons only; contact PII redacted)",
            "verified_domain": True,
            "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "Public corporate press releases",
            "rate_limit_rpm": 20,
            "min_interval_sec": 1.5,
        },
        "SRC_006": {
            "name": "International Airshow Newsrooms",
            "domain": "farnboroughairshow.com,siae.fr,dubaiairshow.aero,singaporeairshow.com",
            "source_type": "INDUSTRY_EVENT",
            "origin": "PRIMARY",
            "access_method": "PLAYWRIGHT_CRAWLER",
            "allowed_access_method": "Approved Scraping (Strict robots.txt & TDM-Reservation check mandatory)",
            "tos_url": "https://www.farnboroughairshow.com/terms-and-conditions/",
            "usage_restrictions": "RESTRICTED: Suspend immediately if robots.txt is unreachable or disallows crawling; retain short excerpts only; no redistribution.",
            "tdm_copyright_basis": "EU Directive 2019/790 Art. 4 TDM (Strictly conditional on absence of machine-readable opt-out)",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (B2B event press releases; personal career/HR posts filtered out)",
            "verified_domain": True,
            "legal_status": SourceLegalStatus.RESTRICTED.value,
            "license_notes": "Respect robots.txt and rate limits; short excerpts only",
            "rate_limit_rpm": 12,
            "min_interval_sec": 2.5,
        },
        "SRC_007": {
            "name": "Bluesky AT Protocol Aviation Feed",
            "domain": "bsky.app",
            "source_type": "COMMUNITY_SOCIAL",
            "origin": "SECONDARY_UNVERIFIED",
            "access_method": "API",
            "allowed_access_method": "API (Official AT Protocol Public Search)",
            "tos_url": "https://bsky.social/about/support/tos",
            "usage_restrictions": "Exclude private/personal posts unrelated to aerospace; anonymize author handles; internal weak-signal verification only.",
            "tdm_copyright_basis": "AT Protocol Developer Terms",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest with strict Data Minimization (personal non-aerospace posts dropped; handles pseudonymized)",
            "verified_domain": False,
            "legal_status": SourceLegalStatus.RESTRICTED.value,
            "license_notes": "AT Protocol public search API",
            "rate_limit_rpm": 20,
            "min_interval_sec": 1.5,
        },
        "SRC_008": {
            "name": "YouTube Data API v3 & Transcripts",
            "domain": "youtube.com",
            "source_type": "VIDEO_MEDIA",
            "origin": "SECONDARY_UNVERIFIED",
            "access_method": "API",
            "allowed_access_method": "API (YouTube Data API v3)",
            "tos_url": "https://developers.google.com/youtube/terms/api-services-terms-of-service",
            "usage_restrictions": "Temporary analytical processing of spoken B2B/aviation news transcripts; no redistribution of full transcripts; exclude personal vlogs.",
            "tdm_copyright_basis": "YouTube API Services Terms of Service",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (public B2B media channels only; personal hobbyist vlogs rejected)",
            "verified_domain": False,
            "legal_status": SourceLegalStatus.RESTRICTED.value,
            "license_notes": "YouTube Data API v3 Terms of Service",
            "rate_limit_rpm": 10,
            "min_interval_sec": 2.0,
        },
    }.items()
}



SOURCE_REGISTRY["SRC_009"] = {
    **_SRC_DEFAULTS,
    "source_id": "SRC_009",
    "name": "Aerospace Supplier Press Releases",
    "domain": (
        "rtx.com,cfmaeroengines.com,"
        "geaerospace.com,safran-group.com"
    ),
    "technical_host": "news.google.com",
    "source_type": "SUPPLIER_PR",
    "origin": "PRIMARY_VIA_AGGREGATOR",
    "access_method": "RSS",
    "allowed_access_method": "Public RSS metadata",
    "tos_url": "",
    "usage_restrictions": (
        "Store headlines, URLs and short excerpts only. "
        "Respect source-specific access restrictions."
    ),
    "tdm_copyright_basis": "Subject to source-specific review",
    "gdpr_legal_basis": "Subject to lawful-basis assessment",
    "verified_domain": False,
    "legal_status": SourceLegalStatus.RESTRICTED.value,
    "license_notes": "Supplier news metadata via Google News RSS",
    "rate_limit_rpm": 12,
    "min_interval_sec": 2.0,
}

# Aerospace manufacturers, suppliers, and their production relationships.

AEROSPACE_SUPPLIER_REGISTRY: List[Dict[str, Any]] = [
    {
        "entity_id": "ENT_AIRBUS", "official_name": "Airbus SE",
        "aliases": ["airbus", "airbus commercial"], "default_tier": "OEM (Final Assembler)",
        "components": ["Final Aircraft Assembly", "Wing Design"],
        "programs": ["A320neo", "A321XLR", "A350", "A220", "A330neo"],
        "downstream_oems": ["Airbus SE"], "geography": "Europe (EU)",
        "source_ref": "Airbus Annual Report / Official Registry",
    },
    {
        "entity_id": "ENT_BOEING", "official_name": "The Boeing Company",
        "aliases": ["boeing", "boeing commercial airplanes"], "default_tier": "OEM (Final Assembler)",
        "components": ["Final Aircraft Assembly"],
        "programs": ["737 MAX", "777X", "787 Dreamliner", "767"],
        "downstream_oems": ["The Boeing Company"], "geography": "North America (USA)",
        "source_ref": "Boeing SEC Form 10-K",
    },
    {
        "entity_id": "ENT_COMAC", "official_name": "COMAC",
        "aliases": ["comac", "commercial aircraft corporation of china"], "default_tier": "OEM (Final Assembler)",
        "components": ["Final Aircraft Assembly"], "programs": ["C919", "C909", "ARJ21"],
        "downstream_oems": ["COMAC"], "geography": "Asia-Pacific (China)",
        "source_ref": "COMAC Official Directory",
    },
    {
        "entity_id": "ENT_PW", "official_name": "Pratt & Whitney (RTX)",
        "aliases": ["pratt & whitney", "pratt", "rtx", "pw1100g", "gtf"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["PW1100G-JM GTF Turbofan Engine", "PW1500G Engine"],
        "programs": ["A320neo", "A321XLR", "A220", "Embraer E2"],
        "downstream_oems": ["Airbus SE", "Embraer"], "geography": "North America (USA)",
        "source_ref": "RTX / Airbus A320neo Family Supplier Registry",
    },
    {
        "entity_id": "ENT_CFM", "official_name": "CFM International (GE / Safran)",
        "aliases": ["cfm", "cfm international", "leap-1a", "leap-1b", "leap-1c"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["LEAP-1A Engine", "LEAP-1B Engine", "LEAP-1C Engine"],
        "programs": ["A320neo", "A321XLR", "737 MAX", "C919"],
        "downstream_oems": ["Airbus SE", "The Boeing Company", "COMAC"],
        "geography": "North America (USA) / Europe (EU)",
        "source_ref": "CFM International Joint Venture Registry",
    },
    {
        "entity_id": "ENT_SAFRAN", "official_name": "Safran S.A.",
        "aliases": ["safran", "safran landing systems", "safran seats"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["LEAP Engine Modules", "Landing Gear", "Nacelles", "Cabin Interiors"],
        "programs": ["A320neo", "A321XLR", "A350", "737 MAX", "787 Dreamliner"],
        "downstream_oems": ["Airbus SE", "The Boeing Company"], "geography": "Europe (EU)",
        "source_ref": "Safran Universal Registration Document",
    },
    {
        "entity_id": "ENT_GE", "official_name": "GE Aerospace",
        "aliases": ["ge aerospace", "general electric", "ge9x", "genx"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["GE9X Engine", "GEnx Engine", "LEAP Core"],
        "programs": ["777X", "787 Dreamliner", "A320neo", "737 MAX"],
        "downstream_oems": ["The Boeing Company", "Airbus SE"], "geography": "North America (USA)",
        "source_ref": "GE Aerospace Supplier Filings",
    },
    {
        "entity_id": "ENT_RR", "official_name": "Rolls-Royce Holdings",
        "aliases": ["rolls-royce", "trent xwb", "trent 7000"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["Trent XWB-84/97 Engine", "Trent 7000 Engine"],
        "programs": ["A350", "A330neo"], "downstream_oems": ["Airbus SE"], "geography": "Europe (UK)",
        "source_ref": "Rolls-Royce Civil Aerospace Disclosures",
    },
    {
        "entity_id": "ENT_SPIRIT", "official_name": "Spirit AeroSystems",
        "aliases": ["spirit aerosystems", "spirit"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["737 Fuselage", "A350 Center Fuselage Section", "A220 Pylons/Wings"],
        "programs": ["737 MAX", "787 Dreamliner", "A350", "A220"],
        "downstream_oems": ["The Boeing Company", "Airbus SE"], "geography": "North America (USA)",
        "source_ref": "Spirit AeroSystems 10-K",
    },
    {
        "entity_id": "ENT_COLLINS", "official_name": "Collins Aerospace",
        "aliases": ["collins aerospace", "collins"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["Avionics", "Nacelles", "Actuation Systems"],
        "programs": ["A320neo", "A321XLR", "737 MAX", "787 Dreamliner"],
        "downstream_oems": ["Airbus SE", "The Boeing Company"], "geography": "North America (USA)",
        "source_ref": "RTX / Collins Aerospace Product Catalog",
    },
    {
        "entity_id": "ENT_VSMPO", "official_name": "VSMPO-AVISMA / Titanium Suppliers",
        "aliases": ["vsmpo", "titanium", "toho titanium", "howmet"], "default_tier": "Tier 3 (Raw Materials)",
        "components": ["Aerospace-grade Titanium Forgings", "Superalloys"],
        "programs": ["A350", "787 Dreamliner", "A320neo", "737 MAX"],
        "downstream_oems": ["Airbus SE", "The Boeing Company", "Safran S.A.", "Spirit AeroSystems"],
        "geography": "Global", "source_ref": "Aerospace Raw Material Supply Chain Registry",
    },
]


# Resolve recognized aerospace suppliers without guessing an entity from weak context.
def lookup_supplier_in_registry(
    text_or_company: str, exact: bool = False
) -> Optional[Dict[str, Any]]:
    if not text_or_company:
        return None
    low = text_or_company.lower()
    if exact:
        normalize = lambda s: re.sub(
            r"\s+", " ", s.lower().replace(" and ", " & ")
        ).strip()

        return next((
            e for e in AEROSPACE_SUPPLIER_REGISTRY
            if normalize(low) in {
            normalize(a) for a in [e["official_name"], *e["aliases"]]
        }
        ), None)
    ordered = sorted(AEROSPACE_SUPPLIER_REGISTRY, key=lambda e: "OEM" in e["default_tier"])
    return next(
        (e for e in ordered if e["official_name"].lower() in low or any(a in low for a in e["aliases"])),
        None,
    )




# Coordinate request pacing to reduce undue load on third-party sources.
class CentralRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_call: Dict[str, float] = {}

    def wait_for_slot(self, source_id: str) -> None:
        min_interval = float(SOURCE_REGISTRY.get(source_id, {}).get("min_interval_sec", 1.0))
        with self._lock:
            wait_sec = min_interval - (time.time() - self._last_call.get(source_id, 0.0))
            if wait_sec > 0:
                time.sleep(wait_sec)
            self._last_call[source_id] = time.time()

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


# Enforce configured source-access restrictions before attempting collection.
def is_source_allowed(source_id: str) -> bool:
    cfg = SOURCE_REGISTRY.get(source_id)
    return bool(cfg and cfg.get("legal_status") in {SourceLegalStatus.ALLOWED.value, SourceLegalStatus.RESTRICTED.value})




_ROBOTS_CACHE: Dict[str, urllib.robotparser.RobotFileParser] = {}


# Reject private or otherwise unsafe network targets to mitigate SSRF exposure.
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
    re.I,
)


# Apply robots/TDM access checks according to configured source policy.
# Technical checks do not replace a legal assessment of permitted reuse.
def check_robots_and_tdm_compliance(
    url: str, source_id: str = "SRC_004", user_agent: str = "AeroEWSBot"
) -> Tuple[bool, str]:
    """Apply configured robots.txt and text-and-data-mining access checks."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False, "Invalid URL scheme or host"

    src_cfg = SOURCE_REGISTRY.get(source_id)
    if not src_cfg:
        return False, f"Unregistered source '{source_id}' - collection suspended (REQUIRES_REVIEW)"

    if src_cfg.get("legal_status") in {SourceLegalStatus.REQUIRES_REVIEW.value, SourceLegalStatus.DISABLED.value}:
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

            resp = requests.get(base_robots, timeout=5)
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
        logger.warning(
            f"[COMPLIANCE FAIL-CLOSED] Error loading robots.txt from {base_robots} ({e}). "
            f"Suspending collection and requiring manual review."
        )
        return False, "Error loading robots.txt rules - collection suspended (REQUIRES_REVIEW)"

    return True, "Allowed (Registry ToS, robots.txt, and TDM pre-check passed)"


# Centralize guarded HTTP retrieval, timeouts, access checks, and request pacing.
# Callers must still validate the returned document content.
def safe_http_get(
    url: str,
    source_id: str = "SRC_004",
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 12,
    max_redirects: int = 3,
    max_bytes: int = 2_000_000,
    check_robots: bool = False,
) -> Optional[requests.Response]:
    """SSRF-safe HTTP GET client with redirect hop verification, fail-closed robots.txt, and EU 2019/790 TDM opt-out checks."""
    if not is_source_allowed(source_id):
        logger.warning(f"[COMPLIANCE] Source {source_id} is disabled or requires legal review.")
        return None

    RATE_LIMITER.wait_for_slot(source_id)
    req_headers = headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AeroEWS/2.0"}
    current_url, current_params = url, params

    for _ in range(max_redirects + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in {"http", "https"} or not is_ip_public_and_safe(parsed.hostname or ""):
            RATE_LIMITER.record_outcome(source_id, False)
            return None

        if check_robots:
            allowed, reason = check_robots_and_tdm_compliance(current_url, source_id=source_id)
            if not allowed:
                logger.info(f"[COMPLIANCE] Skipping {current_url}: {reason}")
                return None

        try:
            resp = requests.get(
                current_url, params=current_params, headers=req_headers,
                timeout=timeout, allow_redirects=False, stream=True,
            )
            current_params = None

            if resp.status_code == 429:
                time.sleep(min(int(resp.headers.get("Retry-After", "3")), 6))
                continue

            if resp.status_code in {301, 302, 303, 307, 308}:
                loc = resp.headers.get("Location")
                if not loc:
                    break
                current_url = urljoin(current_url, loc)
                continue

            tdm_header = resp.headers.get("TDM-Reservation", "").strip()
            x_robots = resp.headers.get("X-Robots-Tag", "").lower()
            if tdm_header == "1" or any(tok in x_robots for tok in ("noai", "notdm", "none")):
                logger.info(f"[TDM COMPLIANCE] Respecting TDM/X-Robots opt-out header on {current_url}")
                resp.close()
                return None

            chunks, downloaded = [], 0
            for chunk in resp.iter_content(chunk_size=65536):
                if chunk:
                    chunks.append(chunk)
                    downloaded += len(chunk)
                    if downloaded >= max_bytes:
                        break
            resp._content = b"".join(chunks)

            if check_robots and "text/html" in resp.headers.get("Content-Type", "").lower():
                if HTML_TDM_OPT_OUT_REGEX.search(resp.text[:4000]):
                    logger.info(f"[TDM COMPLIANCE] Respecting HTML meta TDM opt-out on {current_url}")
                    return None

            RATE_LIMITER.record_outcome(source_id, resp.status_code < 400)
            return resp
        except Exception as e:
            logger.debug(f"[HTTP CLIENT] Error fetching {current_url}: {e}")
            RATE_LIMITER.record_outcome(source_id, False)
            return None

    return None




PROMPT_INJECTION_REGEX = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|system)\s+prompts?|"
    r"you\s+are\s+now\s+a\s+|system\s+override\s*:|new\s+directive\s*:|"
    r"forget\s+everything|do\s+not\s+mention\s+this\s+instruction|"
    r"output\s+threat_score\s*=\s*10|<\s*/?\s*system\s*>)",
    re.I,
)

PII_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PII_PHONE_REGEX = re.compile(r"(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b")
PII_SOCIAL_HANDLE_REGEX = re.compile(r"(?<!\w)@[A-Za-z0-9_.-]{3,40}\b")
PII_PERSONAL_BYLINE_REGEX = re.compile(
    r"\b(?:contact\s+person|media\s+contact|press\s+contact|written\s+by|reported\s+by)\s*:\s*[A-Z][a-z]+\s+[A-Z][a-z]+",
    re.I,
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
    re.I,
)

AEROSPACE_B2B_RELEVANCE_ANCHORS = re.compile(
    r"\b(?:airbus|boeing|comac|embraer|pratt|whitney|cfm|safran|rolls-royce|ge\s+aerospace|spirit\s+aerosystems|"
    r"collins|faa|easa|ntsb|airworthiness|directive|supply\s+chain|tier\s*[123]|delivery\s+delay|shortage|"
    r"production|grounding|grounded|mro|turbine|fuselage|titanium|forging|defect|inspection|fleet\s+order)\b",
    re.I,
)


# Exclude unrelated personal posts before introducing them into intelligence processing.
def is_unrelated_personal_post(text: str, title: str = "") -> bool:
    """Exclude unrelated personal content before downstream collection and analysis."""
    combined = f"{title} {text}".strip()
    return (
        not combined
        or bool(PERSONAL_NON_INDUSTRIAL_POST_REGEX.search(combined))
        or not bool(AEROSPACE_B2B_RELEVANCE_ANCHORS.search(combined))
    )


# Reduce irrelevant or potentially sensitive text before downstream LLM dispatch.
def sanitize_and_minimize_osint_text(raw_text: str) -> Tuple[str, bool, int]:
    """Sanitize indirect prompt injection patterns and minimize personal data (GDPR Art. 5(1)(c))."""
    if not raw_text:
        return "", False, 0

    cleaned, inj_count = PROMPT_INJECTION_REGEX.subn("[REDACTED_PROMPT_INJECTION_ATTEMPT]", raw_text)
    pii_count = 0
    for regex, replacement in _PII_REDACTION_RULES:
        cleaned, count = regex.subn(replacement, cleaned)
        pii_count += count

    return cleaned, inj_count > 0, pii_count




COLLECTED_URLS: set[str] = set()
COLLECTED_DOCUMENTS: List[Dict[str, Any]] = []
CONNECTOR_TELEMETRY: Dict[str, Dict[str, Any]] = {}
NEWS_FALLBACK_CACHE: Dict[Tuple[str, str, str, int], List[Dict[str, Any]]] = {}
_COLLECTION_LOCK = threading.Lock()


# Clear in-memory collection state at the start of a new scan.
def reset_collected_urls() -> None:
    with _COLLECTION_LOCK:
        COLLECTED_URLS.clear()
        COLLECTED_DOCUMENTS.clear()
        CONNECTOR_TELEMETRY.clear()
        NEWS_FALLBACK_CACHE.clear()


# Return the source documents registered during the current collection cycle.
def get_collected_documents() -> List[Dict[str, Any]]:
    with _COLLECTION_LOCK:
        return list(COLLECTED_DOCUMENTS)


# Expose collection success/failure metadata for runtime reporting.
def get_connector_telemetry() -> Dict[str, Dict[str, Any]]:
    with _COLLECTION_LOCK:
        return dict(CONNECTOR_TELEMETRY)


# Update the source-specific telemetry registry after a collection attempt.
def record_connector_telemetry(
    connector_name: str,
    source_id: str,
    query: str,
    found_count: int = 0,
    accepted_count: int = 0,
    rejected_out_of_scope: int = 0,
    unknown_date_count: int = 0,
    error: Optional[str] = None,
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
                "errors": [],
                "time_window": {
                    "from": os.getenv("EWS_EFFECTIVE_FROM", ""),
                    "to": os.getenv("EWS_EFFECTIVE_TO", ""),
                    "scope": os.getenv("EWS_DYNAMIC_SCOPE", "7d"),
                },
                "last_updated": now_str,
            },
        )
        # The interim EASA index is fetched directly
        # from the official EASA website, not Google News.

        if connector_name == "EASA Official Index":

            entry["technical_source"] = (
                "easa.europa.eu"
            )

            entry["origin_type"] = (
                "PRIMARY_OFFICIAL_INDEX_METADATA"
            )
        if query and query not in entry["queries"]:
            entry["queries"].append(query)
        entry["found_count"] += found_count
        entry["accepted_count"] += accepted_count
        entry["rejected_out_of_scope"] += rejected_out_of_scope
        entry["unknown_date_count"] += unknown_date_count
        if error:
            entry["errors"].append(error)
        entry["last_updated"] = now_str


# Register a normalized document with stable provenance and duplicate controls.
def register_collected_document(
    source_id: str,
    connector_name: str,
    url: str,
    title: str,
    raw_text: str,
    published_at: str,
    query_used: str = "",
) -> Dict[str, Any]:
    """Assign a unique DOC_xxx identifier, compute syndication fingerprint, sanitize text, and store metadata."""
    clean_text, injection_flag, pii_redacted = sanitize_and_minimize_osint_text(raw_text)
    clean_title, title_inj, _ = sanitize_and_minimize_osint_text(title)
    norm_pub = normalize_date_str(published_at)

    words_for_fp = re.findall(r"\b[a-z0-9]{4,}\b", f"{clean_title} {clean_text[:300]}".lower())
    fingerprint = hashlib.sha256(" ".join(words_for_fp[:25]).encode("utf-8")).hexdigest()[:16]

    parsed_domain = urlparse(url).netloc.lower().replace("www.", "")
    reg_info = SOURCE_REGISTRY.get(source_id, {})
    supplier_match = lookup_supplier_in_registry(f"{clean_title} {clean_text[:400]}")

    with _COLLECTION_LOCK:
        doc_id = f"DOC_{len(COLLECTED_DOCUMENTS) + 1:03d}"
        COLLECTED_URLS.add(url)
        doc_record = {
            "doc_id": doc_id,
            "source_id": source_id,
            "connector_name": connector_name,
            "url": url,
            "publisher_domain": parsed_domain,
            "origin_type": reg_info.get("origin", "SECONDARY"),
            "source_type": reg_info.get("source_type", "MEDIA"),
            "verified_domain": bool(reg_info.get("verified_domain", False)),
            "title": clean_title,
            "text": clean_text,
            "published_at": norm_pub or "DATE_UNKNOWN",
            "raw_published_at": published_at,
            "date_unknown": not bool(norm_pub),
            "collected_at": _now_iso(),
            "query_used": query_used,
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
    "Paris Air Show": "https://www.siae.fr/en/press/",
    "Dubai Airshow": "https://www.dubaiairshow.aero/usefulinfo/info/news/",
    "Singapore Airshow": "https://www.singaporeairshow.com/media/singapore-airshow-newsroom",
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
        "europe", "easa", "france", "toulouse", "germany", "hamburg", "uk", "britain", "farnborough", "aegean", "wizz", "iberia",
    ],
    "Asia-Pacific (Singapore / China / Japan / India)": [
        "china", "comac", "singapore", "india", "indigo", "qantas", "australia", "japan", "korea", "starlux",
    ],
    "Middle East (UAE / Qatar / Saudi Arabia)": [
        "dubai", "uae", "emirates", "etihad", "flydubai", "abu dhabi", "qatar", "doha", "saudi", "riyadh",
    ],
}

MAX_PAGES_PER_AIRSHOW = 5
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
    re.I,
)

IRRELEVANT_URL_REGEX = re.compile(
    r"/(?:speakers?|aeroforum|archive|contact-us|faqs?|gallery|book-a-booth|201\d|2020|2021)(?:/|-|$)|"
    r"announces-.*-wave-of-speakers",
    re.I,
)

MONTH_MAP = {
    "jan": 1, "january": 1, "feb": 2, "february": 2, "mar": 3, "march": 3,
    "apr": 4, "april": 4, "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
    "aug": 8, "august": 8, "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10, "nov": 11, "november": 11, "dec": 12, "december": 12,
}

_DATE_RANGE_RE = re.compile(
    r"\b\d{1,2}\s*(?:\([A-Za-z]+\)\s*)?(?:–|-|to)\s*\d{1,2}\s*(?:\([A-Za-z]+\)\s*)?[A-Za-z]+\s+20[12]\d\b", re.I
)
_ISO_DATE_RE = re.compile(r"(20[12]\d-\d{2}-\d{2})")
_ISO_EXACT_RE = re.compile(r"^20[12]\d-\d{2}-\d{2}$")
_ISO_FULL_RE = re.compile(r"(20[12]\d-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_MONTH_NAMES_PAT = r"(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*"
_DMY_RE = re.compile(rf"\b(\d{{1,2}})\s+{_MONTH_NAMES_PAT}\s+(20[12]\d)\b", re.I)
_MDY_RE = re.compile(rf"\b{_MONTH_NAMES_PAT}\s+(\d{{1,2}}),?\s+(20[12]\d)\b", re.I)
_COMPACT_DMY_RE = re.compile(r"(?:airshow|news|pr)[-_]?(\d{2})(\d{2})(202\d)", re.I)
_JSON_DATE_RE = re.compile(r'\\?"(?:datePublished|publishedAt|publishDate|articlePublishedTime)\\?"\s*:\s*\\?"(20[12]\d-\d{2}-\d{2})')
_LAYOUT_NOISE_RE = re.compile(r"masthead|footer|sidebar|sitemenu|banner|timer", re.I)
_DATE_CLASS_RE = re.compile(r"blogpost-date|post-date|article-date|publish", re.I)
_VALID_AIRCRAFT_TOKEN_RE = re.compile(
    r"^(?:a(?:220|319|320|321|330|340|350|380)|737|747|757|767|777|787|c919)(?:[a-z0-9-]*)$", re.I
)
_PAGINATION_CONTAINER_RE = re.compile(r"pagin|pager|page-numbers|nav-links", re.I)
_PAGINATION_QUERY_RE = re.compile(r"[?&](?:page|pageNo|pageno|paged|p|start)=([2-9]|\d{2,})\b", re.I)
_PAGINATION_PATH_RE = re.compile(r"/page/([2-9]|\d{2,})(?:/|$|\?)", re.I)
_NOISE_ATTR_RE = re.compile(
    r"cookie|consent|modal|signup|top-signup|mega-menu|navbar|"
    r"sitemenu_area|masthead_area|masthead2_area|sidebar_area|footer_area|mobile-menu|path_box",
    re.I,
)
_CARD_ANCHOR_RE = re.compile(r"BlockWrapper_anchor|informa-module-block")


# Resolve the per-source retrieval limit configured for the active scan.
def get_dynamic_limit() -> int:
    return int(os.getenv("EWS_DYNAMIC_LIMIT", 5))


# Return the effective UTC reference time, including historical simulation mode.
def get_reference_now_utc() -> datetime:
    """Return the historical reference date when configured, otherwise current UTC."""
    as_of = os.getenv("EWS_AS_OF_DATE", "").strip()
    if as_of:
        try:
            if "T" in as_of:
                dt = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return datetime.strptime(as_of[:10], "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


# Convert the selected analysis window into a lookback duration when bounded.
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


# Derive UTC collection boundaries from scope and optional explicit dates.
def get_time_window_utc() -> Tuple[Optional[datetime], datetime]:
    """Return the effective UTC start and end of the requested analysis period."""
    end_utc = get_reference_now_utc()
    scope_enum = normalize_scope_value(os.getenv("EWS_DYNAMIC_SCOPE", "7d"))
    custom_from = os.getenv("EWS_DATE_FROM", "").strip()
    custom_to = os.getenv("EWS_DATE_TO", "").strip()

    if scope_enum == AnalysisScope.CUSTOM and custom_to:
        try:
            end_utc = datetime.strptime(custom_to[:10], "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        except ValueError:
            pass

    if scope_enum == AnalysisScope.CUSTOM and custom_from:
        try:
            return datetime.strptime(custom_from[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc), end_utc
        except ValueError:
            pass

    if scope_enum == AnalysisScope.ALL:
        return None, end_utc
    if scope_enum == AnalysisScope.LAST_24_HOURS:
        return end_utc - timedelta(hours=24), end_utc

    return end_utc - timedelta(days=get_scope_days() or 7), end_utc

# Parse heterogeneous source timestamps into timezone-aware UTC values.
def parse_datetime_utc(date_str: str) -> Optional[datetime]:
    """Parse RSS, ISO-8601, or normalized date string into a timezone-aware UTC datetime."""
    if not date_str or date_str in {"N/A", "Unknown", "DATE_UNKNOWN"} or "unknown" in date_str.lower():
        return None

    raw = date_str.strip()
    try:
        parsed_rss = email.utils.parsedate_to_datetime(raw)
        return (parsed_rss if parsed_rss.tzinfo else parsed_rss.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except Exception:
        pass

    iso_full = _ISO_FULL_RE.search(raw)
    if iso_full:
        try:
            dt = datetime.fromisoformat(iso_full.group(1).replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    norm = normalize_date_str(raw)
    if norm and _ISO_EXACT_RE.match(norm):
        try:
            return datetime.strptime(norm, "%Y-%m-%d").replace(hour=12, minute=0, second=0, tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


# Check publication-time eligibility without equating publication with event occurrence.
def is_date_within_scope(date_str: str) -> bool:
    """Determine whether a source publication timestamp falls within the analysis window."""
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


# Keep relevant context while reducing source payload length for downstream analysis.
def smart_context_filter(full_text: str, query_keywords: list) -> str:
    core_keywords = [k.lower() for k in query_keywords] + [
        "airbus", "boeing", "supplier", "safety", "delay", "defect",
        "easa", "faa", "titanium", "engine", "spirit", "pratt",
    ]
    relevant_paragraphs = [
        p.strip() for p in full_text.split("\n")
        if len(p) > 40 and any(kw in p.lower() for kw in core_keywords)
    ]
    filtered_text = "\n".join(relevant_paragraphs)
    return filtered_text[:2500] if filtered_text else full_text[:1000]


# Normalize unstructured publication dates for consistent downstream handling.
def normalize_date_str(raw_str: str) -> str:
    """Normalize recognized publication dates into a consistent ISO date."""
    if not raw_str:
        return ""
    cleaned = _DATE_RANGE_RE.sub("", raw_str.strip())

    iso_match = _ISO_DATE_RE.search(cleaned)
    if iso_match:
        return iso_match.group(1)

    dmy_match = _DMY_RE.search(cleaned)
    if dmy_match:
        day, month, year = int(dmy_match.group(1)), MONTH_MAP.get(dmy_match.group(2).lower()[:3], 1), int(dmy_match.group(3))
        if 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"

    mdy_match = _MDY_RE.search(cleaned)
    if mdy_match:
        month, day, year = MONTH_MAP.get(mdy_match.group(1).lower()[:3], 1), int(mdy_match.group(2)), int(mdy_match.group(3))
        if 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"

    compact_dmy = _COMPACT_DMY_RE.search(cleaned)
    if compact_dmy:
        day, month, year = int(compact_dmy.group(1)), int(compact_dmy.group(2)), int(compact_dmy.group(3))
        if 1 <= month <= 12 and 1 <= day <= 31:
            return f"{year:04d}-{month:02d}-{day:02d}"

    return ""


# Extract article dates conservatively from page metadata and visible content.
def extract_article_date(
    raw_html: str, clean_article_text: str = "", url: str = "", fallback_date: str = ""
) -> str:
    if fallback_date and _ISO_EXACT_RE.match(fallback_date):
        return fallback_date

    safe_json_date = _JSON_DATE_RE.search(raw_html)
    if safe_json_date:
        return safe_json_date.group(1)

    soup = BeautifulSoup(raw_html, "html.parser")
    for meta_prop in ("article:published_time", "og:published_time", "publish-date", "date"):
        meta = soup.find("meta", attrs={"property": meta_prop}) or soup.find("meta", attrs={"name": meta_prop})
        if meta and meta.get("content"):
            if norm := normalize_date_str(meta["content"]):
                return norm

    for tag in soup(["header", "footer", "nav", "aside", "script", "style"]):
        tag.extract()
    for el in soup.find_all(attrs={"class": _LAYOUT_NOISE_RE}):
        el.extract()

    if time_tag := soup.find("time"):
        if norm := normalize_date_str(time_tag.get("datetime", "") or time_tag.get_text(" ", strip=True)):
            return norm

    for date_el in soup.find_all(attrs={"class": _DATE_CLASS_RE}):
        if norm := normalize_date_str(date_el.get_text(" ", strip=True)):
            return norm

    for candidate in (clean_article_text[:600], fallback_date, url):
        if candidate and (norm := normalize_date_str(candidate)):
            return norm

    return "DATE_UNKNOWN"


MODEL_TOKEN_RE = re.compile(
    r"(?<!\w)(?:[A-Za-z]{1,5}[- ]?\d{1,5}[A-Za-z0-9-]*|"
    r"\d{3,4}(?:[- ]?[A-Za-z]{1,8}|-\d{1,3}))\b",
    re.I
)


def _model_tokens(query: str) -> list[str]:
    return list(dict.fromkeys(
        m.lower() for m in MODEL_TOKEN_RE.findall(query or "")
    ))

_STOP_WORDS = {
    "find", "search", "show", "tell", "about", "this", "what",
    "are", "the", "latest", "new", "from", "with", "for", "and",
}


# Extract source-query constraints without expanding beyond the requested KIT.
def parse_query_intent(safe_query: str) -> tuple[list[str], str]:
    """Preserve explicit aircraft and engine identifiers while parsing search intent."""
    detected_specific_models: list[str] = []
    remaining_query = safe_query.lower()

    for spec_model in _model_tokens(safe_query):
        pattern = rf"(?<![a-z0-9]){re.escape(spec_model)}(?![a-z0-9])"
        if re.search(pattern, remaining_query, re.I):
            detected_specific_models.append(spec_model)
            remaining_query = re.sub(pattern, " ", remaining_query, flags=re.I)

    words = [w.lower() for w in re.findall(r"\b\w+\b", remaining_query)]
    significant_words = [
        w for w in words if (any(c.isdigit() for c in w) or len(w) > 3) and w not in _STOP_WORDS
    ]

    expanded_words = list(detected_specific_models)
    models_for_search = list(detected_specific_models)

    for w in significant_words:
        if w not in expanded_words:
            expanded_words.append(w)
        if not detected_specific_models:
            model_match = re.match(r"^([a-z]?\d{3})(?:[a-z]+|\d+)$", w)
            if model_match:
                models_for_search.append(w)
                base_model = model_match.group(1)
                if base_model not in expanded_words:
                    expanded_words.append(base_model)
            elif any(c.isdigit() for c in w):
                models_for_search.append(w)
        elif any(c.isdigit() for c in w) and w not in models_for_search:
            models_for_search.append(w)

    has_specific_model = bool(detected_specific_models) or any(any(c.isdigit() for c in w) for w in expanded_words)
    required_words = [w for w in expanded_words if w not in GENERIC_MANUFACTURERS] if has_specific_model else expanded_words
    if not required_words:
        required_words = words or [""]

    text_words = [w for w in required_words if w not in detected_specific_models and not any(c.isdigit() for c in w)]
    models_for_search = [
        m for m in models_for_search if any(c.isdigit() for c in m)
    ]
    search_candidates = (models_for_search + text_words)[:3]
    return required_words, (" ".join(search_candidates) if search_candidates else safe_query)


# Preserve relevant evidence-bearing paragraphs from retrieved documents.
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

        if any(nw in combined_lower for nw in num_words) or sum(1 for rw in required_words if rw in combined_lower) >= min(2, len(required_words)):
            norm_key = re.sub(r"[^a-z0-9]", "", combined_lower)
            if norm_key not in seen_normalized:
                seen_normalized.add(norm_key)
                if next_line:
                    seen_normalized.add(re.sub(r"[^a-z0-9]", "", next_line.lower()))
                    skip_next = True
                matched_chunks.append(combined_block)

    return "\n\n".join(matched_chunks)


# Extract readable text and candidate links from HTML while retaining source context.
def extract_clean_blocks(soup: BeautifulSoup, base_url: str) -> tuple[str, list[dict], list[str]]:
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
            ):
                if full_href not in pagination_urls:
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

    for tag in soup(["script", "style", "nav", "footer", "header", "noscript", "svg", "form", "button", "iframe", "aside"]):
        tag.extract()
    for el in soup.find_all(attrs={"id": _NOISE_ATTR_RE}):
        el.extract()
    for el in soup.find_all(attrs={"class": _NOISE_ATTR_RE}):
        el.extract()

    for block in soup.find_all("div", class_="pageblock_box"):
        h2 = block.find("h2")
        if h2 and h2.get_text(strip=True).isdigit() and int(h2.get_text(strip=True)) < 2022:
            block.extract()

    text_blocks, seen_texts, article_links, seen_urls = [], set(), [], set()

    def add_candidate_link(title: str, raw_href: str, context_str: str, card_date: str = ""):
        full_u = urljoin(base_url, raw_href)
        if full_u not in seen_urls and urlparse(full_u).netloc == base_domain:
            seen_urls.update((raw_href, full_u))
            article_links.append({
                "title": title.strip(), "url": full_u,
                "context": context_str[:350].lower(), "date": card_date,
            })

    for td in soup.find_all("td"):
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
        if parsed.netloc == base_domain and len(path_parts) >= 2 and not full_url.lower().endswith((".pdf", ".jpg", ".png", ".svg", ".webp")):
            a_title = a_tag.get_text(" ", strip=True) or path_parts[-1]
            parent_text = a_tag.parent.get_text(" ", strip=True) if a_tag.parent else a_title
            ctx_text = parent_text if len(parent_text) <= 350 else a_title
            card_date = normalize_date_str(full_url) if is_search_page else (normalize_date_str(ctx_text) or normalize_date_str(full_url))
            add_candidate_link(a_title, href, ctx_text, card_date)

    return "\n".join(text_blocks), article_links, pagination_urls

def news_api_search_key(query: str) -> str:
    """
    Build a bounded NewsAPI query while preserving
    aircraft identity, technical scope and event indicators.
    """

    safe_query = re.sub(
        r"\s+",
        " ",
        (query or "").replace(",", " ")
    ).strip()

    words = re.findall(
        r"[a-z0-9-]+",
        safe_query.lower()
    )

    aircraft = _model_tokens(safe_query)

    # Preserve technical identifiers explicitly present in KIT.
    technical = [
        w for w in words
        if w in {
            "gtf", "pw1100g", "leap", "cfm56",
            "ge9x", "ge90", "pratt", "whitney",
            "trent", "safran", "rolls-royce",
            "easa", "faa", "ntsb",
            "spirit", "supplier",
        }
    ]

    # Preserve requested event or warning indicators.
    issue = [
        w for w in words
        if re.fullmatch(
            r"(?:inspect\w*|defect\w*|fail\w*|"
            r"shortag\w*|ground\w*|delay\w*|"
            r"directiv\w*|airworth\w*|"
            r"production|manufactur\w*|"
            r"constraint\w*|recall\w*|"
            r"certif\w*|order\w*|deliver\w*|"
            r"fleet|disrupt\w*|safet\w*|"
            r"engine\w*|regulat\w*|"
            r"problem\w*|issue\w*|incident\w*|"
            r"cancel\w*|strike\w*|maintenan\w*|"
            r"upgrade\w*|turbine|blades?)",
            w
        )
    ]

    def unique(values):
        return list(
            dict.fromkeys(
                v for v in values if v
            )
        )

    technical = unique(technical)[:4]
    issue = unique(issue)[:4]

    if aircraft:
        anchor = aircraft[0]

    else:
        stop = {
            "which", "about", "latest", "news",
            "what", "does", "from", "with",
            "this", "that", "aircraft",
            "aviation", "issues", "report",
            "reports", "europe", "official",
        }

        anchor = next(
            (
                w for w in words
                if len(w) > 3
                and w not in stop
                and w not in issue
            ),
            ""
        )

        technical = [
            w for w in technical
            if w != anchor
        ]

    # Do not repeat technical terms already included
    # in the primary aircraft or engine identifier.

    anchor_words = set(
        re.findall(
            r"[a-z0-9]+",
            anchor.lower()
        )
    )

    technical = [
        term for term in technical
        if term not in anchor_words
    ]

    parts = [
        f'"{anchor}"'
        if " " in anchor
        else anchor
    ]

    if technical:
        parts.append(
            "(" + " OR ".join(technical) + ")"
        )

    if issue:
        parts.append(
            "(" + " OR ".join(issue) + ")"
        )

    return " AND ".join(parts)

def _extract_news_article_body(html: str) -> str:
    """
    Extract article paragraphs and exclude unrelated
    page navigation, recommendations and sidebars.
    """

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    # Remove common non-article containers.
    for node in soup.select(
        "script, style, noscript, nav, "
        "header, footer, aside, form, "
        "[role='navigation'], "
        "[class*='related'], "
        "[class*='recommend'], "
        "[class*='advert'], "
        "[id*='related']"
    ):
        node.decompose()

    # Prefer explicit article containers.
    selectors = (
        "[itemprop='articleBody']",
        "article",
        "[class*='article-body']",
        "[class*='story-body']",
        "main",
    )

    for selector in selectors:

        candidates = []

        for node in soup.select(selector):

            paragraphs = [
                p.get_text(" ", strip=True)
                for p in node.find_all("p")
            ]

            content = "\n".join(
                p for p in paragraphs
                if len(p) >= 35
            )

            if len(content) >= 120:
                candidates.append(content)

        if candidates:
            return max(
                candidates,
                key=len
            )[:10000]

    return ""

# Collect relevant aviation news with source URL, date, and query provenance.
@tool("Search Aerospace News and Read Full Articles")
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def search_aerospace_news(query: str) -> str:
    """Query News API preserving specific aircraft model suffixes (e.g., 777X, A321XLR)."""
    safe_query = query.replace(",", "").replace("  ", " ").strip()
    and_query = news_api_search_key(safe_query)
    query_tokens = and_query.split(" AND ")

    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()

    logger.info(
        f"[OSINT GATHERER] Querying News API for: '{and_query}' "
        f"(limit: {limit}, from: {start_utc.strftime('%Y-%m-%d') if start_utc else 'unrestricted'})"
    )
    url = "https://newsapi.org/v2/everything"
    params: Dict[str, Any] = {
        "q": and_query,
        "language": "en",
        "sortBy": "relevancy",
        "pageSize": min(100, limit * 4),
        "apiKey": NEWS_API_KEY,
        "to": end_utc.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    if start_utc is not None:
        params["from"] = max(start_utc, datetime.now(timezone.utc) - timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%S")

    resp = safe_http_get(url, source_id="SRC_004", params=params, timeout=15)
    if resp is None or resp.status_code != 200:
        record_connector_telemetry("News API", "SRC_004", safe_query, error="News API request failed or blocked")
        return f"No articles found in News API for query '{query}' within the selected time scope."

    articles = resp.json().get("articles", [])
    logger.info(f"[NEWS API DEBUG] Query='{and_query}' | HTTP={resp.status_code} | API articles={len(articles)}")

    # Preserve aircraft and technical scope during fallback.
    # Never broaden directly to the aircraft model alone.

    # Retrieval recall: search technical issues even when
    # articles do not explicitly name the aircraft model.

    if (
            len(query_tokens) >= 3
            and len(articles) < max(10, limit * 2)
    ):
        fallback_q = " AND ".join(query_tokens[1:])

        fallback_params = {
            **params,
            "q": fallback_q,
            "pageSize": min(100, max(20, limit * 4)),
        }

        cache_key = (
            fallback_q,
            str(fallback_params.get("from", "")),
            str(fallback_params.get("to", "")),
            fallback_params["pageSize"],
        )

        with _COLLECTION_LOCK:
            cached_articles = NEWS_FALLBACK_CACHE.get(cache_key)

        if cached_articles is None:
            fb_resp = safe_http_get(
                url,
                source_id="SRC_004",
                params=fallback_params,
                timeout=15,
            )

            cached_articles = (
                fb_resp.json().get("articles", []) or []
                if fb_resp is not None
                   and fb_resp.status_code == 200
                else []
            )

            with _COLLECTION_LOCK:
                NEWS_FALLBACK_CACHE[cache_key] = list(
                    cached_articles
                )

        existing_urls = {
            a.get("url") for a in articles
        }

        for candidate in cached_articles:
            article_url = candidate.get("url")

            if (
                    article_url
                    and article_url not in existing_urls
            ):
                articles.append(candidate)
                existing_urls.add(article_url)

        logger.info(
            "[NEWS API RECALL] Broad query %r, "
            "%d combined candidates",
            fallback_q,
            len(articles),
        )

    if not articles:
        record_connector_telemetry("News API", "SRC_004", safe_query, 0, 0, 0)
        return f"No articles found in News API for query '{query}' within the selected time scope."

    extracted_content = ""
    query_words = [w.lower() for w in safe_query.split() if len(w) > 2]
    count = rejected_scope = unknown_dates = rejected_missing_url = rejected_duplicate = rejected_model = metadata_only = 0

    model_anchor = query_tokens[0].strip('"').lower() if query_tokens else ""
    model_pattern = None
    if model_anchor and any(c.isdigit() for c in model_anchor):
        model_pattern = re.compile(
            rf"(?<!\w){re.escape(model_anchor)}(?!\w)"
        )

    for article in articles:
        if count >= limit:
            break

        article_url = article.get("url", "")
        if not article_url:
            rejected_missing_url += 1
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
        if not normalize_date_str(pub_date):
            unknown_dates += 1

        body_text = desc
        # A NewsAPI description is metadata, not independently
        # retrieved publisher article text.

        body_text = ""

        page_resp = safe_http_get(
            article_url,
            source_id="SRC_004",
            timeout=10,
            check_robots=True
        )

        if (
                page_resp is not None
                and page_resp.status_code == 200
        ):

            content_type = page_resp.headers.get(
                "Content-Type", ""
            ).lower()

            if (
                    "text/html" in content_type
                    or not content_type
            ):

                article_body = _extract_news_article_body(
                    page_resp.text
                )

                # Check whether the extracted content has
                # a recognizable relationship to its title.

                title_terms = {
                    w for w in re.findall(
                        r"[a-z]{4,}",
                        title.lower()
                    )
                    if w not in {
                        "with", "from", "that",
                        "this", "over", "about",
                        "after", "into", "years",
                    }
                }

                body_terms = set(
                    re.findall(
                        r"[a-z]{4,}",
                        article_body.lower()
                    )
                )

                if (
                        article_body
                        and (
                        not title_terms
                        or title_terms & body_terms
                )
                ):

                    body_text = smart_context_filter(
                        article_body,
                        query_words
                    )

                elif article_body:

                    logger.warning(
                        "[NEWS BODY MISMATCH] %s: "
                        "title does not match article text",
                        article_url
                    )

        # If the publisher text could not be retrieved,
        # retain the metadata but explicitly label it.

        if not body_text:
            metadata_only += 1

            body_text = (
                    "[NEWSAPI_METADATA_ONLY: "
                    "PUBLISHER ARTICLE TEXT UNAVAILABLE]\n"
                    + (
                            desc.strip()
                            or "No article description available."
                    )
            )

        if model_pattern and not model_pattern.search(
                f"{title} {desc} {body_text}".lower()
        ):
            logger.info(
                "[NEWS API SCOPE REVIEW] Model %r not "
                "explicitly mentioned in %r; "
                "retaining for semantic filtering.",
                model_anchor,
                title[:100],
            )

        doc = register_collected_document(
            source_id="SRC_004",
            connector_name="News API",
            url=article_url,
            title=title,
            raw_text=body_text,
            published_at=pub_date,
            query_used=safe_query,
        )
        extracted_content += (
            f"\n<untrusted_osint_document id=\"{doc['doc_id']}\" source_id=\"SRC_004\">\n"
            f"DOC_ID: {doc['doc_id']}\n"
            f"DATE: {doc['published_at']}\n"
            f"COLLECTED_AT: {doc['collected_at']}\n"
            f"TITLE: {doc['title']}\n"
            f"SOURCE: {article_url}\n"
            f"CONTENT: {doc['text']}...\n"
            f"</untrusted_osint_document>\n"
            + ("-" * 40)
            + "\n"
        )
        count += 1

    logger.info(
        "[NEWS API AUDIT] query=%r candidates=%d accepted=%d missing_url=%d duplicate=%d out_of_scope=%d model_mismatch=%d metadata_only=%d",
        safe_query, len(articles), count, rejected_missing_url, rejected_duplicate, rejected_scope, rejected_model, metadata_only,
    )
    record_connector_telemetry("News API", "SRC_004", safe_query, len(articles), count, rejected_scope, unknown_dates)

    if count == 0:
        return f"No relevant articles found in News API for query '{query}'."

    logger.info(f"[OSINT GATHERER] News API extraction completed ({count} articles).")
    return extracted_content


# Retrieve NTSB investigation material as regulatory/investigative source evidence.
@tool("Scrape NTSB Safety Investigations")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_ntsb_investigations(query: str = "latest") -> str:
    """Fetch NTSB aviation safety investigation updates via RSS."""
    clean_query = query.replace(",", "").strip()
    required_words, _ = parse_query_intent(clean_query)
    limit = get_dynamic_limit()
    scope_days = get_scope_days()
    time_filter = f" when:{scope_days}d" if scope_days else ""

    logger.info(f"[OSINT GATHERER] Fetching NTSB records for: '{clean_query}' (limit: {limit}, scope: {scope_days or 'all'} days)")
    try:
        safe_query = urllib.parse.quote(
            f"site:ntsb.gov {clean_query}{time_filter}"
        )
        url = f"https://news.google.com/rss/search?q={safe_query}&hl=en-US&gl=US&ceid=US:en"

        resp = safe_http_get(url, source_id="SRC_003", timeout=10)
        if resp is None or resp.status_code != 200:
            record_connector_telemetry("NTSB Investigations", "SRC_003", clean_query, error="HTTP error")
            return "NTSB data currently unavailable."

        feed = feedparser.parse(resp.content)
        extracted_text = f"--- NTSB SAFETY INVESTIGATIONS AND ACCIDENT REPORTS FOR '{query}' ---\n"
        count = rejected_scope = 0

        for entry in feed.entries:
            if count >= limit:
                break
            link = entry.get("link", "https://www.ntsb.gov")
            if link in COLLECTED_URLS:
                continue

            pub_date = entry.get("published", "DATE_UNKNOWN")
            if not is_date_within_scope(pub_date):
                rejected_scope += 1
                continue

            title = entry.get("title", "Untitled")
            clean_desc = BeautifulSoup(entry.get("description", ""), "html.parser").get_text(" ", strip=True)

            if clean_query.lower() != "latest" and not any(rw in f"{title} {clean_desc}".lower() for rw in required_words):
                continue

            doc = register_collected_document(
                source_id="SRC_003",
                connector_name="NTSB Investigations",
                url=link,
                title=title,
                raw_text=clean_desc or title,
                published_at=pub_date,
                query_used=clean_query,
            )
            extracted_text += (
                f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_003\n"
                f"DATE: {doc['published_at']}\nTitle: {doc['title']}\n"
                f"Link: {link}\nSummary: {doc['text']}\n---\n"
            )
            count += 1

        record_connector_telemetry("NTSB Investigations", "SRC_003", clean_query, len(feed.entries), count, rejected_scope)
        if count == 0:
            return f"No NTSB accident or investigation reports found for '{query}' within the selected time scope."

        logger.warning(f"[OSINT DEBUG] NTSB module returned {count} records.")
        return extracted_text
    except Exception as e:
        logger.error(f"[OSINT GATHERER] NTSB RSS error: {str(e)}")
        record_connector_telemetry("NTSB Investigations", "SRC_003", clean_query, error=str(e))
        return "NTSB data currently unavailable."

# Resolve a Federal Register document's latest published action in the same docket.
# A missing/failed lookup is explicitly unverified rather than assumed current.
_FAA_LIFECYCLE_FIELDS = [
    "document_number",
    "docket_id",
    "docket_ids",
    "title",
    "abstract",
    "action",
    "type",
    "html_url",
    "publication_date",
    "effective_on",
]


def _faa_resolve_docket(
    doc: Dict[str, Any],
    as_of: str,
    cache: Dict[str, Tuple[Dict[str, Any], bool]],
) -> Tuple[Dict[str, Any], str, bool]:
    """
    Resolve the latest published FAA rule/proposed rule within the same docket.

    Returns:
        document: Latest applicable document, or the original document.
        docket: FAA docket identifier, if found.
        checked: Whether the lifecycle lookup succeeded.
    """
    number = str(doc.get("document_number") or "")
    full_doc = dict(doc)

    # 1. Request detailed metadata explicitly.
    if re.fullmatch(r"\d{4}-\d{4,6}", number):
        response = safe_http_get(
            f"https://www.federalregister.gov/api/v1/documents/{number}.json",
            source_id="SRC_001",
            params={"fields[]": _FAA_LIFECYCLE_FIELDS},
            timeout=12,
        )

        if response is not None and response.status_code == 200:
            full_doc.update(response.json())

    # 2. Extract docket from structured API fields.
    docket_data = json.dumps({
        "docket_ids": full_doc.get("docket_ids"),
        "docket_id": full_doc.get("docket_id"),
    })

    match = re.search(
        r"\bFAA-\d{4}-\d+\b",
        docket_data,
        re.I,
    )

    docket = match.group(0).upper() if match else ""

    # 3. Fallback: read docket identifier from official document HTML.
    if not docket:
        url = full_doc.get("html_url") or doc.get("html_url")

        if url:
            page = safe_http_get(
                url,
                source_id="SRC_001",
                timeout=12,
            )

            if page is not None and page.status_code == 200:
                plain = BeautifulSoup(
                    page.text,
                    "html.parser",
                ).get_text(" ", strip=True)

                match = re.search(
                    r"\bDocket\s+(?:No\.?|Number)\s*[:#]?\s*"
                    r"(FAA-\d{4}-\d+)\b",
                    plain,
                    re.I,
                )

                if match:
                    docket = match.group(1).upper()

    if not docket:
        logger.info(
            "[FAA LIFECYCLE] Docket unavailable for document %s",
            number,
        )
        return full_doc, "", False

    # 4. Search related Federal Register documents.
    if docket not in cache:
        response = safe_http_get(
            "https://www.federalregister.gov/api/v1/documents.json",
            source_id="SRC_001",
            params={
                "conditions[docket_id]": docket,
                "conditions[publication_date][lte]": as_of,
                "per_page": 100,
                "order": "newest",
                "fields[]": _FAA_LIFECYCLE_FIELDS,
            },
            timeout=12,
        )

        results = (
            response.json().get("results", [])
            if response is not None and response.status_code == 200
            else []
        )

        # Only rules/proposed rules determine this simplified
        # regulatory lifecycle. Notices are not silently promoted.
        relevant = [
            item for item in results
            if item.get("publication_date", "") <= as_of
            and str(item.get("type") or "").strip().upper()
            in {"RULE", "PROPOSED RULE", "PRORULE"}
        ]

        if relevant:
            newest = max(
                relevant,
                key=lambda item: (
                    item.get("publication_date", ""),
                    item.get("document_number", ""),
                ),
            )

            latest_num = str(newest.get("document_number") or "")

            # Fetch full metadata for the selected document.
            if latest_num:
                detail = safe_http_get(
                    f"https://www.federalregister.gov/api/v1/"
                    f"documents/{latest_num}.json",
                    source_id="SRC_001",
                    params={"fields[]": _FAA_LIFECYCLE_FIELDS},
                    timeout=12,
                )

                if detail is not None and detail.status_code == 200:
                    newest = {**newest, **detail.json()}

            cache[docket] = (newest, True)

            logger.info(
                "[FAA LIFECYCLE] Docket %s: %s -> %s",
                docket,
                number,
                latest_num,
            )

        else:
            cache[docket] = (full_doc, False)

            logger.warning(
                "[FAA LIFECYCLE] No verified rule found for docket %s",
                docket,
            )

    latest, checked = cache[docket]

    return latest, docket, checked

_EASA_PRIMARY_INDEX_PAGES = (
    "https://www.easa.europa.eu/en/domains/aircraft-products/"
    "airworthiness-directives-ad/safety-publications-tool-interim-solution",

    "https://www.easa.europa.eu/en/domains/aircraft-products/"
    "airworthiness-directives-ad/archive-airworthiness-directives",
)


def _easa_iso_date(value: str) -> str:
    """Normalize interim and archive publication dates."""

    value = str(value or "").strip()

    match = re.fullmatch(
        r"(\d{1,2})/(\d{1,2})/(20\d{2})",
        value,
    )

    if match:
        month, day, year = map(int, match.groups())

        try:
            return datetime(
                year, month, day
            ).strftime("%Y-%m-%d")

        except ValueError:
            return ""

    return normalize_date_str(value)


def _easa_applicability(
    query: str,
    subject: str,
    approved_types: str,
) -> str:
    """
    Distinguish aircraft-level from engine-level applicability.

    ENGINE_ONLY does not establish installation on a
    particular aircraft variant.
    """

    q = query.lower()
    text = f"{subject} {approved_types}".lower()

    gtf = (
        r"\b(?:gtf|pw1100g?(?:-jm)?|"
        r"pratt\s*(?:&|and)\s*whitney)\b"
    )

    trent = r"\btrent\s*1000\b"

    aircraft = (
        (
            r"\ba320(?:neo)?\b",
            r"\ba320(?:[-\s]|\b)",
        ),
        (
            r"\ba321(?:xlr|neo)?\b",
            r"\ba321(?:[-\s]|\b)",
        ),
        (
            r"\ba350\b",
            r"\ba350(?:[-\s]|\b)",
        ),
        (
            r"\b737\b",
            r"\b737(?:[-\s]|\b)",
        ),
        (
            r"\b787\b",
            r"\b787(?:[-\s]|\b)",
        ),
    )

    demanded_aircraft = [
        source_pattern
        for query_pattern, source_pattern in aircraft
        if re.search(query_pattern, q)
    ]

    aircraft_match = bool(
        demanded_aircraft
        and any(
            re.search(pattern, text)
            for pattern in demanded_aircraft
        )
    )

    if re.search(gtf, q):
        if not re.search(gtf, text):
            return "NONE"

    if re.search(trent, q):
        if not re.search(trent, text):
            return "NONE"

    engine_match = bool(
        (
            re.search(gtf, q)
            and re.search(gtf, text)
        )
        or (
            re.search(trent, q)
            and re.search(trent, text)
        )
    )

    if demanded_aircraft:

        if aircraft_match:
            return "AIRCRAFT"

        if engine_match:
            return "ENGINE_ONLY"

        return "NONE"

    if engine_match:
        return "ENGINE_ONLY"

    if re.search(r"\bairbus\b", q):
        if "airbus" not in text:
            return "NONE"

    if re.search(r"\bboeing\b", q):
        if "boeing" not in text:
            return "NONE"

    return "AIRCRAFT"


# def _easa_record_matches_kit(
#     query: str,
#     record: str,
# ) -> bool:
#     return (
#         _easa_applicability(
#             query,
#             record,
#             record,
#         ) != "NONE"
#     )


def _easa_parse_table(
    html_text: str,
    base_url: str,
) -> tuple[list[dict], str | None]:
    """Parse both EASA interim and archive table formats."""

    soup = BeautifulSoup(
        html_text,
        "html.parser",
    )

    records = []

    for table in soup.find_all("table"):

        headers = [
            re.sub(
                r"\s+",
                " ",
                h.get_text(" ", strip=True),
            ).lower()
            for h in table.select("thead th")
        ]

        if not headers:

            first = table.find("tr")

            headers = (
                [
                    h.get_text(" ", strip=True).lower()
                    for h in first.find_all(
                        "th",
                        recursive=False,
                    )
                ]
                if first else []
            )

        if not (
            "issue date" in headers
            and "subject" in headers
        ):
            continue

        number_col = (
            "number"
            if "number" in headers
            else "class number"
        )

        docs_col = (
            "attachment"
            if "attachment" in headers
            else "documents"
        )

        if (
            number_col not in headers
            or docs_col not in headers
        ):
            continue

        for tr in table.find_all("tr"):

            cells = tr.find_all(
                "td",
                recursive=False,
            )

            if len(cells) < len(headers):
                continue

            cols = {
                header: cells[i]
                for i, header in enumerate(headers)
            }

            number = cols[number_col].get_text(
                " ",
                strip=True,
            )

            # Exclude proposed ADs and unknown identifiers.
            if not re.fullmatch(
                r"20\d{2}-\d{4}(?:[RC]\d+)?",
                number,
            ):
                continue

            if "issued by" in cols:

                issuer = cols["issued by"].get_text(
                    " ",
                    strip=True,
                ).upper()

                if issuer != "EU":
                    continue

            if "ad class" in cols:

                ad_class = cols["ad class"].get_text(
                    " ",
                    strip=True,
                ).upper()

                if ad_class != "AD":
                    continue

            published = _easa_iso_date(
                cols["issue date"].get_text(
                    " ",
                    strip=True,
                )
            )

            if not published:
                continue

            subject = cols["subject"].get_text(
                " ",
                strip=True,
            )

            types = cols.get(
                "approval holder / type designation"
            )

            applicability = (
                types.get_text(" ", strip=True)
                if types else ""
            )

            effective = cols.get("effective date")

            effective_date = (
                _easa_iso_date(
                    effective.get_text(
                        " ",
                        strip=True,
                    )
                )
                if effective else ""
            )

            attachment = cols[docs_col]

            pdf_url = ""

            for a in attachment.find_all(
                "a",
                href=True,
            ):

                candidate = urljoin(
                    base_url,
                    a["href"],
                )

                host = (
                    urlparse(candidate).hostname or ""
                ).lower()

                official = (
                    host == "easa.europa.eu"
                    or host.endswith(".easa.europa.eu")
                )

                pdf = (
                    ".pdf" in candidate.lower()
                    or "pdf" in a.get_text(
                        " ",
                        strip=True,
                    ).lower()
                )

                if official and pdf:
                    pdf_url = candidate
                    break

            if not pdf_url:
                continue

            records.append({
                "number": number,
                "published": published,
                "subject": subject,
                "applicability": applicability,
                "effective": effective_date,
                "pdf_url": pdf_url,
            })

    # Follow only pagination links actually present
    # in the official HTML document.
    next_url = None

    for a in soup.find_all("a", href=True):

        label = a.get_text(
            " ",
            strip=True,
        ).lower()

        relation = str(
            a.get("rel", "")
        ).lower()

        if (
            label in {
                "next",
                "next ›",
                "next »",
                "›",
                "»",
            }
            or "next" in relation
        ):

            candidate = urljoin(
                base_url,
                a["href"],
            )

            if (
                urlparse(candidate).netloc
                == urlparse(base_url).netloc
            ):
                next_url = candidate
                break

    return records, next_url

def _easa_biweekly_csv_rows(
    index_html: str,
    base_url: str,
    max_archives: int = 8,
):
    """Read available official EASA biweekly CSV exports.

    Returns metadata, not verified PDF contents.
    """

    soup = BeautifulSoup(index_html, "html.parser")
    archive_urls = []

    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])

        if len(cells) < 4:
            continue

        for a in row.find_all("a", href=True):
            label = a.get_text(" ", strip=True).lower()

            if "csv" not in label and "cvs" not in label:
                continue

            target = urljoin(base_url, a["href"])
            host = (urlparse(target).hostname or "").lower()

            if (
                host == "easa.europa.eu"
                or host.endswith(".easa.europa.eu")
            ):
                archive_urls.append(target)

    archive_urls = list(
        dict.fromkeys(archive_urls)
    )[:max_archives]

    parsed = []
    issues = []

    for url in archive_urls:

        response = safe_http_get(
            url,
            source_id="SRC_002",
            timeout=15,
            max_bytes=10_000_000,
            check_robots=True,
        )

        if response is None or response.status_code != 200:
            issues.append("CSV_ARCHIVE_UNAVAILABLE")
            continue

        try:
            with zipfile.ZipFile(
                io.BytesIO(response.content)
            ) as z:

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
                        content = raw.decode(
                            "cp1252",
                            errors="replace",
                        )

                    dialect = csv.excel

                    try:
                        dialect = csv.Sniffer().sniff(
                            content[:3000],
                            delimiters=",;\t",
                        )
                    except csv.Error:
                        pass

                    reader = csv.DictReader(
                        io.StringIO(content),
                        dialect=dialect,
                    )

                    if not reader.fieldnames:
                        issues.append("CSV_HEADERS_MISSING")
                        continue

                    logger.info(
                        "[EASA CSV] Archive=%s columns=%s",
                        url,
                        reader.fieldnames,
                    )

                    for row in list(reader)[:4000]:

                        normalized = {
                            re.sub(
                                r"[^a-z0-9]+",
                                " ",
                                str(key or "").lower(),
                            ).strip(): str(value or "").strip()
                            for key, value in row.items()
                        }

                        flattened = " ".join(normalized.values())

                        match = re.search(
                            r"\b20\d{2}-\d{4}(?:[RC]\d+)?\b",
                            flattened,
                        )

                        if not match:
                            continue

                        def field(*names):
                            return next(
                                (
                                    value
                                    for key, value in normalized.items()
                                    if any(n in key for n in names)
                                    and value
                                ),
                                "",
                            )

                        issuer = field("issued by", "issuing state")
                        if issuer and issuer.strip().upper() not in {
                            "EU", "EASA"
                        }:
                            continue

                        published = _easa_iso_date(
                            field(
                                "issue date",
                                "publication date",
                                "date issued",
                            )
                        )

                        if not published:
                            continue

                        subject = field(
                            "subject",
                            "description",
                            "title",
                        )

                        types = field(
                            "approval holder",
                            "type designation",
                            "product",
                            "affected",
                        )

                        if not subject or not types:
                            continue

                        number = match.group(0)

                        parsed.append({
                            "number": number,
                            "published": published,
                            "subject": subject,
                            "applicability": types,
                            "effective": _easa_iso_date(
                                field("effective date")
                            ),
                            # Points to the exact official CSV archive.
                            # The fragment identifies the row conceptually;
                            # it is NOT a direct PDF link.
                            "pdf_url": url + "#ad=" + number,
                            "metadata_only": True,
                        })

        except (ValueError, OSError, zipfile.BadZipFile) as exc:
            issues.append(
                "CSV_ARCHIVE_INVALID:" + type(exc).__name__
            )

    if not archive_urls:
        issues.append("NO_BIWEEKLY_CSV_LINKS")

    return parsed, issues

def _collect_easa_primary_index(
    query: str,
    limit: int,
) -> tuple[str, int]:
    """
    Collect official EASA AD index metadata.

    Supports bounded historical pagination.
    Does not claim complete PDF extraction.
    """

    output = (
        ">> EASA OFFICIAL AD INDEX "
        "(METADATA ONLY; PDF NOT READ):\n"
    )

    accepted = 0
    examined = 0
    pages = 0

    seen_ad = set()
    failures = []

    start, end = get_time_window_utc()

    span = (
        (end - start).days
        if start else 365
    )

    max_archive_pages = min(
        40,
        max(
            1,
            int(
                os.getenv(
                    "EWS_EASA_ARCHIVE_MAX_PAGES",
                    "12" if span <= 90 else "35",
                )
            ),
        ),
    )

    index_html = ""

    for first_url in _EASA_PRIMARY_INDEX_PAGES[:1]:

        archive = (
            "archive-airworthiness-directives"
            in first_url
        )

        url = first_url
        visited = set()

        max_pages = (
            max_archive_pages if archive else 1
        )

        for _ in range(max_pages):

            if (
                not url
                or url in visited
                or accepted >= limit
            ):
                break

            visited.add(url)

            response = safe_http_get(
                url,
                source_id="SRC_002",
                timeout=12,
                check_robots=True,
                max_bytes=5_000_000,
            )

            if (
                response is None
                or response.status_code != 200
            ):
                failures.append(
                    f"HTTP/COMPLIANCE:{url}"
                )
                break

            index_html = response.text

            records, next_page = _easa_parse_table(
                response.text,
                url,
            )

            pages += 1
            examined += len(records)

            # Historical metadata from official biweekly CSV archives.
            if (
                    os.getenv("EWS_EASA_CSV_ENABLED", "0") == "1"
                    and index_html
                    and accepted < limit
            ):

                csv_rows, csv_issues = _easa_biweekly_csv_rows(
                    index_html,
                    _EASA_PRIMARY_INDEX_PAGES[0],
                )

                failures.extend(csv_issues)
                examined += len(csv_rows)

                for row in csv_rows:

                    if accepted >= limit:
                        break

                    if row["number"] in seen_ad:
                        continue

                    seen_ad.add(row["number"])

                    if not is_date_within_scope(row["published"]):
                        continue

                    applicability = _easa_applicability(
                        query,
                        row["subject"],
                        row["applicability"],
                    )

                    if applicability == "NONE":
                        continue

                    if row["pdf_url"] in COLLECTED_URLS:
                        continue

                    summary = (
                        "Official EASA biweekly CSV archive record. "
                        "This record is metadata only; "
                        "the corresponding AD PDF has NOT been read. "
                        f"EASA AD: {row['number']}. "
                        f"Issue date: {row['published']}. "
                        f"Subject: {row['subject']}. "
                        f"Type designation: {row['applicability']}. "
                        f"Applicability class: {applicability}. "
                        "Technical requirements and operational "
                        "effects require direct PDF verification."
                    )

                    doc = register_collected_document(
                        source_id="SRC_002",
                        connector_name="EASA Biweekly CSV Archive",
                        url=row["pdf_url"],
                        title=(
                            f"EASA AD {row['number']}: "
                            f"{row['subject']}"
                        ),
                        raw_text=summary,
                        published_at=row["published"],
                        query_used=query,
                    )

                    doc["origin_type"] = (
                        "PRIMARY_OFFICIAL_INDEX_METADATA"
                    )

                    doc["regulatory_applicability_scope"] = (
                        applicability
                    )

                    doc["verified_domain"] = True

                    output += (
                        f"DOC_ID: {doc['doc_id']} "
                        "| SOURCE_ID: SRC_002\n"
                        f"DATE: {doc['published_at']}\n"
                        f"Title: {doc['title']}\n"
                        f"Link: {doc['url']}\n"
                        f"Summary: {doc['text']}\n---\n"
                    )

                    accepted += 1

                logger.info(
                    "[EASA CSV AUDIT] parsed=%d accepted_total=%d "
                    "issues=%s",
                    len(csv_rows),
                    accepted,
                    csv_issues or "none",
                )

            # Historical source coverage remains incomplete unless
            # a complete archive has been independently established.
            # The currently available index does not
            # necessarily cover the entire requested period.
            # CSV availability alone does not prove coverage.

            dated_rows = [
                str(r.get("published", ""))
                for r in records
                if re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}",
                    str(r.get("published", "")),
                )
            ]

            oldest_index_date = min(
                dated_rows,
                default="",
            )

            if (
                    start
                    and oldest_index_date
                    and start.date().isoformat()
                    < oldest_index_date
                    and "HISTORICAL_COVERAGE_NOT_ESTABLISHED"
                    not in failures
            ):
                failures.append(
                    "HISTORICAL_COVERAGE_NOT_ESTABLISHED"
                )

            logger.info(
                "[EASA PRIMARY AUDIT] "
                "page=%s extracted_rows=%d next=%s",
                url,
                len(records),
                bool(next_page),
            )

            if not records:

                failures.append(
                    f"NO_PARSEABLE_ROWS:{url}"
                )

                break

            for row in records:

                if accepted >= limit:
                    break

                if row["number"] in seen_ad:
                    continue

                seen_ad.add(row["number"])

                if not is_date_within_scope(
                    row["published"]
                ):
                    continue

                scope = _easa_applicability(
                    query,
                    row["subject"],
                    row["applicability"],
                )

                if scope == "NONE":
                    continue

                if (
                    row["pdf_url"]
                    in COLLECTED_URLS
                ):
                    continue

                if scope == "ENGINE_ONLY":

                    note = (
                        "ENGINE-LEVEL AD: aircraft "
                        "installation NOT established "
                        "by this index."
                    )

                else:

                    note = (
                        "AIRCRAFT-LEVEL AD: exact variant "
                        "and technical applicability "
                        "require PDF review."
                    )

                text = (
                    "Official EASA index entry; "
                    "PDF text NOT extracted. "
                    f"EASA AD: {row['number']}. "
                    f"Issued: {row['published']}. "
                    f"Subject: {row['subject']}. "
                    "Approval Holder / Type Designation: "
                    f"{row['applicability']}. "
                    "Effective date: "
                    f"{row['effective'] or 'UNKNOWN'}. "
                    f"Applicability class: {scope}. "
                    f"{note}"
                )

                doc = register_collected_document(
                    source_id="SRC_002",
                    connector_name="EASA Official Index",
                    url=row["pdf_url"],
                    title=(
                        f"EASA AD {row['number']}: "
                        f"{row['subject']}"
                    ),
                    raw_text=text,
                    published_at=row["published"],
                    query_used=query,
                )

                doc["origin_type"] = (
                    "PRIMARY_OFFICIAL_INDEX_METADATA"
                )

                doc["verified_domain"] = True

                doc[
                    "regulatory_applicability_scope"
                ] = scope

                output += (
                    f"DOC_ID: {doc['doc_id']} "
                    "| SOURCE_ID: SRC_002\n"
                    f"DATE: {doc['published_at']}\n"
                    f"Title: {doc['title']}\n"
                    f"Link: {doc['url']}\n"
                    f"Summary: {doc['text']}\n---\n"
                )

                accepted += 1

            if (
                archive
                and not next_page
                and len(records) >= 25
                and accepted < limit
            ):

                failures.append(
                    "ARCHIVE_NEXT_PAGE_NOT_DISCOVERED"
                )

            # Stop when the entire page is older
            # than the requested period.
            if (
                archive
                and start
                and records
                and all(
                    r["published"]
                    < start.date().isoformat()
                    for r in records
                )
            ):

                url = None

            else:

                url = (
                    next_page
                    if archive else None
                )

        if (
            archive
            and len(visited) >= max_pages
            and url
            and accepted < limit
        ):

            failures.append(
                "ARCHIVE_PAGINATION_BUDGET_EXHAUSTED"
            )

    logger.info(
        "[EASA PRIMARY AUDIT] "
        "accepted=%d examined=%d pages=%d issues=%s",
        accepted,
        examined,
        pages,
        failures or "none",
    )

    if failures:

        logger.warning(
            "[EASA COVERAGE] "
            "Partial or unavailable official archive: %s",
            failures,
        )

    record_connector_telemetry(
        "EASA Official Index",
        "SRC_002",
        query,
        examined,
        accepted,
        0,
        error=(
            "; ".join(failures)
            if failures else ""
        ),
    )

    return (
        output if accepted else "",
        accepted,
    )

# Collect FAA/EASA material using the configured official-source access methods.
@tool("Scrape EASA and FAA Regulations")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_regulatory_agencies(query: str = "Airbus") -> str:
    """Retrieve airworthiness directives and regulatory notices from FAA and EASA."""
    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    scope_days = get_scope_days()
    required_words, search_term = parse_query_intent(query)
    search_term = re.sub(
        r"\b(?:FAA|EASA|NTSB)\b", "", search_term, flags=re.I
    ).strip() or query

    logger.info(f"[OSINT GATHERER] Querying FAA and EASA databases for: '{query}' (limit: {limit}, scope: {scope_days or 'all'} days)")
    extracted_text = f"--- REGULATORY DIRECTIVES AND NOTICES (FAA & EASA) FOR '{query}' ---\n"

    try:
        params: Dict[str, Any] = {
            "conditions[term]": search_term,
            "conditions[agencies][]": "federal-aviation-administration",
            "order": "newest",
            "per_page": limit * 3,
            "conditions[publication_date][lte]": end_utc.strftime("%Y-%m-%d"),
        }
        if start_utc is not None:
            params["conditions[publication_date][gte]"] = start_utc.strftime("%Y-%m-%d")

        faa_url = (
            "https://www.federalregister.gov"
            "/api/v1/documents.json"
        )

        resp = safe_http_get(
            faa_url,
            source_id="SRC_001",
            params=params,
            timeout=12,
        )

        if resp is not None and resp.status_code == 200:
            docs = resp.json().get("results", []) or []

            if not docs:
                entity = lookup_supplier_in_registry(query)

                broad_term = (
                    re.sub(
                        r"\s*\([^)]*\)",
                        "",
                        entity["official_name"],
                    ).strip()
                    if entity
                    else next(iter(_model_tokens(query)), "")
                )

                if (
                        broad_term
                        and broad_term.casefold()
                        != search_term.casefold()
                ):
                    broad_params = {
                        **params,
                        "conditions[term]": broad_term,
                    }

                    broad_resp = safe_http_get(
                        faa_url,
                        source_id="SRC_001",
                        params=broad_params,
                        timeout=12,
                    )

                    if (
                            broad_resp is not None
                            and broad_resp.status_code == 200
                    ):
                        docs = (
                                broad_resp.json().get("results", [])
                                or []
                        )

                        logger.info(
                            "[FAA RECALL] Broad query %r "
                            "returned %d records",
                            broad_term,
                            len(docs),
                        )
            faa_count = faa_rejected = 0
            docket_cache: Dict[str, Tuple[Dict[str, Any], bool]] = {}
            faa_block = ">> FAA (Federal Aviation Administration - Federal Register):\n"

            for found_doc in docs:
                if faa_count >= limit:
                    break

                title = str(found_doc.get("title") or "")
                abstract = str(found_doc.get("abstract") or "")

                if not any(rw in f"{title} {abstract}".lower()
                           for rw in required_words):
                    continue

                doc, docket, checked = _faa_resolve_docket(
                    found_doc,
                    end_utc.strftime("%Y-%m-%d"),
                    docket_cache
                )

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

                is_proposed = (
                        doc_type in {"PRORULE", "PROPOSED RULE"}
                        or "notice of proposed rulemaking" in action
                        or action.startswith("proposed rule")
                )

                is_final = (
                        doc_type == "RULE"
                        or action.startswith("final rule")
                )

                if is_proposed:
                    stage = "PROPOSED"

                elif is_final:
                    if effective_on and effective_on <= end_utc.strftime("%Y-%m-%d"):
                        stage = "EFFECTIVE"
                    else:
                        stage = "FINAL_ISSUED"

                else:
                    stage = "UNKNOWN"

                summary = str(doc.get("abstract") or "").replace(
                    "\n", " "
                ).strip()

                old_url = found_doc.get("html_url") or ""
                history = (
                    f"Related earlier document: {old_url}\n"
                    if old_url and old_url != link else ""
                )

                raw_text = (
                    f"Regulatory Stage: {stage}\n"
                    f"Regulatory Lifecycle Check: "
                    f"{'VERIFIED' if checked else 'UNVERIFIED'}\n"
                    f"FAA Docket: {docket or 'UNKNOWN'}\n"
                    f"Federal Register Document: "
                    f"{doc.get('document_number', 'UNKNOWN')}\n"
                    f"Effective Date: {effective_on or 'UNKNOWN'}\n"
                    f"{history}"
                    f"Official Summary: {summary[:850]}"
                )

                doc_rec = register_collected_document(
                    source_id="SRC_001",
                    connector_name="FAA Federal Register",
                    url=link,
                    title=doc.get("title") or title,
                    raw_text=raw_text,
                    published_at=pub_date,
                    query_used=query,
                )

                faa_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_001\n"
                    f"DATE: {doc_rec['published_at']}\n"
                    f"Document Type: {doc_type} | Regulatory Stage: {stage}\n"
                    f"Title: {doc_rec['title']}\n"
                    f"Link: {link}\n"
                    f"Summary: {doc_rec['text']}\n---\n"
                )

                faa_count += 1
            record_connector_telemetry("FAA Federal Register", "SRC_001", query, len(docs), faa_count, faa_rejected)
            if faa_count > 0:
                extracted_text += faa_block
    except Exception as e:
        logger.error(f"[OSINT GATHERER] Federal Register FAA API error: {e}")
        record_connector_telemetry("FAA Federal Register", "SRC_001", query, error=str(e))

    # Current official EASA interim index + RSS fallback.
    # Experimental historical CSV collection remains disabled.
    primary_count = 0

    try:
        primary_block, primary_count = _collect_easa_primary_index(
            query,
            limit,
        )

        if primary_count:
            extracted_text += primary_block

    except Exception as exc:
        logger.warning(
            "[EASA INTERIM INDEX] Unavailable: %s. Using RSS fallback.",
            exc,
        )

        record_connector_telemetry(
            "EASA Official Index",
            "SRC_002",
            query,
            error=str(exc),
        )

    try:
        time_filter = f" when:{scope_days}d" if scope_days else ""
        easa_query = urllib.parse.quote(
            f"site:easa.europa.eu {search_term}{time_filter}"
        )
        easa_feed_url = f"https://news.google.com/rss/search?q={easa_query}&hl=en-US&gl=US&ceid=US:en"
        easa_resp = safe_http_get(easa_feed_url, source_id="SRC_002", timeout=10)
        feed = feedparser.parse(easa_resp.content) if (easa_resp and easa_resp.status_code == 200) else None
        if feed and feed.entries:
            easa_count = easa_rejected = 0
            easa_block = ">> EASA (European Union Aviation Safety Agency Monitor):\n"
            for entry in feed.entries:
                if easa_count >= max(0, limit - primary_count):
                    break
                link = entry.get("link", "https://www.easa.europa.eu")
                if link in COLLECTED_URLS:
                    continue

                pub_date = entry.get("published", "DATE_UNKNOWN")
                if not is_date_within_scope(pub_date):
                    easa_rejected += 1
                    continue
                title = entry.get("title", "Untitled EASA notice")
                clean_desc = BeautifulSoup(entry.get("description", ""), "html.parser").get_text(" ", strip=True)[:400]
                if not any(rw in f"{title} {clean_desc}".lower() for rw in required_words):
                    continue
                if not any(rw in f"{title} {clean_desc}".lower() for rw in required_words):
                    continue

                doc_rec = register_collected_document(
                    source_id="SRC_002",
                    connector_name="EASA Regulatory Monitor",
                    url=link,
                    title=title,
                    raw_text=clean_desc or title,
                    published_at=pub_date,
                    query_used=query,
                )
                easa_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_002\n"
                    f"DATE: {doc_rec['published_at']}\nTitle: {doc_rec['title']}\n"
                    f"Link: {link}\nSummary: {doc_rec['text']}\n---\n"
                )
                easa_count += 1
            record_connector_telemetry("EASA Regulatory Monitor", "SRC_002", query, len(feed.entries), easa_count, easa_rejected)
            if easa_count > 0:
                extracted_text += easa_block
    except Exception as e:
        logger.error(f"[OSINT GATHERER] EASA RSS query error: {e}")
        record_connector_telemetry("EASA Regulatory Monitor", "SRC_002", query, error=str(e))

    if "Title:" not in extracted_text:
        return f"No specific records found in FAA or EASA databases for '{query}' within the selected time scope."

    logger.warning(f"[OSINT DEBUG] Regulatory module returned records for '{query}'.")
    return extracted_text


# Retrieve manufacturer announcements while preserving their primary-source status.
@tool("Scrape Manufacturer PR News")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_manufacturer_pr_news(query: str = "Aviation") -> str:
    """Fetch official press releases from Airbus, Boeing, and COMAC feeds."""
    original_query = query.replace(",", "").replace("  ", " ").strip()
    _, safe_query = parse_query_intent(original_query)
    limit_per_feed = get_dynamic_limit()
    scope_days = get_scope_days()
    time_filter = f" when:{scope_days}d" if scope_days else ""

    logger.info(
        f"[OSINT GATHERER] Fetching manufacturer PR feeds for: '{safe_query}' (limit: {limit_per_feed}, scope: {scope_days or 'all'} days)"
    )

    extracted_text = f"--- OFFICIAL MANUFACTURER PRESS RELEASES FOR '{safe_query}' ---\n"
    query_lower = safe_query.lower()

    def _rss_url(site_expr: str) -> str:
        core = re.sub(
            r"\b(?:Airbus|Boeing|COMAC)\b", "",
            original_query, flags=re.I
        ).strip() or safe_query
        q = urllib.parse.quote(f"{site_expr} {core}{time_filter}")
        return f"https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en"

    feeds = {
        "Airbus": _rss_url("site:airbus.com"),
        "Boeing": _rss_url("(site:boeing.mediaroom.com OR site:boeing.com)"),
        "COMAC": _rss_url("(site:comac.cc OR site:english.comac.cc)"),
    }

    mentioned = {
        name for name in feeds
        if re.search(rf"\b{re.escape(name)}\b", original_query, re.I)
    }
    if mentioned:
        feeds = {name: url for name, url in feeds.items() if name in mentioned}

    total_processed = found_total = rejected_total = 0
    noise_tokens = ("#shorts", "compilation", "takeoff", "landing", "cabin", "trip report", "flight simulator", "msfs")

    for brand, url in feeds.items():
        try:
            resp = safe_http_get(url, source_id="SRC_005", timeout=12)
            if resp is None or resp.status_code != 200:
                continue
            feed = feedparser.parse(resp.content)
            if not feed.entries:
                continue

            brand_block = f"\n>> {brand} Official Newsroom:\n"
            brand_count = 0
            for entry in feed.entries:
                found_total += 1
                if brand_count >= limit_per_feed:
                    break

                link = entry.get("link", f"https://www.{brand.lower()}.com")
                if link in COLLECTED_URLS:
                    continue

                pub_date = entry.get("published", "DATE_UNKNOWN")
                if not is_date_within_scope(pub_date):
                    rejected_total += 1
                    continue

                title = entry.get("title", "Untitled release")
                if any(k in title.lower() for k in noise_tokens):
                    continue

                desc = BeautifulSoup(entry.get("description", ""), "html.parser").get_text(" ", strip=True)[:400]
                doc_rec = register_collected_document(
                    source_id="SRC_005",
                    connector_name="Manufacturer PR",
                    url=link,
                    title=title,
                    raw_text=desc or title,
                    published_at=pub_date,
                    query_used=original_query,
                )
                brand_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_005\n"
                    f"DATE: {doc_rec['published_at']}\nTitle: {doc_rec['title']}\n"
                    f"Link: {link}\nSummary: {doc_rec['text']}\n---\n"
                )
                brand_count += 1
                total_processed += 1

            if brand_count > 0:
                extracted_text += brand_block
        except Exception as e:
            logger.error(f"[OSINT GATHERER] PR feed error for {brand}: {str(e)}")

    record_connector_telemetry("Manufacturer PR", "SRC_005", safe_query, found_total, total_processed, rejected_total)
    if total_processed == 0:
        return f"No official manufacturer press releases found for '{query}' within the selected time scope."

    logger.warning(f"[OSINT DEBUG] PR module downloaded {total_processed} releases.")
    return extracted_text


# Treat social-network posts as preliminary signals requiring corroboration.
@tool("Search Aviation Bluesky")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def search_bluesky_aviation(query: str) -> str:
    """Search Bluesky posts via AT Protocol and filter out automated flight tracking bots."""
    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    logger.info(f"[OSINT GATHERER] Querying Bluesky API for: '{query}' (limit: {limit})")

    handle, password = os.getenv("BLUESKY_HANDLE"), os.getenv("BLUESKY_PASSWORD")
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AeroEWS/2.0"}

    if handle and password:
        try:
            auth_resp = requests.post(
                "https://bsky.social/xrpc/com.atproto.server.createSession",
                json={"identifier": handle, "password": password},
                timeout=10,
            )
            auth_resp.raise_for_status()
            headers["Authorization"] = f"Bearer {auth_resp.json().get('accessJwt')}"
        except Exception as e:
            logger.error(f"[OSINT DEBUG] Bluesky authentication failed: {e}")
            record_connector_telemetry("Bluesky Social Network", "SRC_007", query, error=str(e))
            return "Bluesky authentication failed."

    params: Dict[str, Any] = {
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
            record_connector_telemetry("Bluesky Social Network", "SRC_007", query, error="Blocked or unauthorized")
            return "Bluesky request blocked by server."

        response.raise_for_status()
        posts = response.json().get("posts", []) or []

        logger.info(
            "[BLUESKY AUDIT] HTTP=%s raw_posts=%d query=%r",
            response.status_code,
            len(posts),
            query,
        )

        # One bounded fallback if the original query found no posts.
        if not posts and len(query.split()) >= 4:
            _, short_query = parse_query_intent(query)

            if (
                    short_query
                    and short_query.casefold() != query.casefold()
            ):
                fallback_response = safe_http_get(
                    "https://bsky.social/xrpc/app.bsky.feed.searchPosts",
                    source_id="SRC_007",
                    params={**params, "q": short_query},
                    headers=headers,
                    timeout=15,
                )

                if (
                        fallback_response is not None
                        and fallback_response.status_code == 200
                ):
                    posts = (
                            fallback_response.json().get("posts", [])
                            or []
                    )

                    logger.info(
                        "[BLUESKY FALLBACK] q=%r raw_posts=%d",
                        short_query,
                        len(posts),
                    )

        extracted_text = f"--- BLUESKY POSTS FOR '{query}' ---\n"

        count = rejected_scope = 0
        rejected_bots = rejected_duplicates = 0
        seen_post_texts = set()
        bot_keywords = ("acarsdrama", "tlsflights", "adsbexchange", "adsb.fi", "air to ground message:")

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
                if (uri and "/" in uri)
                else f"https://bsky.app/search?q={urllib.parse.quote(query)}"
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
                source_id="SRC_007",
                connector_name="Bluesky Social Network",
                url=post_url,
                title="Bluesky community aviation signal (pseudonymized)",
                raw_text=text,
                published_at=pub_date,
                query_used=query,
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
            "[BLUESKY FILTER AUDIT] "
            "raw=%d kept=%d out_of_scope_or_personal=%d "
            "bots=%d duplicates_or_empty=%d",
            len(posts),
            count,
            rejected_scope,
            rejected_bots,
            rejected_duplicates,
        )

        record_connector_telemetry(
            "Bluesky Social Network",
            "SRC_007",
            query,
            len(posts),
            count,
            rejected_scope,
        )
        if count == 0:
            return f"No relevant Bluesky posts found for '{query}'."

        logger.warning(f"[OSINT DEBUG] Bluesky API returned {count} filtered posts.")
        return extracted_text
    except Exception as e:
        logger.error(f"[OSINT GATHERER] Bluesky fetch error: {str(e)}")
        record_connector_telemetry("Bluesky Social Network", "SRC_007", query, error=str(e))
        return "Unable to connect to Bluesky server."


_AIRSHOW_IRRELEVANT_PATHS = (
    "/visit/", "/attractions/", "/beauty-n-wellness/", "/shopping/",
    "/accommodation/", "/dining/", "/restaurants/", "/ticketing/", "/hospitality-packages/",
)


# Collect event/exhibition announcements relevant to the requested aerospace program.
@tool("Scrape Airshow Website")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_airshow_website(query: str = "Airbus") -> str:
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
                if (route.request.resource_type in ("image", "media", "font") or "cookiebot.com" in route.request.url.lower())
                else route.continue_(),
            )

            effective_max_pages = 1 if (fast_mode or (scope_days is not None and scope_days <= 14)) else MAX_PAGES_PER_AIRSHOW

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
                        urls_to_check = [f"https://www.siae.fr/en/?s={encoded_query}"] + [
                            f"https://www.siae.fr/en/page/{p_no}/?s={encoded_query}"
                            for p_no in range(2, effective_max_pages + 1)
                        ]
                    elif "singaporeairshow.com" in url:
                        base_sg = f"https://www.singaporeairshow.com/cos/o.x?func=search&c=/qql/pagetree&rid=453&search_str={encoded_query}"
                        urls_to_check = [base_sg] + [f"{base_sg}&pageno={p_no}" for p_no in range(2, effective_max_pages + 1)]
                    else:
                        urls_to_check = [url]

                    all_raw_texts, candidate_links, visited_listing_urls = [], [], set()
                    idx = 0
                    while idx < len(urls_to_check) and len(visited_listing_urls) < (effective_max_pages + 1):
                        target_url = urls_to_check[idx]
                        idx += 1
                        if target_url in visited_listing_urls:
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

                    filtered_overview = filter_relevant_paragraphs("\n".join(all_raw_texts), required_words)
                    link_date_map = {l["url"]: l.get("date", "") for l in candidate_links if l.get("date")}
                    num_words = [rw for rw in required_words if any(c.isdigit() for c in rw)]
                    tier1_links, tier2_links, tier3_links = [], [], []
                    min_req = min(2, len(required_words))

                    for l in candidate_links:
                        t_text = f"{l['title']} {l['url']}".lower()
                        c_text = l["context"].lower()
                        if any(nw in t_text for nw in num_words) or sum(1 for rw in required_words if rw in t_text) >= min_req:
                            tier1_links.append(l["url"])
                        elif any(nw in c_text for nw in num_words) or sum(1 for rw in required_words if rw in c_text) >= min_req:
                            tier2_links.append(l["url"])
                        elif any(rk in c_text or rk in l["url"].lower() for rk in AIRSHOW_ROUNDUP_KEYWORDS):
                            tier3_links.append(l["url"])

                    remaining_slots = max(1, user_limit - total_articles)
                    if num_words or (scope_days is not None and scope_days <= 14):
                        links_to_open = list(dict.fromkeys(tier1_links + tier2_links))[:remaining_slots]
                    else:
                        links_to_open = list(dict.fromkeys(tier1_links + tier2_links + tier3_links))[: (remaining_slots + 2)]

                    deep_articles_output, seen_article_bodies = [], set()

                    for article_url in links_to_open:
                        if total_articles >= user_limit:
                            break
                        if article_url in COLLECTED_URLS:
                            continue

                        pre_date = link_date_map.get(article_url, "") or normalize_date_str(article_url)
                        if scope_days is not None and pre_date and not is_date_within_scope(pre_date):
                            rejected_scope += 1
                            continue

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
                                    logger.info(f"[OSINT DEBUG] Article {article_url} ({pub_date}) skipped (outside time scope).")
                                    continue

                                seen_article_bodies.add(body_hash)
                                doc_rec = register_collected_document(
                                    source_id="SRC_006",
                                    connector_name="Airshow Websites",
                                    url=article_url,
                                    title=f"{airshow_name} Newsroom Article",
                                    raw_text=art_filtered[:2500],
                                    published_at=pub_date,
                                    query_used=safe_query,
                                )
                                deep_articles_output.append(
                                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_006\n"
                                    f"DATE: {doc_rec['published_at']}\nLink: {article_url}\nArticle Content:\n{doc_rec['text']}"
                                )
                                total_articles += 1
                        except Exception as art_e:
                            logger.debug(f"Could not load article {article_url}: {art_e}")

                    final_airshow_sections = list(deep_articles_output)
                    if not final_airshow_sections and len(filtered_overview) >= 120 and total_articles < user_limit and url not in COLLECTED_URLS:
                        overview_date = normalize_date_str(filtered_overview) or "DATE_UNKNOWN"
                        if overview_date == "DATE_UNKNOWN":
                            unknown_dates += 1
                        if is_date_within_scope(overview_date):
                            doc_rec = register_collected_document(
                                source_id="SRC_006",
                                connector_name="Airshow Websites",
                                url=url,
                                title=f"{airshow_name} News Overview",
                                raw_text=filtered_overview[:2000],
                                published_at=overview_date,
                                query_used=safe_query,
                            )
                            final_airshow_sections.append(
                                f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_006\n"
                                f"DATE: {doc_rec['published_at']}\nLink: {url} (News Overview)\nContent:\n{doc_rec['text']}"
                            )
                            total_articles += 1

                    if final_airshow_sections:
                        extracted_text += f"\n>> News from {airshow_name} ({url}):\n" + "\n\n".join(final_airshow_sections) + "\n---\n"
                        processed_shows += 1
                    else:
                        extracted_text += f"\n>> {airshow_name} ({url}): No articles found for '{safe_query}' within the selected time scope.\n---\n"

                except Exception as e:
                    logger.error(f"[OSINT GATHERER] Error scraping {airshow_name}: {e}")
                    extracted_text += f"\n>> {airshow_name} ({url}): Failed to load content ({str(e)})\n---\n"

            browser.close()

    except Exception as e:
        logger.error(f"[OSINT GATHERER] Playwright error: {e}")
        record_connector_telemetry("Airshow Websites", "SRC_006", safe_query, error=str(e))
        return f"Fatal browser launch error: {e}"

    record_connector_telemetry(
        "Airshow Websites", "SRC_006", safe_query, total_articles + rejected_scope, total_articles, rejected_scope, unknown_dates
    )
    if processed_shows == 0:
        return f"No information found for '{safe_query}' on any monitored airshow websites within the selected time scope."

    logger.warning(f"[OSINT DEBUG] Extracted {total_articles} articles across {processed_shows} airshows (limit: {user_limit}).")
    return extracted_text


YOUTUBE_CACHE_FILE = "youtube_transcript_cache.json"
_YT_CACHE_LOCK = threading.Lock()


# Load cached transcripts to avoid repeated external retrieval.
def _load_yt_transcript_cache() -> Dict[str, str]:
    if not os.path.exists(YOUTUBE_CACHE_FILE):
        return {}
    try:
        with _YT_CACHE_LOCK, open(YOUTUBE_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# Persist transcript text for reuse in subsequent document collection.
def _save_yt_transcript_cache(video_id: str, transcript: str) -> None:
    if not video_id or not transcript or len(transcript) < 60:
        return
    cache = _load_yt_transcript_cache()
    cache[video_id] = transcript[:5000]
    try:
        with _YT_CACHE_LOCK, open(YOUTUBE_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.debug(f"[YT CACHE] Could not write transcript cache: {e}")


# Extract public video transcripts as unverified source content, not established facts.
@tool("Search and Extract YouTube")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def extract_youtube_transcript(query: str) -> str:
    """Search YouTube for aviation videos, pre-filter by KIT relevance, and use local transcript caching before Gemini."""
    if not YOUTUBE_API_KEY or not GEMINI_API_KEY:
        record_connector_telemetry("YouTube Videos", "SRC_008", query, error="Missing API keys")
        return "Error: Missing YOUTUBE_API_KEY or GEMINI_API_KEY in .env."

    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    required_words, _ = parse_query_intent(query)
    _, search_term = parse_query_intent(query)
    search_term = re.sub(
        r"\b(?:FAA|EASA|NTSB)\b", "",
        search_term, flags=re.I
    ).strip() or query
    num_model_words = [rw for rw in required_words if any(c.isdigit() for c in rw)]

    logger.info(f"[OSINT GATHERER] Querying YouTube Data API v3 for: '{query}' (limit: {limit})")

    search_params: Dict[str, Any] = {
        "part": "snippet",
        "q": f"{query} -shorts -compilation -landing -takeoff -flightsimulator -msfs",
        "type": "video",
        "videoDuration": "medium",
        "maxResults": min(20, limit * 3),
        "relevanceLanguage": "en",
        "key": YOUTUBE_API_KEY,
        "publishedBefore": end_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if start_utc is not None:
        search_params["publishedAfter"] = start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        search_resp = safe_http_get("https://www.googleapis.com/youtube/v3/search", source_id="SRC_008", params=search_params, timeout=10)
        if search_resp is None or search_resp.status_code != 200:
            record_connector_telemetry("YouTube Videos", "SRC_008", query, error="YouTube API HTTP failure")
            return "Error fetching video data from API."

        videos, rejected_scope = [], 0
        yt_noise = ("#shorts", "compilation", "1:200", "1:400", "scale model", "msfs", "flight simulator", "trip report")

        for item in search_resp.json().get("items", []):
            vid_id = item["id"]["videoId"]
            vid_url = f"https://www.youtube.com/watch?v={vid_id}"
            if vid_url in COLLECTED_URLS:
                continue

            title = html.unescape(item["snippet"]["title"])
            desc = html.unescape(item["snippet"].get("description", ""))
            combined_meta_low = f"{title} {desc}".lower()

            if (
                any(noise in combined_meta_low for noise in yt_noise)
                or (num_model_words and not any(mw in combined_meta_low for mw in num_model_words))
                or not is_date_within_scope(item["snippet"]["publishedAt"])
            ):
                rejected_scope += 1
                continue

            raw_date = item["snippet"]["publishedAt"]
            videos.append({
                "id": vid_id,
                "title": title,
                "channel": item["snippet"]["channelTitle"],
                "desc": desc,
                "date": raw_date.split("T")[0] if "T" in raw_date else raw_date,
                "url": vid_url,
            })
            if len(videos) >= limit:
                break

        if not videos:
            record_connector_telemetry("YouTube Videos", "SRC_008", query, 0, 0, rejected_scope)
            return f"No relevant news videos found on YouTube for '{query}' within the selected time scope."

        extracted_text = f"--- RAW VIDEO TRANSCRIPTS FOR '{query}' ---\n"
        processed_videos = gemini_calls_made = 0
        max_gemini_transcriptions = 2
        yt_cache = _load_yt_transcript_cache()
        client = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options=types.HttpOptions(
                timeout=30_000,
                retry_options=types.HttpRetryOptions(attempts=1)
            )
        )
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
                        else YouTubeTranscriptApi.get_transcript(
                            v["id"], languages=["en", "en-US", "en-GB"]
                        )
                    )
                    transcript_text = re.sub(r"\s+", " ", " ".join(seg.get("text", "") for seg in ts_segments)).strip()[:5000]
                    _save_yt_transcript_cache(v["id"], transcript_text)
                    logger.info(f"[OSINT GATHERER] Fast transcript fetched via YouTubeTranscriptApi for {v['id']}.")
                except Exception as yt_err:
                    if gemini_calls_made >= max_gemini_transcriptions:
                        logger.info(f"[OSINT GATHERER] Skipping slow Gemini audio transcription for {v['id']} (budget {max_gemini_transcriptions} reached).")
                        continue
                    logger.debug(f"YouTubeTranscriptApi failed for {v['id']} ({yt_err}), falling back to Gemini.")
                    used_gemini_fallback = True
                    gemini_calls_made += 1
                    try:
                        response = client.models.generate_content(
                            model="gemini-3.5-flash-lite",
                            contents=types.Content(
                                parts=[
                                    types.Part(file_data=types.FileData(file_uri=v["url"])),
                                    types.Part(text=transcript_prompt),
                                ]
                            ),
                        )
                        if response.text:
                            transcript_text = response.text.replace("\n", " ")[:5000]
                            _save_yt_transcript_cache(v["id"], transcript_text)
                        else:
                            transcript_text = f"(No transcript returned by Gemini. Video description used): {v['desc']}"
                    except Exception as e:
                        logger.warning(f"Gemini API rate limit or error on video {v['id']}: {str(e)[:50]}")
                        transcript_text = f"(Transcript unavailable. Video description used): {v['desc']}" if v["desc"] else ""

            if "♪" in transcript_text or len(transcript_text.strip()) < 60:
                if used_gemini_fallback:
                    time.sleep(1)
                continue

            doc_rec = register_collected_document(
                source_id="SRC_008",
                connector_name="YouTube Videos",
                url=v["url"],
                title=f"{v['title']} ({v['channel']})",
                raw_text=transcript_text,
                published_at=v["date"],
                query_used=query,
            )
            extracted_text += (
                f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_008\n"
                f"DATE: {doc_rec['published_at']}\nTitle: {v['title']}\nChannel: {v['channel']}\n"
                f"Link: {v['url']}\nVideo Transcript: {doc_rec['text']}\n---\n"
            )
            processed_videos += 1

            if used_gemini_fallback:
                time.sleep(2)

        record_connector_telemetry("YouTube Videos", "SRC_008", query, len(videos), processed_videos, rejected_scope)
        logger.info(f"[OSINT GATHERER] YouTube processing completed for {processed_videos} videos.")
        return extracted_text

    except Exception as e:
        logger.error(f"[OSINT GATHERER] YouTube API error: {str(e)}")
        record_connector_telemetry("YouTube Videos", "SRC_008", query, error=str(e))
        return "Error fetching video data from API."