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
import urllib.parse
import urllib.robotparser
import zipfile
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
import unicodedata

load_dotenv()
logger = logging.getLogger(__name__)

NEWS_API_KEY = os.getenv("NEWS_API_KEY")
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


# Provide a normalized UTC timestamp for report metadata and audit records.
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


# Configured access and collection policy statuses for sources.
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
            "name": "FAA Federal Register", "domain": "federalregister.gov",
            "source_type": "REGULATORY", "origin": "PRIMARY", "access_method": "API",
            "allowed_access_method": "API (Official REST Endpoint)",
            "tos_url": "https://www.federalregister.gov/reader-aids/government-policy-and-ofr-procedures/developer-resources",
            "usage_restrictions": "Public domain (17 U.S.C. 105); unrestricted retention, processing, and internal/external redistribution.",
            "tdm_copyright_basis": "Public Domain (No copyright / TDM restrictions)",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (official regulatory records; minimal personal data)",
            "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "US Government Public Domain / Federal Register API",
            "rate_limit_rpm": 30, "min_interval_sec": 1.0,
        },
        "SRC_002": {
            "name": "EASA Safety & Regulatory Monitor (via RSS Proxy)", "domain": "easa.europa.eu",
            "technical_host": "news.google.com", "source_type": "REGULATORY",
            "origin": "PRIMARY_VIA_AGGREGATOR", "access_method": "RSS",
            "allowed_access_method": "RSS (Metadata & Short Snippets Only)",
            "tos_url": "https://www.easa.europa.eu/en/legal-notice",
            "usage_restrictions": "Store metadata, headlines, and short excerpts only; attribute EASA; no commercial redistribution of full texts.",
            "tdm_copyright_basis": "EU Directive 2019/790 Art. 3/4 TDM & EASA Legal Notice",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (institutional safety notices)",
            "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "Metadata & public safety notices via RSS search index",
            "rate_limit_rpm": 20, "min_interval_sec": 1.5,
        },
        "SRC_003": {
            "name": "NTSB Aviation Investigation Monitor (via RSS Proxy)", "domain": "ntsb.gov",
            "technical_host": "news.google.com", "source_type": "REGULATORY",
            "origin": "PRIMARY_VIA_AGGREGATOR", "access_method": "RSS",
            "allowed_access_method": "RSS (Metadata & Short Snippets Only)",
            "tos_url": "https://www.ntsb.gov/Pages/policies.aspx",
            "usage_restrictions": "US Government public safety notices; retain metadata and short summaries; cite original NTSB link.",
            "tdm_copyright_basis": "Public Domain (US Federal Agency) / RSS Aggregation",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (exclude victim/crew private PII)",
            "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "Public safety investigation notices",
            "rate_limit_rpm": 20, "min_interval_sec": 1.5,
        },
        "SRC_004": {
            "name": "News API Global Media", "domain": "newsapi.org",
            "source_type": "MEDIA_AGGREGATOR", "origin": "SECONDARY", "access_method": "API",
            "allowed_access_method": "API + Approved robots.txt/TDM-compliant Snippet Extraction",
            "tos_url": "https://newsapi.org/terms",
            "usage_restrictions": "Internal academic/CI analysis only; store short verbatim quotes (<450 chars) & URLs; no full-article republication.",
            "tdm_copyright_basis": "NewsAPI ToS + EU Directive 2019/790 Art. 4 (subject to publisher TDM-Reservation opt-out)",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (redact reporter/contact PII)",
            "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "NewsAPI Developer/Academic Terms - snippet & link indexing",
            "rate_limit_rpm": 20, "min_interval_sec": 1.5,
        },
        "SRC_005": {
            "name": "Official Industry PR (Aircraft OEMs & Suppliers)",
            "domain": "airbus.com,boeing.mediaroom.com,comac.cc", "technical_host": "news.google.com",
            "source_type": "OEM_PR", "origin": "PRIMARY_VIA_AGGREGATOR", "access_method": "RSS",
            "allowed_access_method": "RSS (Public Corporate Press Releases)",
            "tos_url": "https://www.airbus.com/en/terms-of-use",
            "usage_restrictions": "Public investor/media releases; retain title, link, and short summary for internal CI monitoring.",
            "tdm_copyright_basis": "Corporate PR Public Press License / EU Directive 2019/790 Art. 4",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (corporate spokespersons only; contact PII redacted)",
            "verified_domain": True, "legal_status": SourceLegalStatus.ALLOWED.value,
            "license_notes": "Public corporate press releases",
            "rate_limit_rpm": 20, "min_interval_sec": 1.5,
        },
        "SRC_006": {
            "name": "International Airshow Newsrooms",
            "domain": "farnboroughairshow.com,siae.fr,dubaiairshow.aero,singaporeairshow.com",
            "source_type": "INDUSTRY_EVENT", "origin": "PRIMARY", "access_method": "PLAYWRIGHT_CRAWLER",
            "allowed_access_method": "Approved Scraping (Strict robots.txt & TDM-Reservation check mandatory)",
            "tos_url": "https://www.farnboroughairshow.com/terms-and-conditions/",
            "usage_restrictions": "RESTRICTED: Suspend immediately if robots.txt is unreachable or disallows crawling; retain short excerpts only; no redistribution.",
            "tdm_copyright_basis": "EU Directive 2019/790 Art. 4 TDM (Strictly conditional on absence of machine-readable opt-out)",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (B2B event press releases; personal career/HR posts filtered out)",
            "verified_domain": True, "legal_status": SourceLegalStatus.RESTRICTED.value,
            "license_notes": "Respect robots.txt and rate limits; short excerpts only",
            "rate_limit_rpm": 12, "min_interval_sec": 2.5,
        },
        "SRC_007": {
            "name": "Bluesky AT Protocol Aviation Feed", "domain": "bsky.app",
            "source_type": "COMMUNITY_SOCIAL", "origin": "SECONDARY_UNVERIFIED", "access_method": "API",
            "allowed_access_method": "API (Official AT Protocol Public Search)",
            "tos_url": "https://bsky.social/about/support/tos",
            "usage_restrictions": "Exclude private/personal posts unrelated to aerospace; anonymize author handles; internal weak-signal verification only.",
            "tdm_copyright_basis": "AT Protocol Developer Terms",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest with strict Data Minimization (personal non-aerospace posts dropped; handles pseudonymized)",
            "verified_domain": False, "legal_status": SourceLegalStatus.RESTRICTED.value,
            "license_notes": "AT Protocol public search API",
            "rate_limit_rpm": 20, "min_interval_sec": 1.5,
        },
        "SRC_008": {
            "name": "YouTube Data API v3 & Transcripts", "domain": "youtube.com",
            "source_type": "VIDEO_MEDIA", "origin": "SECONDARY_UNVERIFIED", "access_method": "API",
            "allowed_access_method": "API (YouTube Data API v3)",
            "tos_url": "https://developers.google.com/youtube/terms/api-services-terms-of-service",
            "usage_restrictions": "Temporary analytical processing of spoken B2B/aviation news transcripts; no redistribution of full transcripts; exclude personal vlogs.",
            "tdm_copyright_basis": "YouTube API Services Terms of Service",
            "gdpr_legal_basis": "Art. 6(1)(f) GDPR Legitimate Interest (public B2B media channels only; personal hobbyist vlogs rejected)",
            "verified_domain": False, "legal_status": SourceLegalStatus.RESTRICTED.value,
            "license_notes": "YouTube Data API v3 Terms of Service",
            "rate_limit_rpm": 10, "min_interval_sec": 2.0,
        },
        **{
            sid: {
                "name": company + " RSS",
                "domain": domain,
                "source_type": "SUPPLIER_PR",
                "origin": "PRIMARY",
                "access_method": "RSS",
                "tos_url": tos,
                "last_legal_review_date": os.getenv(key + "_REVIEW_DATE", ""),
                "legal_status": (
                    "RESTRICTED"
                    if os.getenv(key + "_APPROVED") == "1"
                       and os.getenv(key + "_REVIEW_DATE")
                    else "REQUIRES_REVIEW"
                ),
                "verified_domain": True,
                "tdm_copyright_basis": "Review required",
                "usage_restrictions": "Metadata only; permission required",
                "rate_limit_rpm": 6,
                "min_interval_sec": 10.0,
            }
            for sid, company, domain, tos, key in (
                (
                    "SRC_010", "GE Aerospace", "geaerospace.com",
                    "https://www.geaerospace.com/pl/node/5536",
                    "EWS_GE_RSS",
                ),
                (
                    "SRC_011", "RTX", "rtx.com",
                    "https://www.rtx.com/Terms-of-Use",
                    "EWS_RTX_RSS",
                ),
            )
        },
    }.items()
}

from ews_sources_extra import registry_additions

SOURCE_REGISTRY.update({
    sid: {**_SRC_DEFAULTS, **config}
    for sid, config in registry_additions().items()
})

SOURCE_REGISTRY["SRC_002"].update(
    name="EASA Official AD Index",
    technical_host="easa.europa.eu",
    origin="PRIMARY",
    legal_status="REQUIRES_REVIEW",
    policy_status="REQUIRES_REVIEW",
)

SOURCE_REGISTRY["SRC_003"].update(
    name="NTSB Public Aviation API",
    domain="api.ntsb.gov",
    source_type="REGULATORY",
    origin="PRIMARY",
    technical_host="api.ntsb.gov",
    access_method="AUTHENTICATED_API",
    legal_status="REQUIRES_REVIEW",
    policy_status="REQUIRES_REVIEW",
)

SOURCE_REGISTRY["SRC_004"]["policy_status"] = "DEV_ONLY"

SOURCE_REGISTRY["SRC_005"].update(
    name="Airbus Press Releases RSS",
    legal_status="REQUIRES_REVIEW",
    policy_status="REQUIRES_REVIEW",
    domain="airbus.com",
    technical_host="airbus.com",
    origin="PRIMARY",
)

SOURCE_REGISTRY["SRC_006"]["policy_status"] = "REQUIRES_REVIEW"
for _source_id in ("SRC_009", "SRC_010", "SRC_011"):
    SOURCE_REGISTRY.pop(_source_id, None)

SOURCE_REGISTRY["SRC_030"] = {
    **SOURCE_REGISTRY["SRC_005"],
    "source_id": "SRC_030",
    "name": "Boeing Newsroom RSS",
    "domain": "boeing.mediaroom.com",
    "technical_host": "boeing.mediaroom.com",
    "origin": "PRIMARY",
    "access_method": "RSS",
    "tos_url": "https://boeing.mediaroom.com/rss-feeds",
    "legal_status": "DISABLED",
    "policy_status": "DISABLED",
}

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
        "aliases": [
            "pratt & whitney",
            "pratt and whitney",
            "pratt whitney",
            "p&w",
            "pw1100g",
            "pw1100g-jm",
            "pw1127g",
            "pw1133g",
            "pw1500g",
            "pw1900g",
    ],
        "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["PW1100G-JM GTF Turbofan Engine", "PW1500G Engine"],
        "programs": ["A320neo", "A321XLR", "A220", "Embraer E2"],
        "downstream_oems": ["Airbus SE", "Embraer"], "geography": "North America (USA)",
        "source_ref": "RTX / Airbus A320neo Family Supplier Registry",
    },
    {
        "entity_id": "ENT_CFM", "official_name": "CFM International (GE / Safran)",
        "aliases": ["cfm", "cfm international", "leap-1a", "leap-1b", "leap-1c"],
        "default_tier": "Tier 1 (Systems/Engines)",
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
        "aliases": [
            "rolls-royce",
            "rolls royce",
            "rolls royce civil aerospace",
            "trent 1000",
            "trent xwb",
            "trent 7000",
        ]
        , "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["Trent XWB-84/97 Engine", "Trent 7000 Engine"],
        "programs": ["A350", "A330neo"], "downstream_oems": ["Airbus SE"], "geography": "Europe (UK)",
        "source_ref": "Rolls-Royce Civil Aerospace Disclosures",
    },
    {
        "entity_id": "ENT_SPIRIT", "official_name": "Spirit AeroSystems",
        "aliases": ["spirit aerosystems"], "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["737 Fuselage", "A350 Center Fuselage Section", "A220 Pylons/Wings"],
        "programs": ["737 MAX", "787 Dreamliner", "A350", "A220"],
        "downstream_oems": ["The Boeing Company", "Airbus SE"], "geography": "North America (USA)",
        "source_ref": "Spirit AeroSystems 10-K",
    },
    {
        "entity_id": "ENT_COLLINS", "official_name": "Collins Aerospace",
        "aliases": [
            "collins aerospace",
            "rockwell collins",
        ],
        "default_tier": "Tier 1 (Systems/Engines)",
        "components": ["Avionics", "Nacelles", "Actuation Systems"],
        "programs": ["A320neo", "A321XLR", "737 MAX", "787 Dreamliner"],
        "downstream_oems": ["Airbus SE", "The Boeing Company"], "geography": "North America (USA)",
        "source_ref": "RTX / Collins Aerospace Product Catalog",
    },
    {
        "entity_id": "ENT_VSMPO", "official_name": "VSMPO-AVISMA / Titanium Suppliers",
        "aliases": ["vsmpo", "vsmpo-avisma"], "default_tier": "Tier 3 (Raw Materials)",
        "components": ["Aerospace-grade Titanium Forgings", "Superalloys"],
        "programs": ["A350", "787 Dreamliner", "A320neo", "737 MAX"],
        "downstream_oems": ["Airbus SE", "The Boeing Company", "Safran S.A.", "Spirit AeroSystems"],
        "geography": "Global", "source_ref": "Aerospace Raw Material Supply Chain Registry",
    },
]


# Resolve aerospace organizations against controlled supplier metadata.
def _supplier_name_key(value: str) -> str:
    text = unicodedata.normalize(
        "NFKD", str(value or "").casefold()
    ).replace("&", " and ")

    text = "".join(
        ch for ch in text
        if not unicodedata.combining(ch)
    )

    text = re.sub(r"[^a-z0-9]+", " ", text)

    return re.sub(r"\s+", " ", text).strip()


def find_supplier_mentions(text: str) -> List[Dict[str, Any]]:
    """Return all distinct explicitly mentioned registry entities."""
    normalized = _supplier_name_key(text)

    if not normalized:
        return []

    matches = []

    for supplier in AEROSPACE_SUPPLIER_REGISTRY:

        aliases = (
            supplier["official_name"],
            *supplier.get("aliases", []),
        )

        for alias in aliases:
            candidate = _supplier_name_key(alias)

            if len(candidate) < 3:
                continue

            pattern = (
                r"(?<![a-z0-9])"
                + re.escape(candidate)
                + r"(?![a-z0-9])"
            )

            if re.search(pattern, normalized):
                matches.append(supplier)
                break

    return matches


def lookup_supplier_in_registry(
    text_or_company: str,
    exact: bool = False
) -> Optional[Dict[str, Any]]:
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
        self._last_call: Dict[str, float] = {}

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


_ROBOTS_CACHE: Dict[str, urllib.robotparser.RobotFileParser] = {}


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
    re.I,
)


# Apply robots.txt and text-and-data-mining access restrictions.
# Apply source-specific robots and text/data-mining restrictions before retrieval.
def check_robots_and_tdm_compliance(
        url: str, source_id: str = "SRC_004", user_agent: str = "AeroEWSBot"
) -> Tuple[bool, str]:
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
        logger.warning(f"[COMPLIANCE FAIL-CLOSED] Error loading robots.txt from {base_robots} ({e}).")
        return False, "Error loading robots.txt rules - collection suspended (REQUIRES_REVIEW)"

    return True, "Allowed (Registry ToS, robots.txt, and TDM pre-check passed)"


# Perform a guarded HTTP request with source policy and redirect checks.
# Do not bypass compliance checks or trust URLs supplied by unverified documents.
# Enforce network safety across redirects and resolved IP addresses.
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
    # Validate outbound requests and redirects before retrieving external content.
    """SSRF-safe HTTP GET client with redirect hop verification, fail-closed robots.txt, and EU 2019/790 TDM opt-out checks."""
    if not is_source_allowed(source_id):
        if SOURCE_REGISTRY[source_id].get("legal_status") == "REQUIRES_REVIEW":
            check_robots = True
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
                logger.warning(
                    "[HTTP RATE LIMITED] source=%s host=%s status=429",
                    source_id,
                    parsed.hostname,
                )

                time.sleep(
                    min(int(resp.headers.get("Retry-After", "3")), 6)
                )

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


# Flag community text unrelated to the monitored industrial intelligence question.
def is_unrelated_personal_post(text: str, title: str = "") -> bool:
    combined = f"{title} {text}".strip()
    return (
            not combined
            or bool(PERSONAL_NON_INDUSTRIAL_POST_REGEX.search(combined))
            or not bool(AEROSPACE_B2B_RELEVANCE_ANCHORS.search(combined))
    )


# Remove unnecessary personal or unsafe content before storing source excerpts.
def sanitize_and_minimize_osint_text(raw_text: str) -> Tuple[str, bool, int]:
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


# Reset per-run URL deduplication and collection state.
def reset_collected_urls() -> None:
    # Reset only per-run source caches and deduplication state.
    with _COLLECTION_LOCK:
        COLLECTED_URLS.clear()
        COLLECTED_DOCUMENTS.clear()
        CONNECTOR_TELEMETRY.clear()
        NEWS_FALLBACK_CACHE.clear()


# Return the current run’s collected document records.
def get_collected_documents() -> List[Dict[str, Any]]:
    with _COLLECTION_LOCK:
        return list(COLLECTED_DOCUMENTS)


# Read per-connector retrieval and rejection statistics.
def get_connector_telemetry() -> Dict[str, Dict[str, Any]]:
    with _COLLECTION_LOCK:
        return dict(CONNECTOR_TELEMETRY)


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
        error: Optional[str] = None,
        coverage_note: Optional[str] = None,
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
        if error:
            entry["errors"].append(error)

        if coverage_note and coverage_note not in entry["coverage_advisories"]:
            entry["coverage_advisories"].append(coverage_note)

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
) -> Dict[str, Any]:
    # Normalize source records, compute provenance fingerprints, and assign stable document IDs.
    """Assign a unique DOC_xxx identifier, compute syndication fingerprint, sanitize text, and store metadata."""
    clean_text, injection_flag, pii_redacted = sanitize_and_minimize_osint_text(raw_text)
    clean_title, title_inj, _ = sanitize_and_minimize_osint_text(title)
    norm_pub = normalize_date_str(published_at)

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
            "supplier_registry_candidates": supplier_candidates,
            "supplier_match_basis": supplier_match_basis,
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

MAX_PAGES_PER_AIRSHOW = min(
    12, max(1, int(os.getenv("EWS_AIRSHOW_MAX_PAGES", "5")))
)
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
_JSON_DATE_RE = re.compile(
    r'\\?"(?:datePublished|publishedAt|publishDate|articlePublishedTime)\\?"\s*:\s*\\?"(20[12]\d-\d{2}-\d{2})')
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


# Read the active per-query retrieval budget.
def get_dynamic_limit() -> int:
    return int(os.getenv("EWS_DYNAMIC_LIMIT", 5))


# Resolve the monitoring reference date used for current and replay scopes.
def get_reference_now_utc() -> datetime:
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
def get_time_window_utc() -> Tuple[Optional[datetime], datetime]:
    # Compute consistent UTC date bounds for all collection channels.
    end_utc = get_reference_now_utc()
    scope_enum = normalize_scope_value(os.getenv("EWS_DYNAMIC_SCOPE", "7d"))
    custom_from = os.getenv("EWS_DATE_FROM", "").strip()
    custom_to = os.getenv("EWS_DATE_TO", "").strip()

    if scope_enum == AnalysisScope.CUSTOM and custom_to:
        try:
            end_utc = datetime.strptime(custom_to[:10], "%Y-%m-%d").replace(hour=23, minute=59, second=59,
                                                                            tzinfo=timezone.utc)
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


# Parse source timestamps into normalized timezone-aware UTC values.
def parse_datetime_utc(date_str: str) -> Optional[datetime]:
    if not date_str or date_str in {"N/A", "Unknown", "DATE_UNKNOWN"} or "unknown" in date_str.lower():
        return None
    raw = date_str.strip()
    try:
        parsed_rss = email.utils.parsedate_to_datetime(raw)
        return (parsed_rss if parsed_rss.tzinfo else parsed_rss.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except Exception:
        pass

    if iso_full := _ISO_FULL_RE.search(raw):
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
    return filtered[:2500] if filtered else full_text[:1000]


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


MODEL_TOKEN_RE = re.compile(
    # Recognize aircraft and engine identifiers without merging them
    # with unrelated words in surrounding text.
    r"(?<![A-Za-z0-9])(?:[A-Za-z]{1,5}[- ]?\d{1,5}(?:-?[A-Za-z0-9]{1,6}){0,2}|"
    r"\d{3}(?:[- ]?(?:MAX(?:\s*\d{1,2})?|XLR|NEO|CEO|NG|ER|LR|X|F))?)"
    r"(?![A-Za-z0-9])",
    re.I,
)


# Extract model identifiers that must survive query normalization.
def _model_tokens(query: str) -> list[str]:
    return list(dict.fromkeys(m.lower() for m in MODEL_TOKEN_RE.findall(query or "")))


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

    for spec_model in _model_tokens(safe_query):
        pattern = rf"(?<![a-z0-9]){re.escape(spec_model)}(?![a-z0-9])"
        if re.search(pattern, remaining_query, re.I):
            detected_specific_models.append(spec_model)
            remaining_query = re.sub(pattern, " ", remaining_query, flags=re.I)

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

                if not urlparse(absolute).path.startswith(
                        "/en/press/releases/"
                ):
                    continue

                heading = row.select_one(".pml-body strong")
                title = (
                    heading.get_text(" ", strip=True)
                    if heading
                    else row.get_text(" ", strip=True)
                )

                body_element = row.select_one(".pml-body")
                context = (
                    body_element.get_text(" ", strip=True)
                    if body_element
                    else title
                )

                raw_date = row.select_one(".pml-date")
                card_date = ""

                if raw_date:
                    date_text = raw_date.get_text(
                        " ", strip=True
                    )
                    try:
                        card_date = datetime.strptime(
                            date_text, "%d/%m/%Y"
                        ).date().isoformat()
                    except ValueError:
                        pass

                add_candidate_link(
                    title,
                    href,
                    context,
                    card_date,
                )
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


# Construct source-specific Boolean queries with explicit model and topic terms.
# Preserve technical model specificity when building provider query terms.
def news_api_search_key(query: str) -> str:
    # Construct precision-oriented NewsAPI search terms with explicit model identity.
    """Build a bounded NewsAPI query while preserving aircraft identity, technical scope and event indicators."""
    safe_query = re.sub(
        r"\s+", " ",
        (query or "").replace(",", " ")
    ).strip()

    safe_query = re.sub(
        r"(?i)\bp\s*(?:&|and)\s*w\b",
        "pratt whitney",
        safe_query,
    )

    safe_query = re.sub(
        r"(?i)\bpratt[\s\-]*(?:&|and)?[\s\-]*whitney\b",
        "pratt whitney",
        safe_query,
    )

    safe_query = re.sub(
        r"(?i)\brolls[\s\-]+royce\b",
        "rolls-royce",
        safe_query,
    )
    words = re.findall(r"[a-z0-9-]+", safe_query.lower())
    aircraft = _model_tokens(safe_query)

    tech_vocab = {
        "gtf", "pw1100g", "pw1100g-jm", "pw1500g",
        "leap", "leap-1a", "leap-1b", "leap-1c",
        "cfm56", "ge9x", "ge90", "pratt", "whitney",
        "trent", "safran", "rolls-royce",
        "easa", "faa", "ntsb", "spirit", "supplier",
    }
    issue_re = re.compile(
        r"(?:inspect\w*|defect\w*|fail\w*|shortag\w*|ground\w*|delay\w*|directiv\w*|airworth\w*|"
        r"production|manufactur\w*|constraint\w*|recall\w*|certif\w*|order\w*|deliver\w*|"
        r"fleet|disrupt\w*|safet\w*|engine\w*|regulat\w*|problem\w*|issue\w*|incident\w*|"
        r"cancel\w*|strike\w*|maintenan\w*|upgrade\w*|turbine|blades?)"
    )

    technical = list(dict.fromkeys(w for w in words if w in tech_vocab))[:4]
    issue = list(dict.fromkeys(w for w in words if issue_re.fullmatch(w)))[:4]

    named_issuers = (
        (r"\bge\s+aerospace\b", "GE Aerospace"),
        (r"\brolls[-\s]+royce\b", "Rolls-Royce"),
        (r"\bpratt\s+whitney\b", "Pratt Whitney"),
        (r"\b(?:rtx|raytheon)\b", "RTX"),
        (r"\bsafran\b", "Safran"),
        (r"\bboeing\b", "Boeing"),
        (r"\bairbus\b", "Airbus"),
    )
    named = next(
        (issuer for pattern, issuer in named_issuers
         if re.search(pattern, safe_query, re.I)), ""
    )

    if aircraft:
        anchor = aircraft[0]
    elif named:
        anchor = named
        technical = [w for w in technical if w not in set(named.lower().split())]
    else:
        stop = {
            "which", "about", "latest", "news", "what", "does", "from", "with",
            "this", "that", "aircraft", "aviation", "issues", "report", "reports", "europe", "official",
        }
        anchor = next((w for w in words if len(w) > 3 and w not in stop and w not in issue), "")
        technical = [w for w in technical if w != anchor]

    anchor_words = set(re.findall(r"[a-z0-9]+", anchor.lower()))
    technical = [term for term in technical if term not in anchor_words]
    if named and not aircraft and any(
        w in words for w in {"sourcing", "spend", "procurement", "expansion"}
    ):
        # A headline need not use 'supplier' AND 'sourcing'.
        technical = [term for term in technical if term != "supplier"]

    parts = [
        anchor if anchor.startswith("(")
        else (f'"{anchor}"' if " " in anchor else anchor)
    ]
    if technical:
        parts.append(f"({' OR '.join(technical)})")

    # Geography and strategic-intelligence vocabulary can be essential for
    # a company KIT without any aircraft model (e.g. India sourcing plans).
    if not aircraft and named:
        geographical = next((w for w in words if w in {
            "india", "china", "japan", "france", "germany", "canada", "brazil",
            "turkey", "singapore", "australia", "poland", "mexico",
        }), None)
        if geographical:
            parts.append(geographical)
        if not issue:
            strategic = [w for w in words if w in {
                "sourcing", "spend", "supplier", "procurement",
                "expansion", "investment", "capacity", "contracts",
            }]
            if strategic:
                parts.append("(" + " OR ".join(dict.fromkeys(strategic[:4])) + ")")
    if issue:
        parts.append(f"({' OR '.join(issue)})")
    return " AND ".join(parts)


# Extract the substantive body text of a retrieved publisher article.
def _extract_news_article_body(html_text: str) -> str:
    """Extract article paragraphs and exclude unrelated page navigation, recommendations and sidebars."""
    soup = BeautifulSoup(html_text, "html.parser")
    for node in soup.select(
            "script, style, noscript, nav, header, footer, aside, form, "
            "[role='navigation'], [class*='related'], [class*='recommend'], [class*='advert'], [id*='related']"
    ):
        node.decompose()

    for selector in ("[itemprop='articleBody']", "article", "[class*='article-body']", "[class*='story-body']", "main"):
        candidates = []
        for node in soup.select(selector):
            content = "\n".join(
                p.get_text(" ", strip=True) for p in node.find_all("p") if len(p.get_text(" ", strip=True)) >= 35)
            if len(content) >= 120:
                candidates.append(content)
        if candidates:
            return max(candidates, key=len)[:10000]
    return ""


# Combine precise and conditional broad NewsAPI searches with deduplication.
# Conditional recall search can broaden results; it does not bypass relevance screening.
# Recall broadening does not override source scope or later relevance gates.
@tool("Search Aerospace News and Read Full Articles")
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def search_aerospace_news(query: str) -> str:
    # Search the news source using a primary query and guarded recall fallback.
    """Query News API preserving specific aircraft model suffixes (e.g., 777X, A321XLR)."""
    if (
        os.getenv("EWS_ENV", "development").lower()
        not in {"dev", "development", "test"}
        and os.getenv("EWS_NEWSAPI_PRO_LICENSE") != "1"
    ):
        return "NewsAPI disabled: production license required."
    safe_query = query.replace(",", "").replace("  ", " ").strip()
    and_query = news_api_search_key(safe_query)
    query_tokens = and_query.split(" AND ", 2)

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

        news_earliest = (
                datetime.now(timezone.utc) - timedelta(days=29)
        )

        effective_start = max(
            start_utc,
            news_earliest,
        )

        if effective_start > start_utc:
            logger.warning(
                "[NEWS API COVERAGE] Requested scope starts %s, "
                "but this connector uses %s; "
                "the full requested period is NOT covered by News API.",
                start_utc.date(),
                effective_start.date(),
            )

            record_connector_telemetry(
                "News API",
                "SRC_004",
                safe_query,
                coverage_note=(
                    f"NEWSAPI_PARTIAL_WINDOW: requested_from={start_utc.date()}, "
                    f"actual_from={effective_start.date()}, "
                    f"actual_to={end_utc.date()}"
                ),
            )

        params["from"] = effective_start.strftime(
            "%Y-%m-%dT%H:%M:%S"
        )

    if not NEWS_API_KEY:
        logger.error(
            "[NEWS API ERROR] NEWS_API_KEY is missing; "
            "collection was not attempted."
        )

        record_connector_telemetry(
            "News API",
            "SRC_004",
            safe_query,
            error="MISSING_API_KEY",
        )

        return (
            f"News API unavailable for query '{query}' "
            "(missing API key)."
        )

    logger.info(
        "[NEWS API REQUEST] primary=%r from=%s to=%s",
        and_query,
        params.get("from", "unrestricted"),
        params["to"],
    )

    resp = safe_http_get(
        url,
        source_id="SRC_004",
        params=params,
        timeout=15,
    )

    if resp is None or resp.status_code != 200:
        status = (
            resp.status_code
            if resp is not None
            else "NO_RESPONSE_OR_COMPLIANCE_BLOCK"
        )

        # Do not expose credentials or complete request URLs.
        logger.warning(
            "[NEWS API ERROR] query=%r status=%s",
            and_query,
            status,
        )

        record_connector_telemetry(
            "News API",
            "SRC_004",
            safe_query,
            error=f"PRIMARY_HTTP_{status}",
        )

        return (
            f"News API unavailable for query '{query}' "
            f"(HTTP/status: {status})."
        )

    # Use a broader search only according to the existing recall policy and cache state.
    articles = resp.json().get("articles", [])
    logger.info(f"[NEWS API DEBUG] Query='{and_query}' | HTTP={resp.status_code} | API articles={len(articles)}")

    if len(query_tokens) >= 3 and len(articles) < max(10, limit * 2):
        # Recall fallback keeps the aircraft family and issue terms while relaxing the engine-specific
        #   constraint.
        fallback_q = " AND ".join(query_tokens[:2])
        fallback_params = {**params, "q": fallback_q, "pageSize": min(100, max(20, limit * 4))}
        cache_key = (
            fallback_q,
            str(fallback_params.get("from", "")),
            str(fallback_params.get("to", "")),
            fallback_params["pageSize"],
        )

        with _COLLECTION_LOCK:
            # Reuse a bounded broad-search response to avoid redundant NewsAPI quota consumption.
            cached_articles = NEWS_FALLBACK_CACHE.get(cache_key)

        if cached_articles is None:

            logger.info(
                "[NEWS API REQUEST] recall=%r",
                fallback_q,
            )

            fb_resp = safe_http_get(
                url,
                source_id="SRC_004",
                params=fallback_params,
                timeout=15,
            )

            if fb_resp is not None and fb_resp.status_code == 200:

                cached_articles = (
                        fb_resp.json().get("articles", []) or []
                )

                with _COLLECTION_LOCK:
                    NEWS_FALLBACK_CACHE[cache_key] = list(
                        cached_articles
                    )

            else:

                status = (
                    fb_resp.status_code
                    if fb_resp is not None
                    else "NO_RESPONSE_OR_COMPLIANCE_BLOCK"
                )

                logger.warning(
                    "[NEWS API RECALL ERROR] query=%r status=%s",
                    fallback_q,
                    status,
                )

                record_connector_telemetry(
                    "News API",
                    "SRC_004",
                    safe_query,
                    error=f"RECALL_HTTP_{status}",
                )

                cached_articles = []

        existing_urls = {a.get("url") for a in articles}
        for candidate in cached_articles:
            article_url = candidate.get("url")
            if article_url and article_url not in existing_urls:
                articles.append(candidate)
                existing_urls.add(article_url)

        logger.info("[NEWS API RECALL] Broad query %r, %d combined candidates", fallback_q, len(articles))

    if not articles:
        logger.info(
            "[NEWS API NO MATCH] primary and recall yielded "
            "0 articles; query=%r",
            safe_query,
        )

        record_connector_telemetry(
            "News API",
            "SRC_004",
            safe_query,
            0,
            0,
            0,
        )

    extracted_content = ""
    query_words = [w.lower() for w in safe_query.split() if len(w) > 2]
    count = rejected_scope = unknown_dates = rejected_missing_url = rejected_duplicate = rejected_model = metadata_only = 0

    model_anchor = query_tokens[0].strip('"').lower() if query_tokens else ""
    model_pattern = re.compile(rf"(?<!\w){re.escape(model_anchor)}(?!\w)") if (
            model_anchor and any(c.isdigit() for c in model_anchor)) else None

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

        # Retrieve full article bodies when permitted; mark metadata-only results honestly.
        body_text = ""
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
                elif article_body:
                    logger.warning("[NEWS BODY MISMATCH] %s: title does not match article text", article_url)

        if not body_text:
            metadata_only += 1
            body_text = (
                    "[NEWSAPI_METADATA_ONLY: PUBLISHER ARTICLE TEXT UNAVAILABLE]\n"
                    + (desc.strip() or "No article description available.")
            )

        if model_pattern and not model_pattern.search(f"{title} {desc} {body_text}".lower()):
            logger.info(
                "[NEWS API SCOPE REVIEW] Model %r not explicitly mentioned in %r; retaining for semantic filtering.",
                model_anchor, title[:100],
            )

        doc = register_collected_document(
            source_id="SRC_004", connector_name="News API", url=article_url,
            title=title, raw_text=body_text, published_at=pub_date, query_used=safe_query,
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
                + ("-" * 40) + "\n"
        )
        count += 1

    logger.info(
        "[NEWS API AUDIT] query=%r candidates=%d accepted=%d missing_url=%d duplicate=%d out_of_scope=%d model_mismatch=%d metadata_only=%d",
        safe_query, len(articles), count, rejected_missing_url, rejected_duplicate, rejected_scope, rejected_model,
        metadata_only,
    )
    record_connector_telemetry("News API", "SRC_004", safe_query, len(articles), count, rejected_scope, unknown_dates)

    if count == 0:
        return f"No relevant articles found in News API for query '{query}'."

    logger.info(f"[OSINT GATHERER] News API extraction completed ({count} articles).")
    return extracted_content


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
    max_windows = max(1, min(
        20, int(os.getenv("EWS_NTSB_MAX_WINDOWS", "8"))
    ))

    if start is None:
        start = end - timedelta(days=30 * max_windows)

    limit = max(1, min(get_dynamic_limit(), 10))
    tokens = [
        word for word in re.findall(
            r"[a-z0-9-]{3,}", query.lower()
        )
        if word not in {
            "latest", "ntsb", "aviation", "accident",
            "incident", "aircraft", "investigation"
        }
    ]

    headers = {
        "Ocp-Apim-Subscription-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "AeroEWS Academic Research/2.0",
    }

    endpoint = (
        "https://api.ntsb.gov/public/api/"
        "Common/v2/GetCasesByDateRange/"
    )

    output = []
    seen = set()
    cursor_end = end.date()
    requests_count = 0
    partial = False

    for _ in range(max_windows):
        if cursor_end < start.date() or len(output) >= limit:
            break

        cursor_start = max(
            start.date(),
            cursor_end - timedelta(days=29),
        )

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
                published = str(
                    case.get("publishDateTime") or ""
                )[:10]

                aircraft = case.get("aircrafts") or []
                models = [
                    (
                        str(a.get("aircraftMake") or
                            a.get("aircraftManufacturer") or "")
                        + " "
                        + str(a.get("aircraftModel") or "")
                    ).strip()
                    for a in aircraft
                ]
                models_text = "; ".join(models)

                searchable = " ".join([
                    number,
                    models_text,
                    str(case.get("eventType") or ""),
                    str(case.get("eventCity") or ""),
                    str(case.get("eventStateOrRegion") or ""),
                ]).lower()

                if tokens and not any(t in searchable for t in tokens):
                    continue

                if not event_date or not is_date_within_scope(event_date):
                    continue

                classification = [
                    str(e.get("cicttEventSOEGroup") or
                        e.get("eventTier2Name") or "")
                    for a in aircraft
                    for e in (a.get("events") or [])
                ]

                body = (
                    f"NTSB case {number}. "
                    f"Occurrence date: {event_date}. "
                    f"Publication: {published or 'UNKNOWN'}. "
                    f"Event type: {case.get('eventType')}. "
                    f"Aircraft: {models_text or 'UNKNOWN'}. "
                    f"Location: {case.get('eventCity')}, "
                    f"{case.get('eventStateOrRegion')}, "
                    f"{case.get('eventCountry')}. "
                    f"Injury level: {case.get('highestInjuryLevel')}. "
                    f"Investigation status: {case.get('completionStatus')}. "
                    f"Case closed: {case.get('caseClosed')}. "
                    f"Event classification: {', '.join(classification[:4])}. "
                    "These metadata do not establish a final root cause."
                )

                # API request URL with case ID as a reference fragment.
                # This is not a verified case-specific web page.
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
                    "document_type": "NTSB_INVESTIGATION",
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
        coverage_note=(
            f"requests={requests_count}; "
            f"partial={partial}; max_windows={max_windows}"
        ),
    )

    if not output:
        return (
            "NTSB: no matching cases in scanned windows. "
            f"Partial coverage: {partial}"
        )

    return "\n".join(output)



_FAA_LIFECYCLE_FIELDS = [
    "document_number", "docket_id", "docket_ids", "title", "abstract",
    "action", "type", "html_url", "publication_date", "effective_on",
]


# Resolve FAA notices by docket and distinguish their regulatory lifecycle.
# Track proposed, final and effective stages separately for each docket.
def _faa_resolve_docket(
        doc: Dict[str, Any], as_of: str, cache: Dict[str, Tuple[Dict[str, Any], bool]]
) -> Tuple[Dict[str, Any], str, bool]:
    # Resolve FAA docket lifecycle before attributing regulatory effect.
    """Resolve the latest published FAA rule/proposed rule within the same docket."""
    number = str(doc.get("document_number") or "")
    full_doc = dict(doc)

    if re.fullmatch(r"\d{4}-\d{4,6}", number):
        response = safe_http_get(
            f"https://www.federalregister.gov/api/v1/documents/{number}.json",
            source_id="SRC_001", params={"fields[]": _FAA_LIFECYCLE_FIELDS}, timeout=12,
        )
        if response is not None and response.status_code == 200:
            full_doc.update(response.json())

    docket_data = json.dumps({"docket_ids": full_doc.get("docket_ids"), "docket_id": full_doc.get("docket_id")})
    match = re.search(r"\bFAA-\d{4}-\d+\b", docket_data, re.I)
    docket = match.group(0).upper() if match else ""

    if not docket and (url := full_doc.get("html_url") or doc.get("html_url")):
        page = safe_http_get(url, source_id="SRC_001", timeout=12)
        if page is not None and page.status_code == 200:
            plain = BeautifulSoup(page.text, "html.parser").get_text(" ", strip=True)
            if m := re.search(r"\bDocket\s+(?:No\.?|Number)\s*[:#]?\s*(FAA-\d{4}-\d+)\b", plain, re.I):
                docket = m.group(1).upper()

    if not docket:
        logger.info("[FAA LIFECYCLE] Docket unavailable for document %s", number)
        return full_doc, "", False

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
        results = response.json().get("results", []) if (response is not None and response.status_code == 200) else []
        relevant = [
            item for item in results
            if item.get("publication_date", "") <= as_of
               and str(item.get("type") or "").strip().upper() in {"RULE", "PROPOSED RULE", "PRORULE"}
        ]

        if relevant:
            newest = max(relevant, key=lambda item: (item.get("publication_date", ""), item.get("document_number", "")))
            if latest_num := str(newest.get("document_number") or ""):
                detail = safe_http_get(
                    f"https://www.federalregister.gov/api/v1/documents/{latest_num}.json",
                    source_id="SRC_001", params={"fields[]": _FAA_LIFECYCLE_FIELDS}, timeout=12,
                )
                if detail is not None and detail.status_code == 200:
                    newest = {**newest, **detail.json()}
            cache[docket] = (newest, True)
            logger.info("[FAA LIFECYCLE] Docket %s: %s -> %s", docket, number, latest_num)
        else:
            cache[docket] = (full_doc, False)
            logger.warning("[FAA LIFECYCLE] No verified rule found for docket %s", docket)

    latest, checked = cache[docket]
    return latest, docket, checked


_EASA_PRIMARY_INDEX_PAGES = (
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
def _easa_applicability(
        query: str,
        subject: str,
        approved_types: str,
) -> str:
    """
    Determine EASA applicability using centralized aircraft
    and engine identity recognition.

    Returns:
        AIRCRAFT   - Aircraft identity matches the KIT.
        ENGINE_ONLY - Engine matches, aircraft installation unverified.
        NONE       - Direct applicability is not established.
    """

    # Local import prevents circular module dependencies.
    from ews_validation import (
        _detect_aircraft_families,
        _detect_specific_variants,
        _detect_exact_variants,
        _detect_engine_models,
        _engine_models_match,
    )

    text = f"{subject} {approved_types}"

    # Aircraft family identification.
    requested_families = _detect_aircraft_families(query)
    source_families = _detect_aircraft_families(text)

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
    aircraft_match = bool(
        requested_families & source_families
    )

    # Prevent matching different known aircraft programs.
    if (
            requested_specific
            and source_specific
            and not (requested_specific & source_specific)
    ):
        aircraft_match = False

    # Prevent a generic family match from overriding
    # a known mismatch between exact variants.
    # Generic neo designation may match an N-suffixed
    # Airbus type designation of the same aircraft model.
    neo_query = re.search(
        r"\b(a3(?:19|20|21))[\s-]*neo\b",
        query,
        re.I,
    )

    neo_cert_match = bool(
        neo_query
        and re.search(
            rf"\b{re.escape(neo_query.group(1))}"
            rf"-\d{{3}}N[A-Z]?\b",
            text,
            re.I,
        )
    )

    if (
            requested_exact
            and not (requested_exact & source_exact)
            and not neo_cert_match
    ):
        aircraft_match = False

    # A KIT naming an individual certified type must not
    # be satisfied by a different certified type.
    cert_pattern = re.compile(
        r"\bA3(?:19|20|21)-\d{3}N[A-Z]?\b",
        re.I,
    )

    requested_cert = {
        value.upper()
        for value in cert_pattern.findall(query)
    }

    source_cert = {
        value.upper()
        for value in cert_pattern.findall(text)
    }

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

    # Generic manufacturer-level KIT without a model.
    q_lower = query.lower()
    source_lower = text.lower()

    if (
            re.search(r"\bairbus\b", q_lower)
            and "airbus" not in source_lower
    ):
        return "NONE"

    if (
            re.search(r"\bboeing\b", q_lower)
            and "boeing" not in source_lower
    ):
        return "NONE"

    return "AIRCRAFT"


# Parse EASA directive index metadata across supported page layouts.
# Preserve directive numbers and links from official EASA metadata.
def _easa_parse_table(html_text: str, base_url: str) -> tuple[list[dict], str | None]:
    # Parse official EASA index rows into standardized directive metadata.
    """Parse both EASA interim and archive table formats."""
    soup = BeautifulSoup(html_text, "html.parser")
    records = []

    for table in soup.find_all("table"):
        headers = [re.sub(r"\s+", " ", h.get_text(" ", strip=True)).lower() for h in table.select("thead th")]
        if not headers and (first := table.find("tr")):
            headers = [h.get_text(" ", strip=True).lower() for h in first.find_all("th", recursive=False)]

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
            if not re.fullmatch(r"20\d{2}-\d{4}(?:[RC]\d+)?", number):
                continue
            if "issued by" in cols and cols["issued by"].get_text(" ", strip=True).upper() != "EU":
                continue
            if "ad class" in cols and cols["ad class"].get_text(" ", strip=True).upper() != "AD":
                continue

            published = _easa_iso_date(cols["issue date"].get_text(" ", strip=True))
            if not published:
                continue

            subject = cols["subject"].get_text(" ", strip=True)
            types = cols.get("approval holder / type designation")
            applicability = types.get_text(" ", strip=True) if types else ""
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

            if pdf_url:
                records.append({
                    "number": number, "published": published, "subject": subject,
                    "applicability": applicability, "effective": effective_date, "pdf_url": pdf_url,
                })

    next_url = None
    for a in soup.find_all("a", href=True):
        label = a.get_text(" ", strip=True).lower()
        relation = str(a.get("rel", "")).lower()
        if label in {"next", "next ›", "next »", "›", "»"} or "next" in relation:
            candidate = urljoin(base_url, a["href"])
            if urlparse(candidate).netloc == urlparse(base_url).netloc:
                next_url = candidate
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
                        reader.fieldnames = names + [
                            f"Other {i}" for i in range(len(first_row) - 5)
                        ]
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
def _collect_easa_primary_index(query: str, limit: int) -> tuple[str, int]:
    # Collect EASA directives without assuming an index entry provides the full PDF.
    """Collect official EASA AD index metadata."""
    output = ">> EASA OFFICIAL AD INDEX (METADATA ONLY; PDF NOT READ):\n"
    accepted = examined = pages = 0
    seen_ad, failures = set(), []

    start, end = get_time_window_utc()
    span = (end - start).days if start else 365
    max_archive_pages = min(40, max(1, int(os.getenv("EWS_EASA_ARCHIVE_MAX_PAGES", "12" if span <= 90 else "35"))))

    for first_url in _EASA_PRIMARY_INDEX_PAGES[:1]:
        archive = "archive-airworthiness-directives" in first_url
        url = first_url
        visited = set()
        max_pages = max_archive_pages if archive else 1

        for _ in range(max_pages):
            if not url or url in visited or accepted >= limit:
                break
            visited.add(url)

            response = safe_http_get(url, source_id="SRC_002", timeout=12, check_robots=True, max_bytes=5_000_000)
            if response is None or response.status_code != 200:
                failures.append(f"HTTP/COMPLIANCE:{url}")
                break

            index_html = response.text
            records, next_page = _easa_parse_table(index_html, url)
            pages += 1
            examined += len(records)

            csv_rows = []
            if os.getenv("EWS_EASA_CSV_ENABLED", "1") == "1" and index_html and accepted < limit:
                csv_rows, csv_issues = _easa_biweekly_csv_rows(index_html, _EASA_PRIMARY_INDEX_PAGES[0])
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
                    applicability = _easa_applicability(query, row["subject"], row["applicability"])
                    if applicability == "NONE" or row["pdf_url"] in COLLECTED_URLS:
                        continue

                    summary = (
                        "Official EASA biweekly CSV archive record. "
                        "This record is metadata only; the corresponding AD PDF has NOT been read. "
                        f"EASA AD: {row['number']}. Issue date: {row['published']}. "
                        f"Subject: {row['subject']}. Type designation: {row['applicability']}. "
                        f"Applicability class: {applicability}. "
                        "Technical requirements and operational effects require direct PDF verification."
                    )
                    doc = register_collected_document(
                        source_id="SRC_002", connector_name="EASA Biweekly CSV Archive",
                        url=row["pdf_url"], title=f"EASA AD {row['number']}: {row['subject']}",
                        raw_text=summary, published_at=row["published"], query_used=query,
                    )
                    doc["origin_type"] = "PRIMARY_OFFICIAL_INDEX_METADATA"
                    doc["regulatory_applicability_scope"] = applicability
                    doc["verified_domain"] = True

                    output += (
                        f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_002\n"
                        f"DATE: {doc['published_at']}\nTitle: {doc['title']}\n"
                        f"Link: {doc['url']}\nSummary: {doc['text']}\n---\n"
                    )
                    accepted += 1

                logger.info("[EASA CSV AUDIT] parsed=%d accepted_total=%d issues=%s", len(csv_rows), accepted,
                            csv_issues or "none")

            dated_rows = [str(r.get("published", "")) for r in (records + csv_rows) if
                          re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r.get("published", "")))]
            oldest_index_date = min(dated_rows, default="")
            if (
                    start and oldest_index_date and start.date().isoformat() < oldest_index_date
                    and "HISTORICAL_COVERAGE_NOT_ESTABLISHED" not in failures
            ):
                failures.append("HISTORICAL_COVERAGE_NOT_ESTABLISHED")

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

                note = (
                    "ENGINE-LEVEL AD: aircraft installation NOT established by this index."
                    if scope == "ENGINE_ONLY"
                    else "AIRCRAFT-LEVEL AD: exact variant and technical applicability require PDF review."
                )
                text = (
                    "Official EASA index entry; PDF text NOT extracted. "
                    f"EASA AD: {row['number']}. Issued: {row['published']}. Subject: {row['subject']}. "
                    f"Approval Holder / Type Designation: {row['applicability']}. "
                    f"Effective date: {row['effective'] or 'UNKNOWN'}. Applicability class: {scope}. {note}"
                )
                doc = register_collected_document(
                    source_id="SRC_002", connector_name="EASA Official Index",
                    url=row["pdf_url"], title=f"EASA AD {row['number']}: {row['subject']}",
                    raw_text=text, published_at=row["published"], query_used=query,
                )
                doc["origin_type"] = "PRIMARY_OFFICIAL_INDEX_METADATA"
                doc["verified_domain"] = True
                doc["regulatory_applicability_scope"] = scope

                output += (
                    f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_002\n"
                    f"DATE: {doc['published_at']}\nTitle: {doc['title']}\n"
                    f"Link: {doc['url']}\nSummary: {doc['text']}\n---\n"
                )
                accepted += 1

            if archive and not next_page and len(records) >= 25 and accepted < limit:
                failures.append("ARCHIVE_NEXT_PAGE_NOT_DISCOVERED")

            if archive and start and records and all(r["published"] < start.date().isoformat() for r in records):
                url = None
            else:
                url = next_page if archive else None

        if archive and len(visited) >= max_pages and url and accepted < limit:
            failures.append("ARCHIVE_PAGINATION_BUDGET_EXHAUSTED")

    logger.info("[EASA PRIMARY AUDIT] accepted=%d examined=%d pages=%d issues=%s", accepted, examined, pages,
                failures or "none")
    if failures:
        logger.warning("[EASA COVERAGE] Partial or unavailable official archive: %s", failures)

    record_connector_telemetry(
        "EASA Official Index", "SRC_002", query, examined, accepted, 0,
        error="; ".join(failures) if failures else "",
    )
    return (output if accepted else "", accepted)


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
    required_words, search_term = parse_query_intent(query)
    search_term = re.sub(r"\b(?:FAA|EASA|NTSB)\b", "", search_term, flags=re.I).strip() or query

    logger.info(
        f"[OSINT GATHERER] Querying FAA and EASA databases for: '{query}' (limit: {limit}, scope: {scope_days or 'all'} days)")
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


        faa_url = "https://www.federalregister.gov/api/v1/documents.json"

        # Prefer exact Federal Register document numbers.
        exact = re.search(r"(?<!\d)20\d{2}-\d{5}(?!\d)", query)
        exact_doc = None

        if exact:
            number = exact.group()
            direct = safe_http_get(
                f"https://www.federalregister.gov/api/v1/documents/{number}.json",
                source_id="SRC_001",
                params={"fields[]": _FAA_LIFECYCLE_FIELDS},
                timeout=12,
            )
            candidate = (
                direct.json()
                if direct is not None and direct.status_code == 200
                else {}
            )
            if (
                candidate.get("document_number") == number
                and is_date_within_scope(candidate.get("publication_date"))
            ):
                exact_doc = candidate
            else:
                logger.warning("[FAA EXACT LOOKUP] Not retrieved/in scope: %s", number)

        resp = safe_http_get(faa_url, source_id="SRC_001", params=params, timeout=12)

        if (resp is not None and resp.status_code == 200) or exact_doc:
            payload = resp.json() if resp is not None and resp.status_code == 200 else {}
            docs = list(payload.get("results", []) or [])

            if exact_doc:
                docs = [exact_doc] + [
                    d for d in docs
                    if d.get("document_number") != exact_doc["document_number"]
                ]

            if scope_days is None or scope_days > 90:
                pages = min(
                    5, max(1, int(os.getenv("EWS_FAA_MAX_PAGES", "1")))
                )

                for _ in range(pages - 1):
                    next_url = payload.get("next_page_url", "")

                    if urlparse(next_url).hostname not in {
                        "federalregister.gov",
                        "www.federalregister.gov",
                    }:
                        break

                    response = safe_http_get(
                        next_url,
                        source_id="SRC_001",
                        timeout=12,
                    )

                    if response is None or response.status_code != 200:
                        break

                    payload = response.json()
                    docs.extend(payload.get("results", []) or [])

            if not docs:
                entity = lookup_supplier_in_registry(query)
                broad_term = (
                    re.sub(r"\s*\([^)]*\)", "", entity["official_name"]).strip()
                    if entity else next(iter(_model_tokens(query)), "")
                )
                if broad_term and broad_term.casefold() != search_term.casefold():
                    broad_resp = safe_http_get(
                        faa_url, source_id="SRC_001",
                        params={**params, "conditions[term]": broad_term}, timeout=12,
                    )
                    if broad_resp is not None and broad_resp.status_code == 200:
                        docs = broad_resp.json().get("results", []) or []
                        logger.info("[FAA RECALL] Broad query %r returned %d records", broad_term, len(docs))

            faa_count = faa_rejected = 0
            docket_cache: Dict[str, Tuple[Dict[str, Any], bool]] = {}
            faa_block = ">> FAA (Federal Aviation Administration - Federal Register):\n"

            for found_doc in docs:
                if faa_count >= limit:
                    break
                title = str(found_doc.get("title") or "")
                abstract = str(found_doc.get("abstract") or "")
                if not any(rw in f"{title} {abstract}".lower() for rw in required_words) and not (
                        exact and found_doc.get("document_number") == exact.group()
                ):
                    continue

                doc, docket, checked = _faa_resolve_docket(found_doc, end_utc.strftime("%Y-%m-%d"), docket_cache)
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

                if is_proposed:
                    stage = "PROPOSED"
                elif is_final:
                    stage = "EFFECTIVE" if (
                            effective_on and effective_on <= end_utc.strftime("%Y-%m-%d")) else "FINAL_ISSUED"
                else:
                    stage = "UNKNOWN"

                summary = str(doc.get("abstract") or "").replace("\n", " ").strip()
                old_url = found_doc.get("html_url") or ""
                history = f"Related earlier document: {old_url}\n" if (old_url and old_url != link) else ""

                raw_text = (
                    f"Regulatory Stage: {stage}\n"
                    f"Regulatory Lifecycle Check: {'VERIFIED' if checked else 'UNVERIFIED'}\n"
                    f"FAA Docket: {docket or 'UNKNOWN'}\n"
                    f"Federal Register Document: {doc.get('document_number', 'UNKNOWN')}\n"
                    f"Effective Date: {effective_on or 'UNKNOWN'}\n"
                    f"{history}Official Summary: {summary[:850]}"
                )
                doc_rec = register_collected_document(
                    source_id="SRC_001", connector_name="FAA Federal Register", url=link,
                    title=doc.get("title") or title, raw_text=raw_text, published_at=pub_date, query_used=query,
                )
                faa_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_001\n"
                    f"DATE: {doc_rec['published_at']}\n"
                    f"Document Type: {doc_type} | Regulatory Stage: {stage}\n"
                    f"Title: {doc_rec['title']}\nLink: {link}\nSummary: {doc_rec['text']}\n---\n"
                )
                faa_count += 1

            record_connector_telemetry("FAA Federal Register", "SRC_001", query, len(docs), faa_count, faa_rejected)
            if faa_count > 0:
                extracted_text += faa_block
    except Exception as e:
        logger.error(f"[OSINT GATHERER] Federal Register FAA API error: {e}")
        record_connector_telemetry("FAA Federal Register", "SRC_001", query, error=str(e))

    primary_count = 0

    if os.getenv("EWS_EASA_SAFETY_PUBLICATIONS_ENABLED", "0") == "1":
        try:
            primary_block, primary_count = _collect_easa_primary_index(
                query, limit
            )
            if primary_count:
                extracted_text += primary_block
        except Exception as exc:
            logger.warning(
                "[EASA INDEX] Source unavailable: %s",
                exc,
            )
            record_connector_telemetry(
                "EASA Official Index",
                "SRC_002",
                query,
                error=str(exc),
            )
    else:
        record_connector_telemetry(
            "EASA Official Index",
            "SRC_002",
            query,
            coverage_note="TEMPORARILY_UNAVAILABLE; collection paused",
        )

    if "Title:" not in extracted_text:
        return f"No specific records found in FAA or EASA databases for '{query}' within the selected time scope."

    logger.warning(f"[OSINT DEBUG] Regulatory module returned records for '{query}'.")
    return extracted_text


# Collect official aerospace manufacturer announcements and release timestamps.
# A manufacturer release is primary evidence of its statement, not all implied impacts.
@tool("Scrape Manufacturer PR News")
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=2, max=5))
def scrape_manufacturer_pr_news(query: str = "Aviation") -> str:
    # Collect primary-source aerospace announcements with publication metadata.
    """Fetch official press releases from Airbus, Boeing, and COMAC feeds."""
    original_query = query.replace(",", "").replace("  ", " ").strip()
    required_words, safe_query = parse_query_intent(original_query)
    limit_per_feed = get_dynamic_limit()
    scope_days = get_scope_days()
    time_filter = f" when:{scope_days}d" if scope_days else ""

    logger.info(
        f"[OSINT GATHERER] Fetching manufacturer PR feeds for: '{safe_query}' (limit: {limit_per_feed}, scope: {scope_days or 'all'} days)"
    )
    extracted_text = f"--- OFFICIAL MANUFACTURER PRESS RELEASES FOR '{safe_query}' ---\n"

    feeds = {
        "Airbus": "https://www.airbus.com/en/generate-rss-feeds?type=all-press-releases",
        "Boeing": "https://boeing.mediaroom.com/news-releases-statements?pagetemplate=rss",
    }
    mentioned = {
        name for name in feeds
        if re.search(
            rf"\b{re.escape('Boeing' if name.startswith('Boeing') else name)}\b",
            original_query,
            re.I,
        )
    }

    if re.search(
            r"\b(?:faa|type certif\w*|aircraft certif\w*|certif\w*|regulatory approv\w*)\b",
            original_query,
            re.I,
    ):
        mentioned.add("FAA")

    if re.search(
            r"\b(?:ge aerospace|cfm|leap|ge9x|genx)\b",
            original_query, re.I,
    ):
        mentioned.add("GE Aerospace")

    if re.search(
            r"\b(?:rtx|pratt|whitney|collins|gtf|pw1100g)\b",
            original_query, re.I,
    ):
        mentioned.add("RTX")

    if mentioned:
        feeds = {
            name: url
            for name, url in feeds.items()
            if name in mentioned
        }

    total_processed = found_total = rejected_total = 0
    noise_tokens = ("#shorts", "compilation", "takeoff", "landing", "cabin", "trip report", "flight simulator", "msfs")

    for i, (brand, url) in enumerate(feeds.items()):
        if total_processed >= limit_per_feed:
            break

        remaining = limit_per_feed - total_processed
        brand_quota = max(
            1, (remaining + len(feeds) - i - 1) // (len(feeds) - i)
        )

        try:
            source_id = "SRC_030" if brand.startswith("Boeing") else "SRC_005"

            if not is_source_allowed(source_id):
                continue

            resp = safe_http_get(
                url,
                source_id=source_id,
                timeout=12,
                check_robots=True,
            )
            if resp is None or resp.status_code != 200:
                continue
            feed = feedparser.parse(resp.content)
            if not feed.entries:
                continue

            brand_block = f"\n>> {brand} Official Newsroom:\n"
            brand_count = 0
            for entry in feed.entries:
                found_total += 1
                if brand_count >= brand_quota:
                    break

                link = entry.get("link", f"https://www.{brand.lower()}.com")
                if link in COLLECTED_URLS:
                    continue

                raw_date = entry.get("published") or entry.get("updated") or ""

                numeric_date = re.search(
                    r"\b(\d{1,2})/(\d{1,2})/(20\d{2})\b",
                    raw_date
                )

                if numeric_date:
                    month, day, year = map(int, numeric_date.groups())
                    try:
                        pub_date = datetime(year, month, day).date().isoformat()
                    except ValueError:
                        pub_date = "DATE_UNKNOWN"
                else:
                    pub_date = normalize_date_str(raw_date) or "DATE_UNKNOWN"

                if not is_date_within_scope(pub_date):
                    rejected_total += 1
                    continue

                title = entry.get("title", "Untitled release")
                if any(k in title.lower() for k in noise_tokens):
                    continue

                desc = BeautifulSoup(
                    entry.get("summary") or entry.get("description") or "",
                    "html.parser"
                ).get_text(" ", strip=True)[:400]
                # Preserve explicit aircraft/engine model relevance.
                # financial press releases merely because Airbus published them.

                specific_models = _model_tokens(original_query)

                if specific_models:
                    searchable_metadata = f"{title} {desc}".lower()

                    model_matched = any(
                        re.search(
                            rf"(?<![a-z0-9]){re.escape(model)}(?![a-z0-9])",
                            searchable_metadata,
                            re.I,
                        )
                        for model in specific_models
                    )

                    if not model_matched:
                        rejected_total += 1
                        continue
                host = (urlparse(link).hostname or "").lower()
                domains = {
                    "Airbus": ("airbus.com",),
                    "Boeing": ("boeing.com", "boeing.mediaroom.com"),
                }
                official = any(host == d or host.endswith("." + d) for d in domains[brand])
                doc_source_id = source_id if official else "SRC_004"

                body = ""

                if official:
                    page = safe_http_get(
                        link,
                        source_id=doc_source_id,
                        timeout=8,
                        check_robots=True,
                    )

                    if (
                            page is not None
                            and page.status_code == 200
                            and "html" in page.headers.get(
                        "Content-Type", ""
                    ).lower()
                    ):
                        extracted = _extract_news_article_body(page.text)

                        title_terms = {
                            w for w in re.findall(
                                r"[a-z]{4,}", title.lower()
                            )
                            if w not in {
                                "boeing", "airbus", "with",
                                "from", "this", "that",
                            }
                        }

                        body_terms = set(
                            re.findall(r"[a-z]{4,}", extracted.lower())
                        )

                        if (
                                len(extracted) >= 220
                                and len(title_terms & body_terms) >= 2
                        ):
                            body = extracted[:7000]

                raw_text = body if body else (
                        "[OFFICIAL_RSS_METADATA_ONLY: "
                        "FULL ARTICLE UNAVAILABLE]\n"
                        + (desc or title)
                )

                doc_rec = register_collected_document(
                    source_id=doc_source_id,
                    connector_name=(
                        "FAA Newsroom RSS"
                        if brand == "FAA"
                        else "Official Industry PR"
                    ),
                    url=link,
                    title=title,
                    raw_text=raw_text,
                    published_at=pub_date,
                    query_used=original_query,
                )

                doc_rec["origin_type"] = (
                    "PRIMARY_OFFICIAL_FULL_TEXT"
                    if body
                    else (
                        "OFFICIAL_RSS_METADATA_ONLY"
                        if official
                        else "THIRD_PARTY_RSS_METADATA_ONLY"
                    )
                )
                brand_block += (
                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: {doc_source_id}\n"
                    f"DATE: {doc_rec['published_at']}\nTitle: {doc_rec['title']}\n"
                    f"Link: {link}\nSummary: {doc_rec['text']}\n---\n"
                )
                brand_count += 1
                total_processed += 1

            # Outside the "for entry in feed.entries" loop.
            if brand_count:
                extracted_text += brand_block

            record_connector_telemetry(
                f"Official Industry PR / {brand}",
                source_id,
                safe_query,
                found_count=len(feed.entries),
                accepted_count=brand_count,
            )

        except Exception as e:
            logger.error(f"[OSINT GATHERER] PR feed error for {brand}: {str(e)}")

    # Optional historical Boeing archive – metadata only.
    if "Boeing" in feeds and os.getenv("EWS_BOEING_ARCHIVE_APPROVED") == "1":
        start, end = get_time_window_utc()

        if start and (end - start).days > 90:
            max_years = min(5, int(os.getenv("EWS_BOEING_MAX_YEARS", "2")))

            for year in range(
                    end.year,
                    max(start.year, end.year - max_years + 1) - 1,
                    -1,
            ):
                if total_processed >= limit_per_feed:
                    break

                url = (
                    "https://boeing.mediaroom.com/"
                    f"news-releases-statements?year={year}"
                )

                resp = safe_http_get(
                    url, source_id="SRC_030",
                    timeout=12, check_robots=True,
                )
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
    return extracted_text


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
        try:
            auth_resp = requests.post(
                "https://bsky.social/xrpc/com.atproto.server.createSession",
                json={"identifier": handle, "password": password}, timeout=10,
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
        logger.info("[BLUESKY AUDIT] HTTP=%s raw_posts=%d query=%r", response.status_code, len(posts), query)

        if not posts and len(query.split()) >= 4:
            _, short_query = parse_query_intent(query)
            if short_query and short_query.casefold() != query.casefold():
                fb_resp = safe_http_get(
                    "https://bsky.social/xrpc/app.bsky.feed.searchPosts",
                    source_id="SRC_007", params={**params, "q": short_query}, headers=headers, timeout=15,
                )
                if fb_resp is not None and fb_resp.status_code == 200:
                    posts = fb_resp.json().get("posts", []) or []
                    logger.info("[BLUESKY FALLBACK] q=%r raw_posts=%d", short_query, len(posts))

        official_handles = [
            h.strip()
            for h in os.getenv("BLUESKY_OFFICIAL_HANDLES", "").split(",")
            if h.strip()
        ]

        for account in official_handles[:10]:
            resp = safe_http_get(
                "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed",
                source_id="SRC_007",
                params={"actor": account, "limit": min(limit, 10)},
            )
            if resp is not None and resp.status_code == 200:
                posts.extend(
                    item["post"]
                    for item in resp.json().get("feed", [])
                    if "post" in item
                )
        extracted_text = f"--- BLUESKY POSTS FOR '{query}' ---\n"
        count = rejected_scope = rejected_bots = rejected_duplicates = 0
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
        record_connector_telemetry("Bluesky Social Network", "SRC_007", query, len(posts), count, rejected_scope)
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

            effective_max_pages = MAX_PAGES_PER_AIRSHOW

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
                    candidate_links.sort(
                        key=lambda item: item.get("date") or "",
                        reverse=True,
                    )

                    filtered_overview = filter_relevant_paragraphs("\n".join(all_raw_texts), required_words)
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
                                    raw_text=art_filtered[:2500],
                                    published_at=pub_date, query_used=safe_query,
                                )
                                deep_articles_output.append(
                                    f"DOC_ID: {doc_rec['doc_id']} | SOURCE_ID: SRC_006\n"
                                    f"DATE: {doc_rec['published_at']}\nLink: {article_url}\nArticle Content:\n{doc_rec['text']}"
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
                    extracted_text += f"\n>> {airshow_name} ({url}): Failed to load content ({str(e)})\n---\n"

            browser.close()

    except Exception as e:
        logger.error(f"[OSINT GATHERER] Playwright error: {e}")
        record_connector_telemetry("Airshow Websites", "SRC_006", safe_query, error=str(e))
        return f"Fatal browser launch error: {e}"

    record_connector_telemetry(
        "Airshow Websites", "SRC_006", safe_query, total_articles + rejected_scope, total_articles, rejected_scope,
        unknown_dates
    )
    if processed_shows == 0:
        return f"No information found for '{safe_query}' on any monitored airshow websites within the selected time scope."

    logger.warning(
        f"[OSINT DEBUG] Extracted {total_articles} articles across {processed_shows} airshows (limit: {user_limit}).")
    return extracted_text


YOUTUBE_CACHE_FILE = "youtube_transcript_cache.json"
_YT_CACHE_LOCK = threading.Lock()


# Read a cached transcript to avoid repeated remote retrieval.
def _load_yt_transcript_cache() -> Dict[str, str]:
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
    cache[video_id] = transcript[:5000]
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
        record_connector_telemetry("YouTube Videos", "SRC_008", query, error="Missing API keys")
        return "Error: Missing YOUTUBE_API_KEY or GEMINI_API_KEY in .env."

    limit = get_dynamic_limit()
    start_utc, end_utc = get_time_window_utc()
    required_words, _ = parse_query_intent(query)
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
        search_resp = safe_http_get("https://www.googleapis.com/youtube/v3/search", source_id="SRC_008",
                                    params=search_params, timeout=10)
        if search_resp is None or search_resp.status_code != 200:
            record_connector_telemetry("YouTube Videos", "SRC_008", query, error="YouTube API HTTP failure")
            return "Error fetching video data from API."

        videos, rejected_scope = [], 0
        yt_noise = ("#shorts", "compilation", "1:200", "1:400", "scale model", "msfs", "flight simulator",
                    "trip report")

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

                results.append(
                    f"DOC_ID: {doc['doc_id']} | SOURCE_ID: SRC_008\n"
                    f"DATE: {doc['published_at']}\n"
                    f"Title: {doc['title']}\n"
                    f"Link: {v['url']}\n"
                    f"Summary: {doc['text']}\n---"
                )

            return "\n".join(results)

        extracted_text = f"--- RAW VIDEO TRANSCRIPTS FOR '{query}' ---\n"
        processed_videos = gemini_calls_made = 0
        max_gemini_transcriptions = 2
        # Read persistent transcript cache before invoking external transcript and analysis providers.
        yt_cache = _load_yt_transcript_cache()
        client = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options=types.HttpOptions(timeout=30_000, retry_options=types.HttpRetryOptions(attempts=1)),
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
                        else YouTubeTranscriptApi.get_transcript(v["id"], languages=["en", "en-US", "en-GB"])
                    )
                    transcript_text = re.sub(r"\s+", " ", " ".join(seg.get("text", "") for seg in ts_segments)).strip()[
                                      :5000]
                    _save_yt_transcript_cache(v["id"], transcript_text)
                    logger.info(f"[OSINT GATHERER] Fast transcript fetched via YouTubeTranscriptApi for {v['id']}.")
                except Exception as yt_err:
                    if gemini_calls_made >= max_gemini_transcriptions:
                        logger.info(
                            f"[OSINT GATHERER] Skipping slow Gemini audio transcription for {v['id']} (budget {max_gemini_transcriptions} reached).")
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
