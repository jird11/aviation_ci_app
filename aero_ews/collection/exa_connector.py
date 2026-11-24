# =============================================================================
# aviation_ci_app | Exa Semantic Search API connector (POST /search)
#
# Responsibility: Execute governed semantic web discovery via Exa Search API,
#   normalize date windows, register every accepted item via register_collected_document()
#   (DOC_xxx, SHA-256, PII redaction, prompt-injection sanitization), and record telemetry.
# Design boundary: Exa results are secondary discovery candidates until verified by
#   FR03 filtering and deterministic Harness validation.
# =============================================================================

"""Governed Exa Search API client integrated with Aero_EWS provenance and telemetry."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv

from tools import (
    COLLECTED_URLS,
    get_dynamic_limit,
    get_time_window_utc,
    is_date_within_scope,
    is_source_allowed,
    normalize_date_str,
    record_connector_telemetry,
    register_collected_document,
    safe_http_post_json,
)

logger = logging.getLogger(__name__)

EXA_SEARCH_ENDPOINT = "https://api.exa.ai/search"
EXA_SOURCE_ID = "SRC_EXA"
EXA_CONNECTOR_NAME = "Exa Semantic Search"

# Low-signal consumer/flight-sim domains excluded by default unless explicitly requested.
_DEFAULT_EXCLUDE_DOMAINS: tuple[str, ...] = (
    "pinterest.com",
    "tiktok.com",
    "instagram.com",
    "facebook.com",
    "reddit.com",
    "flightsim.to",
    "simmarket.com",
)


def _exa_api_key() -> str:
    """Read EXA_API_KEY dynamically so runtime .env updates take effect without restart."""
    key = os.getenv("EXA_API_KEY", "").strip()
    if not key:
        load_dotenv(override=False)
        key = os.getenv("EXA_API_KEY", "").strip()
    return "" if key.lower() in {"", "your_exa_api_key_here", "changeme"} else key


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200d\u2060\ufeff]")
_REUTERS_LINK_ARTIFACT_RE = re.compile(r",?\s*\bopens\s+new\s+tab\b", re.I)
_PAYWALL_TAIL_RE = re.compile(
    r"(?:^|\n)\s*(?:"
    r"Subscribe\s+to\s+(?:gain\s+access|continue\s+reading|read\s+the\s+full)"
    r"|Already\s+have\s+a\s+subscription\?"
    r"|Create\s+a\s+free\s+account\s+to\s+(?:continue|read)"
    r"|Sign\s+(?:in|up)\s+to\s+(?:continue\s+reading|read\s+the\s+full)"
    r"|This\s+article\s+is\s+(?:for\s+subscribers|available\s+exclusively)"
    r").*$",
    re.I | re.S,
)


def _clean_scraped_text(text: str) -> str:
    """Strip invisible Unicode characters, link artifacts, and trailing paywall prompts."""
    cleaned = _ZERO_WIDTH_RE.sub("", str(text or ""))
    cleaned = _REUTERS_LINK_ARTIFACT_RE.sub("", cleaned)
    cleaned = _PAYWALL_TAIL_RE.sub("", cleaned)
    return re.sub(r"[ \t]{2,}", " ", cleaned).strip()


def _exa_domain_authority(url: str) -> tuple[bool, str, str]:
    """Recognize official HTTPS regulator/OEM/Tier-1 domains already governed in ews_validation."""
    parsed = urlparse(str(url or ""))
    if parsed.scheme != "https" or not parsed.hostname:
        return False, "SECONDARY", ""
    host = parsed.hostname.lower().removeprefix("www.")
    from ews_validation import (
        _PRIMARY_OEM_AND_TIER1_DOMAINS,
        _PRIMARY_REGULATOR_DOMAINS,
        is_exact_or_subdomain,
    )
    if is_exact_or_subdomain(host, _PRIMARY_REGULATOR_DOMAINS):
        return True, "PRIMARY_OFFICIAL_WEB", "REGULATOR_OFFICIAL_WEB"
    if is_exact_or_subdomain(host, _PRIMARY_OEM_AND_TIER1_DOMAINS):
        return True, "PRIMARY_OFFICIAL_WEB", "OFFICIAL_ISSUER_PR"
    return False, "SECONDARY", ""


def _clean_domain_list(domains: Optional[List[str]]) -> List[str]:
    cleaned: List[str] = []
    for raw in domains or []:
        if not isinstance(raw, str):
            continue
        candidate = raw.strip().lower()
        if "://" in candidate:
            candidate = (urlparse(candidate).hostname or "").lower()
        candidate = candidate.removeprefix("www.").strip("/")
        if candidate and "." in candidate and candidate not in cleaned:
            cleaned.append(candidate)
    return cleaned[:20]

def search_exa_structured(
    query: str,
    *,
    objective: Optional[str] = None,
    num_results: Optional[int] = None,
    include_domains: Optional[List[str]] = None,
    exclude_domains: Optional[List[str]] = None,
    category: Optional[str] = None,
    start_published_date: Optional[str] = None,
    end_published_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute one governed POST /search call to Exa and register valid DOC_xxx records."""
    safe_query = " ".join(str(query or "").split()).strip()
    if not safe_query:
        record_connector_telemetry(
            EXA_CONNECTOR_NAME, EXA_SOURCE_ID, query,
            operational_status="MISCONFIGURED", search_outcome="NOT_EXECUTED", error="EMPTY_QUERY",
        )
        return {
            "status": "MISCONFIGURED", "error": "EMPTY_QUERY",
            "query": safe_query, "doc_ids": [], "documents": [], "raw_text": "Exa: EMPTY_QUERY.",
        }

    if not is_source_allowed(EXA_SOURCE_ID):
        record_connector_telemetry(
            EXA_CONNECTOR_NAME, EXA_SOURCE_ID, safe_query,
            operational_status="ACCESS_RESTRICTED", search_outcome="NOT_EXECUTED",
            error="SOURCE_POLICY_BLOCKED",
        )
        return {
            "status": "SOURCE_POLICY_BLOCKED", "error": "SRC_EXA disabled by policy",
            "query": safe_query, "doc_ids": [], "documents": [],
            "raw_text": "Exa: SOURCE_POLICY_BLOCKED.",
        }

    api_key = _exa_api_key()
    if not api_key:
        record_connector_telemetry(
            EXA_CONNECTOR_NAME, EXA_SOURCE_ID, safe_query,
            operational_status="MISCONFIGURED", search_outcome="NOT_EXECUTED",
            error="MISSING_EXA_API_KEY",
        )
        return {
            "status": "MISCONFIGURED", "error": "MISSING_EXA_API_KEY",
            "query": safe_query, "doc_ids": [], "documents": [],
            "raw_text": "Exa: MISCONFIGURED (EXA_API_KEY is missing in .env).",
        }

    limit = max(1, min(15, int(num_results if num_results is not None else get_dynamic_limit())))
    max_chars = max(800, min(10000, int(os.getenv("EWS_EXA_MAX_CHARS", "6000"))))
    search_type = os.getenv("EWS_EXA_SEARCH_TYPE", "auto").strip().lower()
    if search_type not in {"auto", "lite", "deep-lite", "deep", "neural", "keyword", "fast"}:
        search_type = "auto"

    start_utc, end_utc = get_time_window_utc()
    eff_start = start_published_date or (start_utc.strftime("%Y-%m-%dT%H:%M:%SZ") if start_utc else None)
    eff_end = end_published_date or end_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    payload: Dict[str, Any] = {
        "query": safe_query,
        "type": search_type,
        "numResults": limit,
        "contents": {
            "text": {"maxCharacters": max_chars},
            "highlights": True,
        },
    }
    if objective and str(objective).strip():
        payload["objective"] = " ".join(str(objective).split())[:500]
    if eff_start:
        payload["startPublishedDate"] = eff_start
    if eff_end:
        payload["endPublishedDate"] = eff_end

    inc = _clean_domain_list(include_domains)
    exc = _clean_domain_list(exclude_domains)
    if inc:
        payload["includeDomains"] = inc
    else:
        payload["excludeDomains"] = list(dict.fromkeys([*_DEFAULT_EXCLUDE_DOMAINS, *exc]))[:25]
    if category and category.strip().lower() in {
        "news", "company", "research paper", "pdf", "financial report", "tweet", "wikipedia.org",
    }:
        payload["category"] = category.strip().lower()

    logger.info(
        "[EXA SEARCH] query=%r type=%s numResults=%d from=%s to=%s includeDomains=%s",
        safe_query, search_type, limit, eff_start or "unrestricted", eff_end, inc or "any",
    )

    http = safe_http_post_json(
        EXA_SEARCH_ENDPOINT,
        payload,
        source_id=EXA_SOURCE_ID,
        headers={"x-api-key": api_key},
        timeout=25,
        max_bytes=3_000_000,
        max_attempts=2,
    )

    if http.response is None or http.status_code != 200 or not http.response_complete:
        err = http.error_type or f"HTTP_{http.status_code}"
        op_status = (
            "AUTHENTICATION_FAILED" if http.status_code == 401
            else "ACCESS_RESTRICTED" if http.status_code == 403
            else "RATE_LIMITED" if http.status_code == 429
            else "TEMPORARILY_UNAVAILABLE"
        )
        record_connector_telemetry(
            EXA_CONNECTOR_NAME, EXA_SOURCE_ID, safe_query,
            error=err, operational_status=op_status, search_outcome="RETRIEVAL_FAILED",
        )
        return {
            "status": op_status, "error": err, "query": safe_query,
            "doc_ids": [], "documents": [],
            "raw_text": f"Exa Semantic Search: {op_status} ({err}).",
        }

    try:
        data = http.response.json()
    except ValueError:
        record_connector_telemetry(
            EXA_CONNECTOR_NAME, EXA_SOURCE_ID, safe_query,
            error="INVALID_JSON", operational_status="TECHNICAL_ERROR", search_outcome="RETRIEVAL_FAILED",
        )
        return {
            "status": "TECHNICAL_ERROR", "error": "INVALID_JSON", "query": safe_query,
            "doc_ids": [], "documents": [],
            "raw_text": "Exa Semantic Search: TECHNICAL_ERROR (invalid JSON response).",
        }

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        record_connector_telemetry(
            EXA_CONNECTOR_NAME, EXA_SOURCE_ID, safe_query,
            error="UNEXPECTED_SCHEMA", operational_status="TECHNICAL_ERROR", search_outcome="RETRIEVAL_FAILED",
        )
        return {
            "status": "TECHNICAL_ERROR", "error": "UNEXPECTED_SCHEMA", "query": safe_query,
            "doc_ids": [], "documents": [],
            "raw_text": "Exa Semantic Search: TECHNICAL_ERROR (unexpected payload schema).",
        }

    accepted_docs: List[Dict[str, Any]] = []
    raw_blocks: List[str] = []
    rejected_scope = unknown_dates = duplicates = 0

    for item in results:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        if url in COLLECTED_URLS:
            duplicates += 1
            continue

        title = _clean_scraped_text(item.get("title") or "") or "Untitled Exa Result"
        text_body = _clean_scraped_text(item.get("text") or "")
        highlights = [
            _clean_scraped_text(h) for h in (item.get("highlights") or [])
            if isinstance(h, str) and _clean_scraped_text(h)
        ]
        summary_text = _clean_scraped_text(item.get("summary") or "")

        raw_pub = str(item.get("publishedDate") or "").strip()
        norm_pub = (
                normalize_date_str(raw_pub)
                or normalize_date_str(url)
                or normalize_date_str(text_body[:400])
        )
        if not norm_pub:
            unknown_dates += 1
        elif not is_date_within_scope(norm_pub):
            rejected_scope += 1
            continue

        # Combine verbatim text and highlights without fabricating content.
        if text_body:
            combined_text = text_body
        elif highlights:
            combined_text = "\n\n".join(highlights)
        elif summary_text:
            combined_text = summary_text
        else:
            combined_text = f"[EXA_METADATA_ONLY] {title}"

        truncated = bool(text_body and len(text_body) >= max_chars - 40)
        if len(text_body) >= 450:
            content_status = "FULL_TEXT"
        elif len(text_body) >= 180 or highlights:
            content_status = "PARTIAL_TEXT"
        else:
            content_status = "METADATA_ONLY"

        verified_official, origin_type, ev_auth = _exa_domain_authority(url)
        doc = register_collected_document(
            source_id=EXA_SOURCE_ID,
            connector_name=EXA_CONNECTOR_NAME,
            url=url,
            title=title,
            raw_text=combined_text,
            published_at=norm_pub or "DATE_UNKNOWN",
            query_used=safe_query,
        )
        doc.update(
            content_status=content_status,
            content_truncated=truncated,
            content_limit_reason="EXA_MAX_CHARACTERS" if truncated else "",
            verified_domain=verified_official or bool(doc.get("verified_domain")),
            origin_type=origin_type if verified_official else doc.get("origin_type", "SECONDARY"),
            evidence_authority=ev_auth or doc.get("evidence_authority", ""),
            exa_score=item.get("score"),
            exa_highlights=highlights[:3],
            event_date="NOT_ESTABLISHED",
            event_date_basis="PUBLICATION_DATE_ONLY" if norm_pub else "NOT_ESTABLISHED",
        )

        accepted_docs.append(doc)
        raw_blocks.append(
            f"\n<untrusted_osint_document id=\"{doc['doc_id']}\" source_id=\"{EXA_SOURCE_ID}\">\n"
            f"DOC_ID: {doc['doc_id']}\n"
            f"DATE: {doc['published_at']}\n"
            f"COLLECTED_AT: {doc['collected_at']}\n"
            f"TITLE: {doc['title']}\n"
            f"SOURCE: {doc['url']}\n"
            f"CONTENT_STATUS: {content_status}\n"
            f"CONTENT: {doc['text']}\n"
            f"</untrusted_osint_document>\n"
            + ("-" * 40) + "\n"
        )

    record_connector_telemetry(
        EXA_CONNECTOR_NAME, EXA_SOURCE_ID, safe_query,
        found_count=len(results),
        accepted_count=len(accepted_docs),
        rejected_out_of_scope=rejected_scope,
        unknown_date_count=unknown_dates,
        operational_status="AVAILABLE",
        search_outcome="RESULTS_RETRIEVED" if accepted_docs else "NO_MATCH",
        coverage_note=f"exa_type={search_type}; duplicates_skipped={duplicates}; include_domains={','.join(inc) if inc else 'ALL'}",
    )

    logger.info(
        "[EXA AUDIT] query=%r raw=%d accepted=%d duplicates=%d out_of_scope=%d unknown_dates=%d",
        safe_query, len(results), len(accepted_docs), duplicates, rejected_scope, unknown_dates,
    )

    raw_text = (
        "".join(raw_blocks) if raw_blocks
        else f"Exa Semantic Search: NO_MATCH (0 new documents accepted for '{safe_query}')."
    )
    return {
        "status": "RESULTS_RETRIEVED" if accepted_docs else "NO_MATCH",
        "error": "",
        "query": safe_query,
        "found_count": len(results),
        "accepted_count": len(accepted_docs),
        "duplicates_skipped": duplicates,
        "rejected_out_of_scope": rejected_scope,
        "doc_ids": [d["doc_id"] for d in accepted_docs],
        "documents": accepted_docs,
        "raw_text": raw_text,
    }


def search_exa_semantic(
    query: str,
    *,
    num_results: Optional[int] = None,
    include_domains: Optional[List[str]] = None,
    exclude_domains: Optional[List[str]] = None,
) -> str:
    """Text-returning convenience wrapper aligned with legacy connector signature."""
    return search_exa_structured(
        query,
        num_results=num_results,
        include_domains=include_domains,
        exclude_domains=exclude_domains,
    )["raw_text"]