"""Additional official sources for Aero_EWS."""

import csv
import hashlib
import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import feedparser
import requests
from bs4 import BeautifulSoup

from aero_ews.collection.financial_registry import (
    SEC_ALIASES,
    SEC_CIK_OVERRIDES,
    SEC_MORE_ALIASES,
    SEC_WATCHLIST,
    SEC_WEAK_AUTO_ALIASES,
    SOURCES,
    _company,
    _extra_aliases,
)
from aero_ews.domain.evidence_text import SEC_VISIBLE_TEXT_METHOD, assess_source_passage

# ESEF/XBRL curated discovery list (API search term, legal issuer terms, KIT aliases) — preserved verbatim.
ESEF_WATCHLIST = {
    "Airbus": ("Airbus", ("Airbus",), ("Airbus", "A320neo", "A321neo", "A350", "A220")),
    "Safran": ("Safran", ("Safran",), ("Safran", "CFM International", "LEAP-1A")),
    "Thales": ("Thales", ("Thales",), ("Thales", "Thales avionics")),
    "Dassault Aviation": ("Dassault", ("Dassault",), ("Dassault Aviation", "Rafale", "Falcon 6X")),
    "Rolls-Royce": ("Rolls", ("Rolls-Royce", "Rolls Royce"), ("Rolls-Royce", "Rolls Royce", "Trent XWB", "Trent 1000")),
    "BAE Systems": ("BAE Systems", ("BAE Systems",), ("BAE Systems",)),
    "Leonardo": ("Leonardo", ("Leonardo",), ("Leonardo", "Leonardo S.p.A.")),
    "Saab": ("Saab", ("Saab",), ("Saab", "Gripen E")),
    "Kongsberg": ("Kongsberg", ("Kongsberg",), ("Kongsberg",)),
    "QinetiQ": ("QinetiQ", ("QinetiQ",), ("QinetiQ",)),
    "Chemring": ("Chemring", ("Chemring",), ("Chemring",)),
    "Babcock": ("Babcock", ("Babcock",), ("Babcock",)),
    "Melrose": ("Melrose", ("Melrose",), ("Melrose", "GKN Aerospace")),
    "Senior": ("Senior", ("Senior plc",), ("Senior plc", "Senior Aerospace")),
    "Avio": ("Avio", ("Avio S.p.A.", "Avio SpA"), ("Avio S.p.A.", "Vega C")),
    "FACC": ("FACC", ("FACC",), ("FACC",)),
    "MTU Aero Engines": ("MTU Aero", ("MTU Aero",), ("MTU Aero Engines",)),
    "Rheinmetall": ("Rheinmetall", ("Rheinmetall",), ("Rheinmetall",)),
}

ESEF_VERIFIED_LEIS = {
    "Airbus": {"MINO79WLOO247M1IL051"},
    "Safran": {"969500UIC89GT3UL7L24"},
    "Rolls-Royce": {"213800EC7997ZBLZJH69", "X57JK1U580XATGR67572"},
}

# SEC topic intent and evidence patterns — preserved verbatim.
_SEC_TOPICS = (
    ("CERTIFICATION", r"\b(?:certif\w*|approv\w*|type certificate)\b",
     r"\b(?:certif\w*|approv\w*|type certificate|amended type certif\w*|ATC)\b"),
    ("SCHEDULE", r"\b(?:delay\w*|postpon\w*|late)\b",
     r"\b(?:delay\w*|postpon\w*|late|schedule\w*)\b"),
    ("DELIVERIES", r"\b(?:deliver\w*|handover\w*)\b", r"\b(?:deliver\w*|handover\w*)\b"),
    ("PRODUCTION", r"\b(?:produc\w*|manufactur\w*|capacity)\b",
     r"\b(?:produc\w*|manufactur\w*|capacity)\b"),
    ("SUPPLY_CHAIN", r"\b(?:shortag\w*|supply|supplier)\b",
     r"\b(?:shortag\w*|supply|supplier|constraint\w*)\b"),
    ("QUALITY", r"\b(?:defect\w*|fail\w*|inspect\w*|problem\w*|issue\w*|durabilit\w*|powder\s+metal|engine\w*)\b",
     r"\b(?:defect\w*|fail\w*|inspect\w*|powder\s+metal|microscopic|contaminat\w*|durabilit\w*|"
     r"fleet\s+management|aog|aircraft\s+on\s+ground|ground\w*|removal\w*|shop\s+visit\w*|"
     r"turnaround|backlog|recall|issue\w*|problem\w*)\b"),
    ("AIRWORTHINESS", r"\b(?:ground\w*|airworth\w*|directive)\b",
     r"\b(?:ground\w*|airworth\w*|directive|regulator\w*)\b"),
    ("COMMERCIAL", r"\b(?:order\w*|contract\w*|invest\w*)\b",
     r"\b(?:order\w*|contract\w*|invest\w*)\b"),
)

_GENERIC_RSS_WORDS = {
    "airbus", "boeing", "embraer", "aircraft", "aviation", "aerospace",
    "easa", "ntsb", "engine", "engines", "airworthiness", "directive",
    "directives", "regulatory", "regulation", "safety", "issues", "issue",
    "problems", "problem", "durability", "inspection", "inspections",
    "status", "update", "updates", "report", "reports", "media",
    "proposed", "incident", "delays", "delay", "fleet", "compliance",
    "document", "applicability", "effective", "date", "official",
}
_SEC_ALLOWED_FORMS = {"8-K", "8-K/A", "10-Q", "10-Q/A", "10-K", "10-K/A", "6-K", "20-F", "20-F/A", "40-F"}
_SEC_PERIODIC_FORMS = {"10-Q", "10-Q/A", "10-K", "10-K/A", "20-F", "20-F/A", "40-F"}
_OFFICIAL_POST_ENDPOINTS = {
    "SRC_028": {"https://api.ted.europa.eu/v3/notices/search"},
    "SRC_029": {
        "https://api.usaspending.gov/api/v2/search/spending_by_award/",
        "https://api.usaspending.gov/api/v2/transactions/",
    },
}


def _sha256(data):
    """Return the lowercase SHA-256 hex digest for bytes or a UTF-8 string."""
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def _is_trusted_https(url, allowed_hosts):
    """Verify that a URL uses clean HTTPS (default port, no credentials) on an approved host."""
    try:
        p = urlparse(url)
        return p.scheme == "https" and p.hostname in allowed_hosts and not p.username and not p.password and p.port in (None, 443)
    except ValueError:
        return False


def _sec_norm(value):
    """Normalize accents, symbols, hyphens, and whitespace consistently."""
    text = unicodedata.normalize("NFKD", str(value or "").casefold()).replace("&", " and ")
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", text)).strip()


def select_sec_targets(query, limit):
    """Resolve relevant SEC filers from the query, or rotate a broad watchlist."""
    from aero_ews.collection.queries import get_program_engine_domain

    universe = [(g, name, ticker) for g, companies in SEC_WATCHLIST.items() for name, ticker in companies.items()]
    search_text = str(query or "")
    if re.search(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", search_text, re.I):
        domain = get_program_engine_domain(search_text)
        oems = domain.get("engine_manufacturers", ())
        extra = list(oems) + list(domain.get("engine_models", ()))
        if any("pratt" in o.lower() or "international aero" in o.lower() for o in oems):
            extra.extend(("RTX", "Pratt & Whitney"))
        if any("cfm" in o.lower() or "ge aerospace" in o.lower() for o in oems):
            extra.append("GE Aerospace")
        if extra:
            search_text = f"{search_text} {' '.join(dict.fromkeys(extra))}"

    norm_q = _sec_norm(search_text)
    matched = []
    for group, name, ticker in universe:
        for alias in (name, *SEC_ALIASES.get(name, ())):
            norm_a = _sec_norm(alias)
            if not norm_a or (norm_a in SEC_WEAK_AUTO_ALIASES and norm_q != norm_a):
                continue
            # Do not infer GE Aerospace from GE HealthCare or GE Vernova queries.
            if name == "GE Aerospace" and norm_a == "general electric" and re.search(r"\b(?:healthcare|health care|vernova)\b", norm_q):
                continue
            if re.search(rf"(?<![a-z0-9]){re.escape(norm_a)}(?![a-z0-9])", norm_q):
                matched.append((group, name, ticker))
                break

    if matched:
        return matched[:limit]
    if os.getenv("EWS_SEC_SCAN_MODE", "targeted").strip().lower() != "rotating":
        return []

    # Rotate through successive slices of the watchlist across days.
    batch_size = max(1, min(30, limit, int(os.getenv("EWS_SEC_COMPANIES_PER_RUN", "5"))))
    batches = (len(universe) + batch_size - 1) // batch_size
    cfg_batch = os.getenv("EWS_SEC_BATCH_INDEX")
    batch = (int(cfg_batch) if cfg_batch is not None else datetime.now(timezone.utc).date().toordinal()) % batches
    start = batch * batch_size
    return universe[start:start + batch_size]


def _esef_match(text, phrase):
    """Return True when normalized phrase matches on alphanumeric token boundaries."""
    needle = _sec_norm(phrase)
    return bool(needle and re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", _sec_norm(text)))


def _esef_date(raw):
    """Parse an ISO YYYY-MM-DD prefix or return DATE_UNKNOWN."""
    try:
        return datetime.strptime(str(raw or "")[:10], "%Y-%m-%d").date().isoformat()
    except ValueError:
        return "DATE_UNKNOWN"


def _esef_safe_url(raw):
    """Resolve and validate a filings.xbrl.org HTTPS URL."""
    if not isinstance(raw, str) or not raw.strip():
        return ""
    candidate = urljoin("https://filings.xbrl.org/", raw.strip())
    return candidate if _is_trusted_https(candidate, {"filings.xbrl.org"}) else ""


def collect_esef_metadata(query, limit, fetch, within_scope, fetch_report=None):
    """ESEF collector with bounded XHTML excerpt extraction from report_url (max 3 issuers)."""
    chosen = [
        (name, search, issuer_terms)
        for name, (search, issuer_terms, aliases) in ESEF_WATCHLIST.items()
        if any(_esef_match(query, alias) for alias in aliases)
    ][:3]
    explicit_kit = bool(re.search(r"\b(?:esef|xbrl|filings?|annual\s+reports?|financial\s+statements?)\b", str(query or ""), re.I))
    fetch_text = callable(fetch_report) and os.getenv("EWS_ESEF_FETCH_REPORT_TEXT", "1") == "1"
    results, seen = [], set()
    max_results = max(1, min(int(limit), 10))

    for target, search, issuer_terms in chosen:
        params = {
            "include": "entity", "sort": "-processed", "page[size]": 25, "page[number]": 1,
            "filter": json.dumps([{"name": "entity.name", "op": "ilike", "val": f"%{search}%"}], separators=(",", ":")),
        }
        response = fetch(params)
        if response is None or response.status_code != 200:
            raise ValueError(f"ESEF API unavailable for {target}")
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ValueError("Invalid ESEF JSON:API payload")

        entities = {}
        for item in payload.get("included", []):
            if isinstance(item, dict) and item.get("type") == "entity" and isinstance(attrs := item.get("attributes") or {}, dict):
                for key in (str(item.get("id") or ""), str(attrs.get("identifier") or "")):
                    if key:
                        entities[key] = attrs

        issuer_checked, seen_periods = 0, set()
        for item in payload["data"]:
            if issuer_checked >= 1:
                break
            if not isinstance(item, dict) or item.get("type") != "filing" or not isinstance(attrs := item.get("attributes") or {}, dict):
                continue
            lei_from_filing = str(attrs.get("fxo_id") or "").split("-", 1)[0]
            if (verified_leis := ESEF_VERIFIED_LEIS.get(target)) and lei_from_filing not in verified_leis:
                continue
            rel_data = ((item.get("relationships") or {}).get("entity") or {}).get("data") or {}
            rel_id = str(rel_data.get("id") or "") if isinstance(rel_data, dict) else ""
            entity = entities.get(rel_id) or entities.get(lei_from_filing) or {}
            issuer = str(entity.get("name") or "").strip()
            if not issuer or not any(_esef_match(issuer, term) for term in issuer_terms):
                continue
            published = _esef_date(attrs.get("published"))
            if not within_scope(published):
                continue
            period_end, filing_id, sha = _esef_date(attrs.get("period_end")), str(item.get("id") or ""), str(attrs.get("sha256") or "")
            unique_key = sha or filing_id
            if not unique_key or unique_key in seen:
                continue
            report_url = _esef_safe_url(attrs.get("report_url"))
            safe_url = next((u for u in (report_url, _esef_safe_url(attrs.get("viewer_url")), _esef_safe_url((item.get("links") or {}).get("self"))) if u), "")
            if not safe_url or (target, period_end) in seen_periods:
                continue

            seen.add(unique_key)
            seen_periods.add((target, period_end))
            issuer_checked += 1
            lei = str(entity.get("identifier") or lei_from_filing)
            doc_title = f"{issuer} ESEF/UKSEF filing ({period_end})"
            evidence_passages, source_hash, content_retrieved = [], "", False

            if fetch_text and report_url and "ixbrlviewer.html" not in report_url.lower():
                rep = fetch_report(report_url)
                if (rep is not None and rep.status_code == 200 and rep.content and len(rep.content) >= 10_000
                        and any(ct in rep.headers.get("Content-Type", "").lower() for ct in ("html", "xml", "xhtml"))):
                    content_retrieved = True
                    source_bytes = re.sub(rb"data:[^\"'\s]{256,}", b"data:omitted", rep.content)
                    source_hash = _sha256(source_bytes)
                    excerpts, _, source_text = _sec_relevant_excerpts(source_bytes, query, max_excerpts=10, structured=True, return_source_text=True)
                    evidence_passages = [
                        {
                            **ex, "document_title": doc_title, "issuer": issuer, "issuer_name": issuer, "issuer_lei": lei,
                            "filing_form": "ESEF/UKSEF", "filing_date": published, "publication_date": published,
                            "event_date": "DATE_UNKNOWN", "query": query, "source_url": report_url, "original_source_url": report_url,
                            "source_content_sha256": source_hash, "passage_sha256": _sha256(ex["text"]),
                            "extraction_method": SEC_VISIBLE_TEXT_METHOD, "validated": True,
                            "validation_status": "SOURCE_PASSAGE_VERIFIED", "evidence_authority": "ESEF_FILING",
                            "claim_authority": "ISSUER_REPORTED", "regulator_decision_verified": False,
                        }
                        for ex in excerpts if _sec_source_span_matches(ex, source_text)
                    ]

            verified = bool(evidence_passages)
            if not verified and not explicit_kit:
                continue
            final_url = report_url if verified else safe_url
            body = (
                f"ESEF/UKSEF OFFICIAL FILING EXCERPTS. Issuer: {issuer}; LEI: {lei}; period end: {period_end}; published: {published}. "
                + " [...] ".join(p["text"] for p in evidence_passages)
                if verified else
                f"[ESEF_FILING_METADATA_ONLY] {issuer}; LEI {lei}; country {attrs.get('country')}; "
                f"accounting period end {period_end}; published {published}; index processed {attrs.get('processed')}; "
                f"filing ID {filing_id}. This is XBRL International repository index metadata only: underlying financial "
                "results, operational events, supply-chain disruptions and causality are NOT verified."
            )
            results.append({
                "title": doc_title, "url": final_url, "body": body, "date": published,
                "metadata": {
                    "body_limit": 20000 if verified else 2500, "document_title": doc_title,
                    "document_type": "ESEF_FILING_VERIFIED_EXCERPTS" if verified else "ESEF_FILING_METADATA_ONLY",
                    "content_status": "PARTIAL_TEXT" if verified else "METADATA_ONLY",
                    "passage_verification_status": "VERIFIED_PASSAGE" if verified else "NO_VERIFIED_PASSAGE",
                    "evidence_verified": verified, "evidence_passages": evidence_passages, "full_text_available": False,
                    "source_content_retrieved": content_retrieved,
                    "source_text_completeness": "PARTIAL_EXCERPTS" if verified else "NOT_RETRIEVED",
                    "evidence_scope": "SOURCE_STATEMENT_ONLY" if verified else "FILING_EXISTENCE_ONLY",
                    "evidence_authority": "ESEF_FILING" if verified else "FILING_INDEX_METADATA",
                    "claim_type": "ISSUER_FILING_EXCERPT" if verified else "FILING_EXISTENCE_ONLY",
                    "source_content_sha256": source_hash, "source_url": final_url, "original_source_url": final_url,
                    "regulator_decision_verified": False,
                    "claim_authority": "ISSUER_REPORTED" if verified else "NO_SUBSTANTIVE_CLAIM",
                    "filing_form": "ESEF/UKSEF", "filing_date": published, "event_date": "DATE_UNKNOWN",
                    "issuer_name": issuer, "issuer_lei": lei, "filing_id": filing_id, "filing_sha256": sha,
                    "filing_hash_provenance": "SOURCE_BYTES_SHA256" if verified else "REPOSITORY_REPORTED_UNVERIFIED",
                    "reported_period_end": period_end, "index_processed_at": str(attrs.get("processed") or ""),
                    "original_published_at": published, "filing_country": str(attrs.get("country") or ""),
                    "aggregation_provider": "XBRL International (filings.xbrl.org)",
                    "validation_error_count": attrs.get("error_count"),
                },
            })
            if len(results) >= max_results:
                return results
    return results


def registry_additions():
    """Build source-registry metadata dictionaries for all extra official sources."""
    kind_map = {"news": "MARKET_DATA", "regulatory": "REGULATORY", "pr": "OEM_PR", "airshow": "INDUSTRY_EVENT"}
    result = {}
    for sid, (name, group, status, method, url) in SOURCES.items():
        entry = {
            "source_id": sid, "name": name, "category": group, "policy_status": status,
            "legal_status": "ALLOWED" if status == "ENABLED" else status, "source_type": kind_map[group],
            "origin": "PRIMARY", "domain": urlparse(url).hostname, "access_method": method, "tos_url": url,
            "last_legal_review_date": "2026-11-09", "verified_domain": True, "rate_limit_rpm": 8,
            "min_interval_sec": 2, "usage_restrictions": "Official API/RSS or manual export; provider terms apply",
        }
        if sid == "SRC_027":
            entry.update(source_type="CORPORATE_FILING", evidence_authority="ISSUER_OFFICIAL_STATEMENT", regulator_decision_verified=False)
        elif sid == "SRC_031":
            entry.update(
                origin="SECONDARY", source_type="CORPORATE_FILING_METADATA",
                tos_url="https://filings.xbrl.org/docs/about", last_legal_review_date="2026-11-10",
                rate_limit_rpm=6, min_interval_sec=10,
                usage_restrictions="Public XBRL API; metadata only. Provider terms and rate limits may change.",
            )
        result[sid] = entry
    return result


def official_api_post(source_id, url, payload):
    """POST only to allowlisted official APIs with rate limiting and size caps."""
    from tools import RATE_LIMITER, is_source_allowed

    if url not in _OFFICIAL_POST_ENDPOINTS.get(source_id, set()):
        raise ValueError("Unapproved API endpoint")
    if not is_source_allowed(source_id):
        return None
    RATE_LIMITER.wait_for_slot(source_id)
    response = requests.post(
        url, json=payload, timeout=25, allow_redirects=False,
        headers={"User-Agent": "AeroEWS Academic Research/2.0", "Accept": "application/json"},
    )
    RATE_LIMITER.record_outcome(source_id, response.status_code == 200)
    if response.status_code != 200 or len(response.content) > 2_000_000:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _sec_model_patterns(query, *, expand_engines=False):
    """Preserve exact program variants, including 737-10 / 737 MAX 10 and engine aliases."""
    from aero_ews.collection.queries import _model_tokens, get_program_engine_domain

    models = list(_model_tokens(query))
    if expand_engines and re.search(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", query or "", re.I):
        for eng in get_program_engine_domain(query).get("engine_models", ()):
            models.append(eng)
            if eng.upper() == "GTF":
                models.append("Geared Turbofan")
            elif eng.upper().startswith("LEAP-1"):
                models.append("LEAP")

    variants = re.findall(r"(?<!\d)737[\s-]*(?:MAX[\s-]*)?(\d{1,2})(?!\w)", query, re.I)
    if variants:
        models = [m for m in models if re.sub(r"\W", "", m) != "737"] + [f"737max{v}" for v in variants]
    patterns = [
        re.compile(r"(?<!\w)" + r"[\s-]*".join(map(re.escape, toks)) + r"(?!\w)", re.I)
        for m in dict.fromkeys(models) if (toks := re.findall(r"[a-z]+|\d+", m.lower()))
    ]
    return patterns + [re.compile(rf"(?<!\w)737[\s-]*{v}(?!\w)", re.I) for v in dict.fromkeys(variants)]


def _sec_claim_type(sentence):
    """Classify what a sentence claims without verifying its truth."""
    rules = (
        ("UNRESOLVED_STATUS", r"\b(?:not|never|pending|awaiting|yet to)\b.{0,65}\b(?:certif\w*|approv\w*|complet\w*|resum\w*|restor\w*)\b|\b(?:certif\w*|approv\w*|complet\w*|resum\w*|restor\w*)\b.{0,65}\b(?:pending|awaiting|not yet|outstanding|incomplete)\b"),
        ("FORECAST_STATUS", r"\b(?:expect\w*|anticipat\w*|intend\w*|forecast\w*|plan\w*|target\w*)\b|\b(?:will|could|may|might|would|should|to be)\s+(?:\w+\s+){0,4}(?:certified|approved|completed|resumed|restored)\b"),
        ("RESOLUTION", r"\b(?:certified|approved|completed|resumed|restored|resolved|restarted|lifted|recovered|cleared)\b|\b(?:received|obtained|granted|issued)\b.{0,75}\b(?:certif\w*|approval)\b"),
        ("ACTIVE_ISSUE", r"\b(?:delay\w*|postpon\w*|pending|shortag\w*|disrupt\w*|suspend\w*|halted|grounded|constraint\w*)\b"),
        ("CAUSE_CLAIM", r"\b(?:because of|due to|caused by|resulted from)\b"),
        ("IMPACT_CLAIM", r"\b(?:deliver\w*|produc\w*|inventor\w*|capacity|order\w*)\b"),
    )
    return next((label for label, pat in rules if re.search(pat, sentence, re.I)), "STATUS_CONTEXT")


def _sec_near_duplicate(first, second):
    """Ignore duplicated wording without merging distinct numbers or claim statuses."""
    if first["claim_type"] != second["claim_type"]:
        return False
    a, b = _sec_norm(first["claim_sentence"]), _sec_norm(second["claim_sentence"])
    if a == b:
        return True
    if len(a) < 100 or len(b) < 100 or re.findall(r"\b\d+\b", a) != re.findall(r"\b\d+\b", b):
        return False
    shingles = lambda v: set(zip(*(w[i:] for i in range(5)))) if len(w := v.split()) >= 5 else set()
    left, right = shingles(a), shingles(b)
    return bool(left and right and len(left & right) / len(left | right) >= 0.93)


def _sec_visible_text(html):
    """Canonical v1 extraction: visible HTML text with collapsed Unicode whitespace."""
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "nav", "footer", "noscript"]):
        node.decompose()
    return soup, re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()


def _sec_source_span_matches(passage, source_text):
    """Verify that stored character offsets match the exact passage and claim sentence."""
    try:
        start, end, claim_start = (int(passage[k]) for k in ("start", "end", "claim_start"))
        return (0 <= start <= claim_start < end <= len(source_text)
                and passage["text"] == source_text[start:end].strip()
                and passage["claim_sentence"] == source_text[claim_start:end].strip())
    except (KeyError, TypeError, ValueError):
        return False


def verify_evidence_passage(passage, source_html=None):
    """Audit stored quote integrity; recheck origin only when fresh source bytes are supplied."""
    if not isinstance(passage, dict):
        return "INCOMPLETE_METADATA"
    doc = {
        "evidence_url": passage.get("source_url"), "sec_filing_url": passage.get("original_filing_url"),
        "issuer_name": passage.get("issuer_name"), "issuer_cik": passage.get("issuer_cik"),
        "issuer_identity_verified": passage.get("issuer_identity_verified"),
        "source_content_sha256": passage.get("source_content_sha256"),
        "evidence_origin": passage.get("evidence_authority"), "evidence_verified": passage.get("validated"),
    }
    verdict, reason = assess_source_passage(doc, passage, source_bytes=source_html)
    if verdict == "VERIFIED":
        return "SOURCE_PASSAGE_VERIFIED" if source_html is not None else "STORED_PASSAGE_INTEGRITY_VERIFIED_REMOTE_UNCHECKED"
    return reason


def _sec_verified_passages(
    excerpts, source_text, source_bytes, *, source_url, original_source_url, filing_url,
    issuer_name, issuer_cik, filing_date, publication_date, filing_form, document_title,
    authority, query, accession_number="",
):
    """Create serializable evidence exclusively from source-exact spans."""
    source_hash = _sha256(source_bytes)
    is_edgar = authority == "SEC_EDGAR"
    doc = dict(
        evidence_url=source_url, sec_filing_url=filing_url, issuer_name=issuer_name, issuer_cik=issuer_cik,
        issuer_identity_verified=is_edgar, source_content_sha256=source_hash, evidence_origin=authority, evidence_verified=True,
    )
    verified = []
    for item in excerpts:
        if not _sec_source_span_matches(item, source_text):
            continue
        passage = dict(
            item, document_title=document_title, issuer=issuer_name, issuer_name=issuer_name, issuer_cik=issuer_cik,
            issuer_identity_verified=is_edgar,
            issuer_identity_status="SEC_CIK_VERIFIED" if is_edgar else "IR_ISSUER_IDENTITY_NOT_INDEPENDENTLY_VERIFIED",
            filing_form=filing_form, filing_date=filing_date, publication_date=publication_date,
            event_date="DATE_UNKNOWN", kit_id=None, kiq_id=None, query=query,
            source_url=source_url, original_source_url=original_source_url, original_filing_url=filing_url,
            accession_number=accession_number, source_content_sha256=source_hash,
            passage_sha256=_sha256(item["text"]), extraction_method=SEC_VISIBLE_TEXT_METHOD,
            validated=True, validation_status="SOURCE_PASSAGE_VERIFIED", evidence_authority=authority,
            claim_authority="ISSUER_REPORTED" if is_edgar else "ISSUER_ATTRIBUTION_UNCONFIRMED",
            direct_kiq_answer_verified=False, regulator_decision_verified=False,
            verification_basis="EXACT_NORMALIZED_SOURCE_SPAN",
        )
        verdict, reason = assess_source_passage(doc, passage, source_bytes=source_bytes)
        if verdict != "UNVERIFIED":
            passage["source_validation_reason"] = reason
            verified.append(passage)
    return verified


def _trusted_response_url(response, requested_url, allowed_hosts):
    """Reject redirects to hosts outside the approved document authority."""
    final_url = str(getattr(response, "url", None) or requested_url)
    return final_url if _is_trusted_https(final_url, allowed_hosts) else ""


def _sec_relevant_excerpts(
    html, query, max_excerpts=16, structured=False, max_total_chars=18000, return_source_text=False,
):
    """Select source-exact claims ranked by query facet coverage and semantic diversity."""
    soup, text = _sec_visible_text(html)
    models = _sec_model_patterns(query, expand_engines=True)
    topics = [(name, re.compile(ev, re.I)) for name, intent, ev in _SEC_TOPICS if re.search(intent, query, re.I)]
    if not (models or topics):
        return ([], len(text), text) if return_source_text else ([], len(text))

    headings = sorted(
        (text.find(t), t)
        for tag in soup.select("h1, h2, h3, h4, h5, h6")[:200]
        if len(t := re.sub(r"\s+", " ", tag.get_text(" ", strip=True)).strip()[:140]) >= 6 and text.count(t) == 1
    )
    boundaries = [0, *(m.end() for m in re.finditer(r"(?<=[.!?])\s+(?=[A-Z\d(\"“])", text)), len(text)]
    spans = [
        (pos, min(pos + 1600, end))
        for start, end in zip(boundaries, boundaries[1:])
        for pos in (range(start, end, 1400) if end - start > 1800 else (start,))
    ]
    weights = {"RESOLUTION": 9, "ACTIVE_ISSUE": 5, "UNRESOLVED_STATUS": 5, "CAUSE_CLAIM": 4, "IMPACT_CLAIM": 3, "FORECAST_STATUS": 1}
    ranked = []
    for i, (start, end) in enumerate(spans):
        sentence = text[start:end].strip()
        if not 18 <= len(sentence) <= 1800:
            continue
        matched_topics = [name for name, pat in topics if pat.search(sentence)]
        if topics and not matched_topics:
            continue
        direct_model = any(pat.search(sentence) for pat in models)
        prev_model = bool(i and models and any(pat.search(text[spans[i - 1][0]:start]) for pat in models))
        if (models and not (direct_model or prev_model)) or (prev_model and not direct_model and _sec_model_patterns(sentence)):
            continue
        q_start = spans[i - 1][0] if prev_model and not direct_model else start
        if end - q_start > 1600:
            continue
        claim = _sec_claim_type(sentence)
        dims = list(dict.fromkeys([
            claim,
            *(["CAUSE_CLAIM"] if re.search(r"\b(?:because of|due to|caused by|resulted from)\b", sentence, re.I) else []),
            *(["IMPACT_CLAIM"] if re.search(r"\b(?:impact\w*|affect\w*|result\w*|deliver\w*|produc\w*|capacity)\b", sentence, re.I) else []),
        ]))
        ranked.append({
            "text": text[q_start:end].strip(), "claim_sentence": sentence, "claim_type": claim,
            "section": next((title for pos, title in reversed(headings) if pos <= q_start), ""),
            "start": q_start, "end": end, "claim_start": start,
            "matched_query_facets": matched_topics, "claim_dimensions": dims,
            "offset_basis": "NORMALIZED_VISIBLE_TEXT",
            "model_linkage": "DIRECT" if direct_model else "ADJACENT_CONTEXT",
            "score": weights.get(claim, 0) + 4 * len(matched_topics) + (7 if direct_model else 1),
        })

    selected, covered_topics, covered_facets, used_chars = [], set(), set(), 0
    remaining = sorted(ranked, key=lambda r: (-r["score"], r["start"]))
    while remaining and len(selected) < max_excerpts:
        eligible = [
            item for item in remaining
            if used_chars + len(item["text"]) <= max_total_chars
            and not any(_sec_near_duplicate(item, s) or (item["claim_start"] == s["claim_start"] and item["end"] == s["end"]) for s in selected)
        ]
        if not eligible:
            break
        chosen = max(eligible, key=lambda it: (
            len(set(it["matched_query_facets"] or ["MODEL_ONLY"]) - covered_topics),
            len({(t, k) for t in (it["matched_query_facets"] or ["MODEL_ONLY"]) for k in it["claim_dimensions"]} - covered_facets),
            it["score"], -it["start"],
        ))
        selected.append(chosen)
        used_chars += len(chosen["text"])
        covered_topics.update(chosen["matched_query_facets"])
        covered_facets.update((t, k) for t in (chosen["matched_query_facets"] or ["MODEL_ONLY"]) for k in chosen["claim_dimensions"])
        remaining.remove(chosen)

    for idx, item in enumerate(selected, 1):
        item["excerpt_id"] = f"E{idx:03d}"
        item.pop("score")
    res = (selected if structured else [i["text"] for i in selected]), len(text)
    return (*res, text) if return_source_text else res


def _sec_ir_fallback(ticker, accession):
    """Use only explicitly configured issuer URLs on approved investor-relations hosts."""
    try:
        val = json.loads(os.getenv("EWS_SEC_IR_FALLBACKS_JSON", "{}")).get(ticker.upper(), {}).get(accession)
        url = val if isinstance(val, str) else (val.get("url", "") if isinstance(val, dict) else "")
        date_val = val.get("date", "DATE_UNKNOWN") if isinstance(val, dict) else "DATE_UNKNOWN"
    except (ValueError, AttributeError, TypeError):
        return None
    if not isinstance(url, str):
        return None
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    allowed = {d.strip().lower() for d in os.getenv("EWS_SEC_IR_ALLOWED_HOSTS", "").split(",")}
    return (url, date_val) if (parsed.scheme == "https" and host and host in allowed) else None


def _collect_sec_edgar(sid, query, limit, output, group_start, get, add, is_date_within_scope, record_connector_telemetry):
    """Collect verified SEC EDGAR filing excerpts (with optional IR fallback) for matched filers."""
    contact = os.getenv("EWS_CONTACT_EMAIL", "").strip().removeprefix("mailto:")
    if "@" not in contact:
        output.append("SEC EDGAR: EWS_CONTACT_EMAIL is missing.")
        return
    if not (selected_companies := select_sec_targets(query, limit)):
        return
    headers = {"User-Agent": f"AeroEWS Academic Research {contact}", "Accept": "application/json, text/html"}
    mapping_resp = get(sid, "https://www.sec.gov/files/company_tickers.json", headers=headers)
    if mapping_resp is None or mapping_resp.status_code != 200:
        return
    cik_map = {
        str(v["ticker"]).upper(): int(v["cik_str"])
        for v in mapping_resp.json().values() if isinstance(v, dict) and v.get("ticker") and v.get("cik_str")
    }
    fetch_full = os.getenv("EWS_SEC_FETCH_FULL_TEXT", "1") == "1"

    for sec_group, company_name, ticker in selected_companies:
        tu = ticker.upper()
        mapped_cik = next((cik_map[v] for v in (tu, tu.replace(".", "-"), tu.replace("-", ".")) if v in cik_map), None)
        override_cik = SEC_CIK_OVERRIDES.get(company_name)
        if mapped_cik and override_cik and int(mapped_cik) != int(override_cik):
            print(f"[SEC] TICKER_CIK_CONFLICT: {company_name} ({ticker})")
            continue
        if (cik := override_cik or mapped_cik) is None:
            print(f"[SEC] UNRESOLVED_ENTITY: {company_name} ({ticker})")
            continue
        cik = int(cik)
        per_company_limit = max(2, limit // max(1, len(selected_companies)))
        max_company_fetches = min(4, per_company_limit + 1)
        issuer_registry_url = f"https://data.sec.gov/submissions/CIK{cik:010d}.json"
        subs = get(sid, issuer_registry_url, headers=headers)
        if subs is None or subs.status_code != 200 or not isinstance(payload := subs.json(), dict):
            continue
        if str(payload.get("cik") or "").lstrip("0") != str(cik):
            print(f"[SEC] CIK_MISMATCH: {company_name} expected={cik}")
            continue
        if not (issuer_name := str(payload.get("name") or "").strip()):
            print(f"[SEC] ISSUER_NAME_MISSING: {company_name} CIK={cik}")
            continue

        filings = payload.get("filings", {}).get("recent", {})
        dates, acc_times = filings.get("filingDate", []), filings.get("acceptanceDateTime", [])
        candidates = sorted(
            ((i, f) for i, f in enumerate(filings.get("form", [])[:120]) if f in _SEC_ALLOWED_FORMS and i < len(dates) and is_date_within_scope(dates[i])),
            key=lambda p: (0 if p[1] in _SEC_PERIODIC_FORMS else 1, p[0]),
        )
        company_filing_count = company_fetches = 0
        for i, form in candidates:
            if len(output) - group_start >= limit or company_filing_count >= per_company_limit or company_fetches >= max_company_fetches:
                break
            company_fetches += 1
            filing_date = dates[i]
            if not is_date_within_scope(filing_date):
                continue
            accession, primary_doc = filings["accessionNumber"][i], filings["primaryDocument"][i]
            if not accession or not primary_doc:
                continue
            doc_url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{accession.replace('-', '')}/{quote(primary_doc)}"
            accepted_at = acc_times[i] if i < len(acc_times) else ""
            body = (
                f"SEC EDGAR OFFICIAL FILING. Verified issuer: {issuer_name}. SEC CIK: {cik}. "
                f"Company ticker: {ticker}. Form: {form}. Filing date: {filing_date}. "
                f"Acceptance time: {accepted_at}. Accession number: {accession}. "
            )
            excerpts, text_len, source_text, source_bytes = [], 0, "", b""
            ev_url, ev_date, orig_src_url, ev_origin = doc_url, filing_date, doc_url, "SEC_EDGAR"
            ev_hash = sec_hash = ""
            sec_retrieved = ir_retrieved = False
            ret_status = "DISABLED_BY_CONFIGURATION"

            if fetch_full:
                page = get(sid, doc_url, headers=headers, check_robots=True, max_bytes=12_000_000)
                final_u = _trusted_response_url(page, doc_url, {"www.sec.gov", "sec.gov"}) if page is not None else ""
                if page is None:
                    ret_status = "UNAVAILABLE_OR_POLICY_BLOCKED"
                elif page.status_code != 200:
                    ret_status = f"HTTP_{page.status_code}"
                elif getattr(page, "aero_content_truncated", False):
                    ret_status = "INCOMPLETE_RESPONSE"
                elif "html" not in page.headers.get("Content-Type", "").lower():
                    ret_status = "NON_HTML_RESPONSE"
                elif not final_u or urlparse(final_u).path != urlparse(doc_url).path:
                    ret_status = "UNAPPROVED_SOURCE_REDIRECT"
                else:
                    source_bytes, ev_url = page.content, final_u
                    sec_hash = ev_hash = _sha256(source_bytes)
                    excerpts, text_len, source_text = _sec_relevant_excerpts(source_bytes, query, structured=True, return_source_text=True)
                    sec_retrieved = bool(source_text)
                    ret_status = "EXCERPTS_FOUND" if excerpts else "NO_QUERY_MATCHING_PASSAGES"

            sec_ret_status, sec_text_len, ir_status = ret_status, text_len, "NOT_ATTEMPTED"
            if fetch_full and not excerpts and (fb := _sec_ir_fallback(ticker, accession)):
                ir_url, ir_date = fb
                ir_page = get(sid, ir_url, headers=headers, check_robots=True, max_bytes=8_000_000)
                ir_final = _trusted_response_url(ir_page, ir_url, {urlparse(ir_url).hostname}) if ir_page is not None else ""
                ir_status = "UNAVAILABLE_OR_UNTRUSTED_SOURCE"
                if ir_page is not None and ir_page.status_code == 200 and not getattr(ir_page, "aero_content_truncated", False) and "html" in ir_page.headers.get("Content-Type", "").lower() and ir_final:
                    ir_retrieved = True
                    ir_ex, ir_len, ir_txt = _sec_relevant_excerpts(ir_page.content, query, structured=True, return_source_text=True)
                    ir_status = "EXCERPTS_FOUND" if ir_ex else "NO_QUERY_MATCHING_PASSAGES"
                    if ir_ex:
                        excerpts, text_len, source_text, source_bytes = ir_ex, ir_len, ir_txt, ir_page.content
                        orig_src_url, ev_url, ev_date, ev_origin = ir_url, ir_final, ir_date, "OFFICIAL_ISSUER_IR"
                        ev_hash, ret_status = _sha256(source_bytes), "IR_FALLBACK_EXCERPTS_FOUND"

            doc_title = f"{ticker} SEC {form} {accession}"
            passages = _sec_verified_passages(
                excerpts, source_text, source_bytes, source_url=ev_url, original_source_url=orig_src_url,
                filing_url=doc_url, issuer_name=issuer_name, issuer_cik=cik, filing_date=filing_date,
                publication_date=ev_date, filing_form=form, document_title=doc_title,
                authority=ev_origin, query=query, accession_number=accession,
            ) if source_bytes else []
            rejected = len(excerpts) - len(passages)
            if rejected:
                ret_status = "PASSAGE_VALIDATION_FAILED"
            if passages:
                body += f"SOURCE-MATCHED ISSUER CLAIMS ({ev_origin}; not independent regulatory decisions): " + " [...] ".join(
                    f"[{p['excerpt_id']} {p['claim_type']} offset={p['start']}] {p['text']}" for p in passages
                )
            else:
                body += f"NO_VERIFIED_QUERY_PASSAGE ({ret_status}). Filing metadata are not evidence of the event."

            verified = bool(passages)
            if not verified and form not in _SEC_PERIODIC_FORMS:
                continue
            is_edgar, is_ir = ev_origin == "SEC_EDGAR", ev_origin == "OFFICIAL_ISSUER_IR"
            add(
                sid, doc_title if is_edgar else f"{ticker} issuer IR evidence for SEC {form} {accession}",
                ev_url, body, ev_date, force=True, body_limit=24000,
                document_type="SEC_FILING_VERIFIED_EXCERPTS" if verified and is_edgar else ("ISSUER_IR_VERIFIED_EXCERPTS" if verified else "SEC_FILING_METADATA_ONLY"),
                content_status="PARTIAL_TEXT" if verified else "METADATA_ONLY",
                source_type="CORPORATE_IR_EXCERPT" if not is_edgar else ("CORPORATE_FILING_EXCERPT" if verified else "CORPORATE_FILING_METADATA"),
                full_text_available=False,
                source_text_completeness="UNVERIFIED_IR_PAGE" if is_ir else ("UNVERIFIED_PRIMARY_DOCUMENT" if sec_retrieved else "NOT_RETRIEVED"),
                source_text_scope="ISSUER_IR_PAGE" if is_ir else ("PRIMARY_FILING_DOCUMENT" if sec_retrieved else "NO_SOURCE_TEXT"),
                source_content_retrieved=sec_retrieved or ir_retrieved, sec_filing_content_retrieved=sec_retrieved,
                sec_primary_document_retrieved=sec_retrieved, evidence_verified=verified,
                evidence_authority=ev_origin if verified else "FILING_INDEX_METADATA",
                claim_authority="ISSUER_REPORTED" if verified and is_edgar else ("ISSUER_ATTRIBUTION_UNCONFIRMED" if verified else "NO_SUBSTANTIVE_CLAIM"),
                evidence_scope="SOURCE_STATEMENT_ONLY" if verified else "FILING_EXISTENCE_ONLY",
                direct_kiq_answer_verified=False, evidence_issuer_identity_verified=verified and is_edgar,
                regulator_decision_verified=False,
                passage_verification_status="VERIFIED_PASSAGE" if verified else "NO_VERIFIED_PASSAGE",
                claim_verification_status="ISSUER_REPORTED_SOURCE_TEXT_CONFIRMED" if verified and is_edgar else ("SOURCE_PASSAGE_VERIFIED_ISSUER_UNCONFIRMED" if verified else "NO_SUBSTANTIVE_CLAIM_VERIFIED"),
                evidence_passages=passages, rejected_passage_count=rejected,
                quote_hashes=[p["passage_sha256"] for p in passages],
                matched_query_facets=sorted({f for p in passages for f in p["matched_query_facets"]}),
                source_content_sha256=ev_hash, sec_filing_content_sha256=sec_hash, evidence_origin=ev_origin,
                evidence_url=ev_url if verified else "", source_url=ev_url if verified else doc_url,
                original_source_url=orig_src_url if verified else doc_url, sec_filing_url=doc_url,
                sec_retrieval_status=sec_ret_status, ir_fallback_status=ir_status, evidence_retrieval_status=ret_status,
                sec_extracted_passage_count=len(excerpts), sec_verified_passage_count=len(passages),
                sec_source_text_length=sec_text_len, evidence_source_text_length=text_len,
                origin_type="PRIMARY_ISSUER_IR" if is_ir else "PRIMARY_ISSUER_FILING",
                accession_number=accession, filing_form=form, sec_filing_date=filing_date, accepted_at=accepted_at,
                issuer_name=issuer_name, issuer_cik=cik, issuer_ticker=ticker, issuer_identity_verified=True,
                issuer_identity_source=issuer_registry_url, sec_company=company_name, sec_group=sec_group,
                sec_ticker=ticker, sec_cik=cik,
            )
            company_filing_count += 1

        sec_added = len(output) - group_start
        record_connector_telemetry("SEC EDGAR", "SRC_027", query, sec_added, sec_added, 0, operational_status="AVAILABLE", search_outcome="RESULTS_RETRIEVED" if sec_added else "NO_MATCH")


def collect_extra(query, platforms, limit):
    """Run all enabled extra official source connectors matching the selected platform groups."""
    from tools import is_date_within_scope, record_connector_telemetry, register_collected_document, safe_http_get

    selected = " ".join(platforms).lower()
    if any(w in selected for w in ("ntsb", "faa", "easa")):
        selected += " regulatory"

    words = [w for w in re.findall(r"[a-z0-9]{4,}", query.lower()) if w not in _GENERIC_RSS_WORDS]
    model_patterns = _sec_model_patterns(query)
    seen_doc_ids, output, limit = set(), [], min(limit, 10)
    review_test = os.getenv("EWS_TEST_REVIEW_SOURCES") == "1" and os.getenv("EWS_ENV", "development").lower() in {"dev", "development", "test"}

    def add(sid, title, url, body, date="DATE_UNKNOWN", force=False, **metadata):
        if len(output) - group_start >= limit:
            return
        if not force:
            haystack = f"{title} {body}"
            if model_patterns:
                if not any(p.search(haystack) for p in model_patterns):
                    return
            elif words:
                if not any(re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", haystack, re.I) for w in words):
                    return
            else:
                return
        if date != "DATE_UNKNOWN" and not is_date_within_scope(date):
            return
        body_limit = metadata.pop("body_limit", 2500)
        doc = register_collected_document(sid, SOURCES[sid][0], url, title, str(body)[:body_limit], str(date), query)
        if doc["doc_id"] in seen_doc_ids:
            return
        seen_doc_ids.add(doc["doc_id"])
        doc.update(metadata)
        for p in doc.get("evidence_passages", ()):
            p["document_id"] = doc["doc_id"]
        output.append(f"DOC_ID: {doc['doc_id']} | SOURCE_ID: {sid}\nDATE: {doc['published_at']}\nTitle: {doc['title']}\nLink: {url}\nSummary: {doc['text']}\n---")

    def get(sid, url=None, **kwargs):
        return safe_http_get(url or SOURCES[sid][4], source_id=sid, timeout=15, **kwargs)

    for sid, (name, group, status, method, url) in SOURCES.items():
        if group not in selected or (status != "ENABLED" and not (review_test and status == "REQUIRES_REVIEW")):
            continue
        group_start = len(output)
        try:
            if method == "RSS":
                resp = get(sid)
                if resp is None or resp.status_code != 200:
                    continue
                entries = feedparser.parse(resp.content).entries
                for entry in entries:
                    title = str(entry.get("title") or "")
                    summary = BeautifulSoup(str(entry.get("summary") or ""), "html.parser").get_text(" ", strip=True)
                    raw_date = str(entry.get("published") or entry.get("updated") or "")
                    if num := re.search(r"\b(\d{1,2})/(\d{1,2})/(20\d{2})\b", raw_date):
                        try:
                            pub_date = datetime(int(num[3]), int(num[1]), int(num[2])).date().isoformat()
                        except ValueError:
                            pub_date = "DATE_UNKNOWN"
                    else:
                        from tools import normalize_date_str
                        pub_date = normalize_date_str(raw_date) or "DATE_UNKNOWN"
                    link = entry.get("link") or url
                    if sid == "SRC_013":
                        code = title.split(" - ", 1)[0].strip().upper()
                        if not code.startswith(("AVIA_", "AIRP_")):
                            continue
                        cat = str(entry.get("category") or "")
                        add(sid, title, link, f"EUROSTAT DATASET METADATA UPDATE. Dataset: {code}. Update category: {cat}. Description: {summary}. This is not a confirmed aviation safety incident.", pub_date, force=True, document_type="STATISTICAL_METADATA_UPDATE", dataset_code=code, update_category=cat)
                    else:
                        add(sid, title, link, summary or title, pub_date)
                        if len(output) - group_start >= limit:
                            break
                    rss_added = len(output) - group_start
                    record_connector_telemetry(name, sid, query, len(entries), rss_added, 0, operational_status="AVAILABLE", search_outcome="RESULTS_RETRIEVED" if rss_added else "NO_MATCH")

            elif sid == "SRC_012":
                resp = get(sid, params={"geo": "EU27_2020", "freq": "M", "lastTimePeriod": 3})
                if resp is None or resp.status_code != 200 or not (values := (data := resp.json()).get("value") or {}):
                    continue
                time_idx = data.get("dimension", {}).get("time", {}).get("category", {}).get("index", {})
                periods = list(time_idx.keys()) if isinstance(time_idx, dict) else []
                from tools import normalize_date_str
                updated_at = normalize_date_str(str(data.get("updated") or "")) or "DATE_UNKNOWN"
                sample = list(values.items())[-8:]
                body = (
                    f"EUROSTAT MONTHLY AVIATION STATISTICAL SERIES. Dataset: avia_paoc. Number of returned statistical values: {len(values)}. "
                    f"Recent periods: {periods[-3:]}. Sample JSON-stat indices and values: {sample}. Dataset updated: {updated_at}. "
                    "Dataset update time is not an aircraft incident date. A period-over-period comparison is required before concluding that traffic increased or decreased."
                )
                add(sid, "Eurostat monthly aviation statistics – avia_paoc", resp.url, body, updated_at, force=True, document_type="STATISTICAL_SERIES", dataset_code="avia_paoc", sample_values=sample, reference_periods=periods[-3:])

            elif method in {"CSV_IMPORT", "XML_IMPORT"}:
                root = Path(os.getenv("EWS_OFFICIAL_EXPORT_DIR", "data/official_exports"))
                if method == "CSV_IMPORT":
                    for path in sorted(root.glob(f"{sid}_*.csv"))[-2:]:
                        with path.open(encoding="utf-8-sig", errors="replace", newline="") as f:
                            for i, row in enumerate(csv.DictReader(f)):
                                if i >= 3000:
                                    break
                                add(sid, f"{name} – {path.stem} / {i + 1}", f"{url}#row-{path.stem}-{i + 1}", f"Official historical export {path.name}: " + " | ".join(f"{k}: {v}" for k, v in row.items() if v)[:900])
                else:
                    from defusedxml import ElementTree as ET
                    for path in sorted(root.glob(f"{sid}_*.xml"))[-2:]:
                        if path.stat().st_size > 15_000_000:
                            continue
                        for i, (_, elem) in enumerate(ET.iterparse(path, events=("end",))):
                            if i > 5000:
                                break
                            if (body := " ".join(elem.itertext())[:900]).strip():
                                add(sid, f"EASA Rules – {path.stem} / {i}", f"{url}#xml-{path.stem}-{i}", body)
                            elem.clear()

            elif sid == "SRC_031":
                contact = os.getenv("EWS_CONTACT_EMAIL", "").strip().removeprefix("mailto:")
                if "@" not in contact:
                    output.append("ESEF: EWS_CONTACT_EMAIL missing")
                    continue
                hdrs = {"User-Agent": f"AeroEWS Academic Research {contact}", "Accept": "application/vnd.api+json, application/json"}
                rep_hdrs = {"User-Agent": f"AeroEWS Academic Research {contact}", "Accept": "application/xhtml+xml, text/html, application/xml;q=0.9"}
                records = collect_esef_metadata(
                    query, limit,
                    fetch=lambda params: get(sid, params=params, headers=hdrs, max_bytes=2_000_000),
                    within_scope=is_date_within_scope,
                    fetch_report=lambda rep_url: get(sid, url=rep_url, headers=rep_hdrs, max_bytes=25_000_000, check_robots=True),
                )
                for item in records:
                    add(sid, item["title"], item["url"], item["body"], item["date"], force=True, **item["metadata"])
                esef_added = len(output) - group_start
                record_connector_telemetry(name, sid, query, len(records), esef_added, 0, operational_status="AVAILABLE", search_outcome="RESULTS_RETRIEVED" if esef_added else "NO_MATCH")

            elif sid == "SRC_027":
                _collect_sec_edgar(sid, query, limit, output, group_start, get, add, is_date_within_scope, record_connector_telemetry)

            elif sid == "SRC_028":
                from tools import get_time_window_utc
                scope_start, _ = get_time_window_utc()
                term = query[:75].replace('"', " ").strip() or "aircraft"
                date_f = f" AND PD>={scope_start:%Y%m%d}" if scope_start else ""
                payload = {"query": f'FT~"{term}"{date_f} SORT BY publication-date DESC', "fields": ["publication-number", "publication-date", "notice-title"], "page": 1, "limit": max(10, limit), "scope": "ALL"}
                for item in (official_api_post(sid, url, payload) or {}).get("notices", []):
                    if len(output) - group_start >= limit:
                        break
                    number, pub_date = str(item.get("publication-number") or ""), str(item.get("publication-date") or "DATE_UNKNOWN")
                    if not number or not is_date_within_scope(pub_date):
                        continue
                    titles = item.get("notice-title") or {}
                    title = (titles.get("eng") or next(iter(titles.values()), "")) if isinstance(titles, dict) else str(titles)
                    add(sid, f"TED {number} – {str(title)[:150]}", "https://ted.europa.eu/en/notice/" + quote(number),
                        f"TED PROCUREMENT NOTICE. Number: {number}. Publication date: {pub_date}. Title: {title}. This is a procurement signal, not a safety incident.",
                        pub_date, force=True, document_type="PROCUREMENT_NOTICE", notice_number=number)

            elif sid == "SRC_029":
                from tools import get_time_window_utc
                scope_start, scope_end = get_time_window_utc()
                payload = {
                    "filters": {"keywords": [query[:160]], "award_type_codes": ["A", "B", "C", "D"], "time_period": [{"start_date": scope_start.date().isoformat() if scope_start else "2000-01-01", "end_date": scope_end.date().isoformat(), "date_type": "action_date"}]},
                    "fields": ["Award ID", "Recipient Name", "Start Date", "End Date", "Award Amount", "Description"],
                    "page": 1, "limit": max(5, limit), "sort": "Award Amount", "order": "desc",
                }
                for award in (official_api_post(sid, url, payload) or {}).get("results", []):
                    if len(output) - group_start >= limit:
                        break
                    award_id, internal_id = str(award.get("Award ID") or ""), award.get("generated_internal_id") or award.get("internal_id")
                    if not award_id or not internal_id:
                        continue
                    txs = official_api_post(sid, "https://api.usaspending.gov/api/v2/transactions/", {"award_id": internal_id, "page": 1, "limit": 100}) or {}
                    recent = sorted((t for t in txs.get("results", []) if t.get("action_date") and is_date_within_scope(str(t["action_date"]))), key=lambda x: str(x["action_date"]), reverse=True)
                    for tx in recent[:2]:
                        if len(output) - group_start >= limit:
                            break
                        act_date, mod, obl, act_type = str(tx.get("action_date") or ""), str(tx.get("modification_number") or "UNKNOWN"), tx.get("federal_action_obligation"), str(tx.get("action_type_description") or "")
                        body = (
                            f"USASPENDING OFFICIAL TRANSACTION. Award: {award_id}. Recipient: {award.get('Recipient Name')}. "
                            f"Original award start: {award.get('Start Date')}. Transaction date: {act_date}. Modification: {mod}. "
                            f"Action type: {act_type}. Incremental obligation: {obl}. Total award: {award.get('Award Amount')}. "
                            f"Description: {str(award.get('Description') or '')[:450]}. This transaction is not necessarily a new contract."
                        )
                        add(sid, f"USAspending {award_id} {mod}", f"https://www.usaspending.gov/award/{quote(str(internal_id))}#{quote(act_date + '-' + mod)}",
                            body, act_date, force=True, document_type="CONTRACT_TRANSACTION" if mod in ("", "UNKNOWN", "0") else "CONTRACT_MODIFICATION",
                            award_id=award_id, modification_number=mod, action_date=act_date, incremental_obligation=obl)
        except (OSError, ValueError, KeyError, IndexError, requests.RequestException, ImportError) as exc:
            output.append(f"{name}: unavailable ({type(exc).__name__}: {exc})")

    return "\n".join(output)
