"""Additional official sources for Aero_EWS."""

import csv
import hashlib
import json
import os
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse, urljoin

import feedparser
import requests
from bs4 import BeautifulSoup

from aero_ews.domain.evidence_text import assess_source_passage, SEC_VISIBLE_TEXT_METHOD

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

def _sec_norm(value):
    """Normalize accents, symbols, hyphens and whitespace consistently."""
    text = unicodedata.normalize('NFKD', str(value or '').casefold()).replace('&', ' and ')

    text = ''.join((char for char in text if not unicodedata.combining(char)))

    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def select_sec_targets(query, limit):
    """Resolve relevant SEC filers, or rotate a broad watchlist.

    Returns (group, company_name, ticker) tuples.
    """
    from aero_ews.collection.queries import get_program_engine_domain

    universe = [
        (group, name, ticker)
        for group, companies in SEC_WATCHLIST.items()
        for name, ticker in companies.items()
    ]

    search_text = str(query or "")
    if re.search(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", search_text, re.I):
        domain = get_program_engine_domain(search_text)
        oems = domain.get("engine_manufacturers", ())
        extra_terms = list(oems) + list(domain.get("engine_models", ()))
        if any("pratt" in o.lower() or "international aero" in o.lower() for o in oems):
            extra_terms.extend(("RTX", "Pratt & Whitney"))
        if any("cfm" in o.lower() or "ge aerospace" in o.lower() for o in oems):
            extra_terms.append("GE Aerospace")
        if extra_terms:
            search_text = f"{search_text} {' '.join(dict.fromkeys(extra_terms))}"

    normalized_query = _sec_norm(search_text)
    matched = []

    for group, name, ticker in universe:

        # Always include the canonical name, even when aliases exist.
        aliases = (name, *SEC_ALIASES.get(name, ()))

        for alias in aliases:
            normalized_alias = _sec_norm(alias)

            if not normalized_alias:
                continue

            # Prevent ambiguous short names from matching unrelated KITs.
            if (
                    normalized_alias in SEC_WEAK_AUTO_ALIASES
                    and normalized_query != normalized_alias
            ):
                continue

            # General Electric has separately named businesses;
            # do not infer GE Aerospace from a Vernova/HealthCare query.
            if (
                    name == "GE Aerospace"
                    and normalized_alias == "general electric"
                    and re.search(
                r"\b(?:healthcare|health care|vernova)\b",
                normalized_query,
            )
            ):
                continue

            pattern = '(?<![a-z0-9])' + re.escape(normalized_alias) + '(?![a-z0-9])'

            if re.search(pattern, normalized_query):
                matched.append((group, name, ticker))
                break

    if matched:
        return matched[:limit]

    mode = os.getenv('EWS_SEC_SCAN_MODE', 'targeted').strip().lower()

    if mode != "rotating":
        return []

    # Cover successive portions of the universe on successive
    # days, without contacting every SEC filer in one run.
    batch_size = max(1, min(30, limit, int(os.getenv('EWS_SEC_COMPANIES_PER_RUN', '5'))))

    from datetime import timezone

    batches = (len(universe) + batch_size - 1) // batch_size

    configured_batch = os.getenv("EWS_SEC_BATCH_INDEX")

    if configured_batch is not None:
        batch = int(configured_batch) % batches
    else:
        batch = datetime.now(timezone.utc).date().toordinal() % batches

    start = batch * batch_size
    return universe[start:start + batch_size]

# ESEF/XBRL – curated discovery list, not guaranteed issuer coverage.
# (API search term, legal issuer terms, KIT search aliases)
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

def _esef_match(text, phrase):
    needle = _sec_norm(phrase)
    haystack = _sec_norm(text)

    if not needle:
        return False

    return bool(re.search('(?<![a-z0-9])' + re.escape(needle) + '(?![a-z0-9])', haystack))

def _esef_date(raw):
    raw = str(raw or "")[:10]
    try:
        return datetime.strptime(raw, '%Y-%m-%d').date().isoformat()
    except ValueError:
        return "DATE_UNKNOWN"

def _esef_safe_url(raw):
    if not isinstance(raw, str) or not raw.strip():
        return ""

    try:
        candidate = urljoin('https://filings.xbrl.org/', raw.strip())
        parsed = urlparse(candidate)

        if (
            parsed.scheme == "https"
            and parsed.hostname == "filings.xbrl.org"
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
        ):
            return candidate
    except ValueError:
        pass

    return ""

ESEF_VERIFIED_LEIS = {
    "Airbus": {
        "MINO79WLOO247M1IL051",
    },
    "Safran": {
        "969500UIC89GT3UL7L24",
    },
    "Rolls-Royce": {
        "213800EC7997ZBLZJH69",
        "X57JK1U580XATGR67572",
    },
}

def collect_esef_metadata(query, limit, fetch, within_scope, fetch_report=None):
    """
    ESEF collector with bounded XHTML excerpt extraction from report_url.
    Maximum 3 targeted API requests and up to 2 recent filings per issuer.
    """

    chosen = [
        (name, search, issuer_terms)
        for name, (search, issuer_terms, aliases)
        in ESEF_WATCHLIST.items()
        if any(
            _esef_match(query, alias)
            for alias in aliases
        )
    ][:3]

    explicit_filing_kit = bool(re.search(
        r"\b(?:esef|xbrl|filings?|annual\s+reports?|financial\s+statements?)\b",
        str(query or ""), re.I,
    ))
    fetch_text_enabled = (
        callable(fetch_report)
        and os.getenv("EWS_ESEF_FETCH_REPORT_TEXT", "1") == "1"
    )
    results = []
    seen = set()

    for (target, search, issuer_terms) in chosen:
        params = {
            "include": "entity",
            "sort": "-processed",
            "page[size]": 25,
            "page[number]": 1,
            "filter": json.dumps([{
                "name": "entity.name",
                "op": "ilike",
                "val": f"%{search}%",
            }], separators=(",", ":")),
        }

        response = fetch(params)

        if response is None or response.status_code != 200:
            raise ValueError(f'ESEF API unavailable for {target}')

        payload = response.json()

        if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
            raise ValueError('Invalid ESEF JSON:API payload')

        entities = {}

        for item in payload.get("included", []):
            if not isinstance(item, dict) or item.get('type') != 'entity':
                continue

            attrs = item.get("attributes") or {}

            if isinstance(attrs, dict):
                for key in (str(item.get('id') or ''), str(attrs.get('identifier') or '')):
                    if key:
                        entities[key] = attrs

        issuer_checked = 0
        seen_periods = set()
        for item in payload['data']:
            if issuer_checked >= 1:
                break
            if not isinstance(item, dict) or item.get('type') != 'filing':
                continue

            attrs = item.get("attributes") or {}

            if not isinstance(attrs, dict):
                continue

            rel = (item.get('relationships') or {}).get('entity') or {}
            rel_data = rel.get("data") or {}
            lei_from_filing = str(attrs.get('fxo_id') or '').split('-', 1)[0]
            verified_leis = ESEF_VERIFIED_LEIS.get(target)

            if verified_leis and lei_from_filing not in verified_leis:
                continue

            rel_id = str(rel_data.get('id') or '') if isinstance(rel_data, dict) else ''
            entity = entities.get(rel_id) or entities.get(lei_from_filing) or {}
            issuer = str(entity.get('name') or '').strip()

            if not issuer or not any((_esef_match(issuer, term) for term in issuer_terms)):
                continue

            published = _esef_date(attrs.get('published'))
            if not within_scope(published):
                continue

            period_end = _esef_date(attrs.get('period_end'))
            filing_id = str(item.get('id') or '')
            sha = str(attrs.get('sha256') or '')
            unique_key = sha or filing_id

            if not unique_key or unique_key in seen:
                continue

            report_url = _esef_safe_url(attrs.get('report_url'))
            viewer_url = _esef_safe_url(attrs.get('viewer_url'))
            self_url = _esef_safe_url((item.get('links') or {}).get('self'))
            safe_url = next((u for u in (report_url, viewer_url, self_url) if u), "")

            if not safe_url or (target, period_end) in seen_periods:
                continue

            seen.add(unique_key)
            seen_periods.add((target, period_end))
            issuer_checked += 1
            lei = str(entity.get('identifier') or lei_from_filing)
            doc_title = f"{issuer} ESEF/UKSEF filing ({period_end})"

            evidence_passages = []
            source_hash = ""
            content_retrieved = False
            report_truncated = False
            if fetch_text_enabled and report_url and "ixbrlviewer.html" not in report_url.lower():
                rep = fetch_report(report_url)
                if (
                        rep is not None
                        and rep.status_code == 200
                        and rep.content
                        and len(rep.content) >= 10_000
                        and any(ct in rep.headers.get("Content-Type", "").lower() for ct in ("html", "xml", "xhtml"))
                ):
                    content_retrieved = True
                    report_truncated = bool(getattr(rep, "aero_content_truncated", False))
                    source_bytes = re.sub(rb"data:[^\"'\s]{256,}", b"data:omitted", rep.content)
                    source_hash = hashlib.sha256(source_bytes).hexdigest()
                    excerpts, _, source_text = _sec_relevant_excerpts(
                        source_bytes, query, max_excerpts=10, structured=True, return_source_text=True,
                    )
                    for ex in excerpts:
                        if not _sec_source_span_matches(ex, source_text):
                            continue
                        evidence_passages.append({
                            **ex,
                            "document_title": doc_title,
                            "issuer": issuer,
                            "issuer_name": issuer,
                            "issuer_lei": lei,
                            "filing_form": "ESEF/UKSEF",
                            "filing_date": published,
                            "publication_date": published,
                            "event_date": "DATE_UNKNOWN",
                            "query": query,
                            "source_url": report_url,
                            "original_source_url": report_url,
                            "source_content_sha256": source_hash,
                            "passage_sha256": hashlib.sha256(ex["text"].encode("utf-8")).hexdigest(),
                            "extraction_method": SEC_VISIBLE_TEXT_METHOD,
                            "validated": True,
                            "validation_status": "SOURCE_PASSAGE_VERIFIED",
                            "evidence_authority": "ESEF_FILING",
                            "claim_authority": "ISSUER_REPORTED",
                            "regulator_decision_verified": False,
                        })

            verified = bool(evidence_passages)
            if not verified and not explicit_filing_kit:
                continue

            if verified:
                body = (
                    f"ESEF/UKSEF OFFICIAL FILING EXCERPTS. "
                    f"Issuer: {issuer}; LEI: {lei}; period end: {period_end}; published: {published}. "
                    + " [...] ".join(item_p["text"] for item_p in evidence_passages)
                )
            else:
                body = (
                    f"[ESEF_FILING_METADATA_ONLY] "
                    f"{issuer}; LEI {lei}; "
                    f"country {attrs.get('country')}; "
                    f"accounting period end {period_end}; "
                    f"published {published}; "
                    f"index processed {attrs.get('processed')}; "
                    f"filing ID {filing_id}. "
                    "This is XBRL International repository "
                    "index metadata only: underlying financial "
                    "results, operational events, supply-chain "
                    "disruptions and causality are NOT verified."
                )

            results.append({
                "title": doc_title,
                "url": report_url if verified else safe_url,
                "body": body,
                "date": published,
                "metadata": {
                    "body_limit": 20000 if verified else 2500,
                    "document_title": doc_title,
                    "document_type": "ESEF_FILING_VERIFIED_EXCERPTS" if verified else "ESEF_FILING_METADATA_ONLY",
                    "content_status": "PARTIAL_TEXT" if verified else "METADATA_ONLY",
                    "passage_verification_status": "VERIFIED_PASSAGE" if verified else "NO_VERIFIED_PASSAGE",
                    "evidence_verified": verified,
                    "evidence_passages": evidence_passages,
                    "full_text_available": False,
                    "source_content_retrieved": content_retrieved,
                    "source_text_completeness": "PARTIAL_EXCERPTS" if verified else "NOT_RETRIEVED",
                    "evidence_scope": "SOURCE_STATEMENT_ONLY" if verified else "FILING_EXISTENCE_ONLY",
                    "evidence_authority": "ESEF_FILING" if verified else "FILING_INDEX_METADATA",
                    "claim_type": "ISSUER_FILING_EXCERPT" if verified else "FILING_EXISTENCE_ONLY",
                    "source_content_sha256": source_hash,
                    "source_url": report_url if verified else safe_url,
                    "original_source_url": report_url if verified else safe_url,
                    "regulator_decision_verified": False,
                    "claim_authority": "ISSUER_REPORTED" if verified else "NO_SUBSTANTIVE_CLAIM",
                    "filing_form": "ESEF/UKSEF",
                    "filing_date": published,
                    "event_date": "DATE_UNKNOWN",
                    "issuer_name": issuer,
                    "issuer_lei": lei,
                    "filing_id": filing_id,
                    "filing_sha256": sha,
                    "filing_hash_provenance": "SOURCE_BYTES_SHA256" if verified else "REPOSITORY_REPORTED_UNVERIFIED",
                    "reported_period_end": period_end,
                    "index_processed_at": str(attrs.get("processed") or ""),
                    "original_published_at": published,
                    "filing_country": str(attrs.get("country") or ""),
                    "aggregation_provider": "XBRL International (filings.xbrl.org)",
                    "validation_error_count": attrs.get("error_count"),
                },
            })

            if len(results) >= max(1, min(int(limit), 10)):
                return results

    return results

def registry_additions():
    result = {}
    for sid, (name, group, status, method, url) in SOURCES.items():
        kind = {
            "news": "MARKET_DATA",
            "regulatory": "REGULATORY",
            "pr": "OEM_PR",
            "airshow": "INDUSTRY_EVENT",
        }[group]
        result[sid] = {
            "source_id": sid,
            "name": name,
            "category": group,
            "policy_status": status,
            "legal_status": "ALLOWED" if status == "ENABLED" else status,
            "source_type": kind,
            "origin": "PRIMARY",
            "domain": urlparse(url).hostname,
            "access_method": method,
            "tos_url": url,
            "last_legal_review_date": "2026-11-09",
            "verified_domain": True,
            "rate_limit_rpm": 8,
            "min_interval_sec": 2,
            "usage_restrictions": "Official API/RSS or manual export; provider terms apply",
        }

        if sid == "SRC_027":
            result[sid].update(
                source_type="CORPORATE_FILING",
                evidence_authority="ISSUER_OFFICIAL_STATEMENT",
                regulator_decision_verified=False,
            )

        if sid == "SRC_031":
            result[sid].update(
        origin = "SECONDARY",
        source_type = "CORPORATE_FILING_METADATA",
        tos_url = "https://filings.xbrl.org/docs/about",
        last_legal_review_date = "2026-11-10",
        rate_limit_rpm = 6,
        min_interval_sec = 10,
        usage_restrictions = (
            "Public XBRL API; metadata only. "
            "Provider terms and rate limits may change."
        ),
    )

    return result

def official_api_post(source_id, url, payload):
    """POST only to registered official APIs with rate limiting."""
    from tools import RATE_LIMITER, is_source_allowed

    allowed = {
        "SRC_028": {
            "https://api.ted.europa.eu/v3/notices/search",
        },
        "SRC_029": {
            "https://api.usaspending.gov/api/v2/search/spending_by_award/",
            "https://api.usaspending.gov/api/v2/transactions/",
        },
    }

    if url not in allowed.get(source_id, set()):
        raise ValueError("Unapproved API endpoint")

    if not is_source_allowed(source_id):
        return None

    RATE_LIMITER.wait_for_slot(source_id)

    response = requests.post(
        url,
        json=payload,
        timeout=25,
        allow_redirects=False,
        headers={
            "User-Agent": "AeroEWS Academic Research/2.0",
            "Accept": "application/json",
        },
    )

    RATE_LIMITER.record_outcome(source_id, response.status_code == 200)

    if response.status_code != 200:
        return None

    if len(response.content) > 2_000_000:
        return None

    try:
        return response.json()
    except ValueError:
        return None


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


def _sec_model_patterns(query, *, expand_engines=False):
    """Preserve exact program variants, including 737-10 / 737 MAX 10 and program engine aliases."""
    from aero_ews.collection.queries import _model_tokens, get_program_engine_domain

    models = list(_model_tokens(query))
    if expand_engines and re.search(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", query or "",
                                    re.I):
        domain = get_program_engine_domain(query)
        for eng in domain.get("engine_models", ()):
            models.append(eng)
            if eng.upper() == "GTF":
                models.append("Geared Turbofan")
            elif eng.upper().startswith("LEAP-1"):
                models.append("LEAP")

    variants = re.findall(r"(?<!\d)737[\s-]*(?:MAX[\s-]*)?(\d{1,2})(?!\w)", query, re.I)
    if variants:
        models = [model for model in models if re.sub(r"\W", "", model) != "737"]
        models.extend(f"737max{variant}" for variant in variants)
    patterns = []
    for model in dict.fromkeys(models):
        tokens = re.findall(r"[a-z]+|\d+", model.lower())
        if tokens:
            patterns.append(re.compile(r"(?<!\w)" + r"[\s-]*".join(map(re.escape, tokens)) + r"(?!\w)", re.I))
    patterns.extend(
        re.compile(rf"(?<!\w)737[\s-]*{variant}(?!\w)", re.I)
        for variant in dict.fromkeys(variants)
    )
    return patterns


def _sec_claim_type(sentence):
    """Classify what a sentence claims; this does not verify its truth."""
    if (re.search(r"\b(?:not|never|pending|awaiting|yet to)\b.{0,65}\b(?:certif\w*|approv\w*|complet\w*|resum\w*|restor\w*)\b", sentence, re.I)
            or re.search(r"\b(?:certif\w*|approv\w*|complet\w*|resum\w*|restor\w*)\b.{0,65}\b(?:pending|awaiting|not yet|outstanding|incomplete)\b", sentence, re.I)):
        return "UNRESOLVED_STATUS"
    if re.search(r"\b(?:expect\w*|anticipat\w*|intend\w*|forecast\w*|plan\w*|target\w*)\b|\b(?:will|could|may|might|would|should|to be)\s+(?:\w+\s+){0,4}(?:certified|approved|completed|resumed|restored)\b", sentence, re.I):
        return "FORECAST_STATUS"
    if re.search(r"\b(?:certified|approved|completed|resumed|restored|resolved|restarted|lifted|recovered|cleared)\b|\b(?:received|obtained|granted|issued)\b.{0,75}\b(?:certif\w*|approval)\b", sentence, re.I):
        return "RESOLUTION"
    if re.search(r"\b(?:delay\w*|postpon\w*|pending|shortag\w*|disrupt\w*|suspend\w*|halted|grounded|constraint\w*)\b", sentence, re.I):
        return "ACTIVE_ISSUE"
    if re.search(r"\b(?:because of|due to|caused by|resulted from)\b", sentence, re.I):
        return "CAUSE_CLAIM"
    if re.search(r"\b(?:deliver\w*|produc\w*|inventor\w*|capacity|order\w*)\b", sentence, re.I):
        return "IMPACT_CLAIM"
    return "STATUS_CONTEXT"


def _sec_near_duplicate(first, second):
    """Ignore duplicated wording without merging distinct amounts or statuses."""
    if first["claim_type"] != second["claim_type"]:
        return False
    a, b = (_sec_norm(item["claim_sentence"]) for item in (first, second))
    if a == b:
        return True
    if re.findall(r"\b\d+\b", a) != re.findall(r"\b\d+\b", b):
        return False
    if len(a) < 100 or len(b) < 100:
        return False
    def shingles(value):
        words = value.split()
        return set(zip(*(words[i:] for i in range(5)))) if len(words) >= 5 else set()
    left, right = shingles(a), shingles(b)
    return bool(left and right and len(left & right) / len(left | right) >= 0.93)


def _sec_visible_text(html):
    """Canonical v1 extraction: visible HTML with collapsed Unicode whitespace."""
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "nav", "footer", "noscript"]):
        node.decompose()
    return soup, re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()


def _sec_source_span_matches(passage, source_text):
    try:
        start, end, claim_start = (int(passage[key]) for key in ("start", "end", "claim_start"))
        return (0 <= start <= claim_start < end <= len(source_text)
                and passage["text"] == source_text[start:end].strip()
                and passage["claim_sentence"] == source_text[claim_start:end].strip())
    except (KeyError, TypeError, ValueError):
        return False


def verify_evidence_passage(passage, source_html=None):
    """Audit stored quote integrity; recheck origin only with fresh source bytes.

    A stored hash does not independently authenticate the remote issuer or filing.
    """
    if not isinstance(passage, dict):
        return "INCOMPLETE_METADATA"
    doc = {
        "evidence_url": passage.get("source_url"),
        "sec_filing_url": passage.get("original_filing_url"),
        "issuer_name": passage.get("issuer_name"),
        "issuer_cik": passage.get("issuer_cik"),
        "issuer_identity_verified": passage.get("issuer_identity_verified"),
        "source_content_sha256": passage.get("source_content_sha256"),
        "evidence_origin": passage.get("evidence_authority"),
        "evidence_verified": passage.get("validated"),
    }
    verdict, reason = assess_source_passage(doc, passage, source_bytes=source_html)
    if verdict == "VERIFIED":
        return ("SOURCE_PASSAGE_VERIFIED" if source_html is not None
                else "STORED_PASSAGE_INTEGRITY_VERIFIED_REMOTE_UNCHECKED")
    return reason


def _sec_verified_passages(excerpts, source_text, source_bytes, *, source_url,
                           original_source_url, filing_url, issuer_name, issuer_cik,
                           filing_date, publication_date, filing_form, document_title,
                           authority, query, accession_number=""):
    """Create serializable evidence exclusively from source-exact spans."""
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    verified = []
    for item in excerpts:
        if not _sec_source_span_matches(item, source_text):
            continue
        passage = dict(
            item, document_title=document_title,
            issuer=issuer_name, issuer_name=issuer_name, issuer_cik=issuer_cik,
            issuer_identity_verified=(authority == "SEC_EDGAR"),
            issuer_identity_status=("SEC_CIK_VERIFIED" if authority == "SEC_EDGAR"
                                    else "IR_ISSUER_IDENTITY_NOT_INDEPENDENTLY_VERIFIED"),
            filing_form=filing_form,
            filing_date=filing_date, publication_date=publication_date,
            event_date="DATE_UNKNOWN", kit_id=None, kiq_id=None, query=query,
            source_url=source_url, original_source_url=original_source_url,
            original_filing_url=filing_url,
            accession_number=accession_number,
            source_content_sha256=source_hash,
            passage_sha256=hashlib.sha256(item["text"].encode("utf-8")).hexdigest(),
            extraction_method=SEC_VISIBLE_TEXT_METHOD, validated=True,
            validation_status="SOURCE_PASSAGE_VERIFIED", evidence_authority=authority,
            claim_authority=("ISSUER_REPORTED" if authority == "SEC_EDGAR"
                             else "ISSUER_ATTRIBUTION_UNCONFIRMED"),
            direct_kiq_answer_verified=False, regulator_decision_verified=False,
            verification_basis="EXACT_NORMALIZED_SOURCE_SPAN",
        )
        doc = dict(evidence_url=source_url, sec_filing_url=filing_url,
                   issuer_name=issuer_name, issuer_cik=issuer_cik,
                   issuer_identity_verified=authority == "SEC_EDGAR",
                   source_content_sha256=source_hash, evidence_origin=authority,
                   evidence_verified=True)
        verdict, reason = assess_source_passage(doc, passage, source_bytes=source_bytes)
        if verdict != "UNVERIFIED":
            passage["source_validation_reason"] = reason
            verified.append(passage)
    return verified


def _trusted_response_url(response, requested_url, allowed_hosts):
    """Reject redirections to hosts outside the approved document authority."""
    final_url = str(getattr(response, "url", None) or requested_url)
    try:
        parsed = urlparse(final_url)
        if (parsed.scheme == "https" and parsed.hostname in allowed_hosts
                and not parsed.username and not parsed.password and parsed.port in (None, 443)):
            return final_url
    except ValueError:
        pass
    return ""


def _sec_relevant_excerpts(html, query, max_excerpts=16, structured=False,
                           max_total_chars=18000, return_source_text=False):
    """Select source-exact claims by query facet and semantic diversity."""
    soup, text = _sec_visible_text(html)
    models = _sec_model_patterns(query, expand_engines=True)
    topics = [(name, re.compile(evidence, re.I)) for name, intent, evidence in _SEC_TOPICS
              if re.search(intent, query, re.I)]
    if not (models or topics):
        return ([], len(text), text) if return_source_text else ([], len(text))

    headings = []
    for tag in soup.select("h1, h2, h3, h4, h5, h6")[:200]:
        title = re.sub(r"\s+", " ", tag.get_text(" ", strip=True)).strip()[:140]
        if len(title) >= 6 and text.count(title) == 1:
            headings.append((text.find(title), title))
    headings.sort()

    boundaries = [0, *(m.end() for m in re.finditer(r"(?<=[.!?])\s+(?=[A-Z\d(\"“])", text)), len(text)]
    spans = []
    for start, end in zip(boundaries, boundaries[1:]):
        # Keep unpunctuated SEC tables from becoming one artificial claim.
        spans.extend((pos, min(pos + 1600, end)) for pos in
                     (range(start, end, 1400) if end - start > 1800 else (start,)))
    ranked = []
    for i, (start, end) in enumerate(spans):
        sentence = text[start:end].strip()
        if len(sentence) < 18 or len(sentence) > 1800:
            continue
        matched_topics = [name for name, pattern in topics if pattern.search(sentence)]
        if topics and not matched_topics:
            continue
        direct_model = any(pattern.search(sentence) for pattern in models)
        previous_model = bool(i and models and any(
            pattern.search(text[spans[i - 1][0]:start]) for pattern in models
        ))
        if models and not (direct_model or previous_model):
            continue
        # An adjacent claim about another explicit aircraft/engine program
        # must not inherit the requested program from the prior sentence.
        if previous_model and not direct_model and _sec_model_patterns(sentence):
            continue
        quote_start = spans[i - 1][0] if previous_model and not direct_model else start
        if end - quote_start > 1600:
            continue
        claim = _sec_claim_type(sentence)
        dimensions = [claim]
        if re.search(r"\b(?:because of|due to|caused by|resulted from)\b", sentence, re.I):
            dimensions.append("CAUSE_CLAIM")
        if re.search(r"\b(?:impact\w*|affect\w*|result\w*|deliver\w*|produc\w*|capacity)\b", sentence, re.I):
            dimensions.append("IMPACT_CLAIM")
        dimensions = list(dict.fromkeys(dimensions))
        weight = {"RESOLUTION": 9, "ACTIVE_ISSUE": 5, "UNRESOLVED_STATUS": 5,
                  "CAUSE_CLAIM": 4, "IMPACT_CLAIM": 3, "FORECAST_STATUS": 1}.get(claim, 0)
        score = weight + 4 * len(matched_topics) + (7 if direct_model else 1)
        section = next((title for pos, title in reversed(headings) if pos <= quote_start), "")
        ranked.append({"text": text[quote_start:end].strip(), "claim_sentence": sentence,
                       "claim_type": claim, "section": section, "start": quote_start,
                       "end": end, "claim_start": start,
                       "matched_query_facets": matched_topics,
                       "claim_dimensions": dimensions,
                       "offset_basis": "NORMALIZED_VISIBLE_TEXT",
                       "model_linkage": "DIRECT" if direct_model else "ADJACENT_CONTEXT",
                       "score": score})

    selected, covered_topics, covered_facets = [], set(), set()
    remaining = sorted(ranked, key=lambda row: (-row["score"], row["start"]))
    used_chars = 0
    while remaining and len(selected) < max_excerpts:
        eligible = [item for item in remaining
                    if used_chars + len(item["text"]) <= max_total_chars
                    and not any(_sec_near_duplicate(item, saved) or
                                (item["claim_start"] == saved["claim_start"]
                                 and item["end"] == saved["end"])
                                for saved in selected)]
        if not eligible:
            break
        def rank(item):
            facet = item["matched_query_facets"] or ["MODEL_ONLY"]
            combinations = {(topic, kind) for topic in facet
                            for kind in item["claim_dimensions"]}
            return (len(set(facet) - covered_topics),
                    len(combinations - covered_facets), item["score"], -item["start"])
        chosen = max(eligible, key=rank)
        selected.append(chosen)
        used_chars += len(chosen["text"])
        covered_topics.update(chosen["matched_query_facets"])
        covered_facets.update((topic, kind)
                              for topic in (chosen["matched_query_facets"] or ["MODEL_ONLY"])
                              for kind in chosen["claim_dimensions"])
        remaining.remove(chosen)
    for index, item in enumerate(selected, 1):
        item["excerpt_id"] = f"E{index:03d}"
        item.pop("score")
    result = (selected if structured else [item["text"] for item in selected]), len(text)
    return (*result, text) if return_source_text else result


def _sec_ir_fallback(ticker, accession):
    """Use only explicitly configured issuer URLs on approved investor-relations hosts."""
    try:
        entries = json.loads(os.getenv("EWS_SEC_IR_FALLBACKS_JSON", "{}"))
        value = entries.get(ticker.upper(), {}).get(accession)
        url = value if isinstance(value, str) else value.get("url", "") if isinstance(value, dict) else ""
        date = value.get("date", "DATE_UNKNOWN") if isinstance(value, dict) else "DATE_UNKNOWN"
    except (ValueError, AttributeError, TypeError):
        return None
    if not isinstance(url, str):
        return None
    host = (urlparse(url).hostname or "").lower()
    allowed = {domain.strip().lower() for domain in os.getenv("EWS_SEC_IR_ALLOWED_HOSTS", "").split(",")}
    if urlparse(url).scheme != "https" or host not in allowed or not host:
        return None
    return url, date


def collect_extra(query, platforms, limit):
    from tools import (
        safe_http_get, register_collected_document,
        is_date_within_scope, record_connector_telemetry,
    )

    selected = " ".join(platforms).lower()
    if any(w in selected for w in ("ntsb", "faa", "easa")):
        selected += " regulatory"

    _generic_rss_words = {
        "airbus", "boeing", "embraer", "aircraft", "aviation", "aerospace",
        "easa", "ntsb", "engine", "engines", "airworthiness", "directive",
        "directives", "regulatory", "regulation", "safety", "issues", "issue",
        "problems", "problem", "durability", "inspection", "inspections",
        "status", "update", "updates", "report", "reports", "media",
        "proposed", "incident", "delays", "delay", "fleet", "compliance",
        "document", "applicability", "effective", "date", "official",
    }
    words = [
        w for w in re.findall(r"[a-z0-9]{4,}", query.lower())
        if w not in _generic_rss_words
    ]
    model_patterns = _sec_model_patterns(query)
    seen_doc_ids = set()
    output = []
    limit = min(limit, 10)

    def add(sid, title, url, body, date='DATE_UNKNOWN', force=False, **metadata):
        if len(output) - group_start >= limit:
            return
        if not force:
            haystack = f"{title} {body}"
            if model_patterns:
                if not any(pat.search(haystack) for pat in model_patterns):
                    return
            elif words:
                if not any(re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", haystack, re.I) for w in words):
                    return
            else:
                return
        if date != "DATE_UNKNOWN" and not is_date_within_scope(date):
            return
        body_limit = metadata.pop("body_limit", 2500)
        doc = register_collected_document(
            sid,
            SOURCES[sid][0],
            url,
            title,
            str(body)[:body_limit],
            str(date),
            query,
        )
        if doc["doc_id"] in seen_doc_ids:
            return
        seen_doc_ids.add(doc["doc_id"])
        doc.update(metadata)
        for passage in doc.get("evidence_passages", ()):
            passage["document_id"] = doc["doc_id"]
        output.append(
            f"DOC_ID: {doc['doc_id']} | SOURCE_ID: {sid}\n"
            f"DATE: {doc['published_at']}\n"
            f"Title: {doc['title']}\n"
            f"Link: {url}\nSummary: {doc['text']}\n---"
        )

    def get(sid, url=None, **kwargs):
        return safe_http_get(url or SOURCES[sid][4], source_id=sid, timeout=15, **kwargs)

    for sid, (name, group, status, method, url) in SOURCES.items():
        review_test = (
                os.getenv("EWS_TEST_REVIEW_SOURCES") == "1"
                and os.getenv("EWS_ENV", "development").lower()
                in {"dev", "development", "test"}
        )

        if group not in selected or (
                status != "ENABLED"
                and not (review_test and status == "REQUIRES_REVIEW")
        ):
            continue

        group_start = len(output)

        try:

            if method == "RSS":
                response = get(sid)

                if response is None or response.status_code != 200:
                    continue

                entries = feedparser.parse(response.content).entries

                for entry in entries:
                    title = str(entry.get("title") or "")

                    summary = BeautifulSoup(
                        str(entry.get("summary") or ""),
                        "html.parser"
                    ).get_text(" ", strip=True)

                    raw_date = str(entry.get('published') or entry.get('updated') or '')

                    # Standard ISO date or Airbus-style numeric date.
                    numeric = re.search('\\b(\\d{1,2})/(\\d{1,2})/(20\\d{2})\\b', raw_date)

                    if numeric:
                        month, day, year = map(int, numeric.groups())
                        try:
                            pub_date = datetime(year, month, day).date().isoformat()
                        except ValueError:
                            pub_date = "DATE_UNKNOWN"
                    else:
                        from tools import normalize_date_str
                        pub_date = normalize_date_str(raw_date) or "DATE_UNKNOWN"

                    link = entry.get("link") or url

                    if sid == "SRC_013":
                        dataset_code = title.split(" - ", 1)[0].strip().upper()

                        if not dataset_code.startswith(("AVIA_", "AIRP_")):
                            continue

                        category = str(entry.get("category") or "")

                        body = (
                            f"EUROSTAT DATASET METADATA UPDATE. "
                            f"Dataset: {dataset_code}. "
                            f"Update category: {category}. "
                            f"Description: {summary}. "
                            "This is not a confirmed aviation safety incident."
                        )

                        add(
                            sid,
                            title,
                            link,
                            body,
                            pub_date,
                            force=True,
                            document_type="STATISTICAL_METADATA_UPDATE",
                            dataset_code=dataset_code,
                            update_category=category,
                        )
                    else:
                        add(sid, title, link, summary or title, pub_date)

                        if len(output) - group_start >= limit:
                            break

                    rss_added = len(output) - group_start
                    record_connector_telemetry(
                        name, sid, query, len(entries), rss_added, 0,
                        operational_status="AVAILABLE",
                        search_outcome="RESULTS_RETRIEVED" if rss_added else "NO_MATCH",
                    )

            elif sid == 'SRC_012':
                response = get(sid, params={'geo': 'EU27_2020', 'freq': 'M', 'lastTimePeriod': 3})

                if response is None or response.status_code != 200:
                    continue

                data = response.json()

                values = data.get("value") or {}

                if not values:
                    continue

                time_dimension = (
                    data.get('dimension', {}).get('time', {}).get('category', {}).get('index', {})
                )

                periods = list(time_dimension.keys()) if isinstance(time_dimension, dict) else []

                from tools import normalize_date_str

                updated_at = normalize_date_str(str(data.get('updated') or '')) or 'DATE_UNKNOWN'

                sample = list(values.items())[-8:]

                body = (
                    "EUROSTAT MONTHLY AVIATION STATISTICAL SERIES. "
                    "Dataset: avia_paoc. "
                    f"Number of returned statistical values: {len(values)}. "
                    f"Recent periods: {periods[-3:]}. "
                    f"Sample JSON-stat indices and values: {sample}. "
                    f"Dataset updated: {updated_at}. "
                    "Dataset update time is not an aircraft incident date. "
                    "A period-over-period comparison is required before "
                    "concluding that traffic increased or decreased."
                )

                add(
                    sid,
                    "Eurostat monthly aviation statistics – avia_paoc",
                    response.url,
                    body,
                    updated_at,
                    force=True,
                    document_type="STATISTICAL_SERIES",
                    dataset_code="avia_paoc",
                    sample_values=sample,
                    reference_periods=periods[-3:],
                )

            elif method in {"CSV_IMPORT", "XML_IMPORT"}:
                root = Path(os.getenv('EWS_OFFICIAL_EXPORT_DIR', 'data/official_exports'))

                if method == "CSV_IMPORT":
                    for path in sorted(root.glob(f"{sid}_*.csv"))[-2:]:
                        with path.open(encoding='utf-8-sig', errors='replace', newline='') as file:
                            for i, row in enumerate(csv.DictReader(file)):
                                if i >= 3000:
                                    break
                                body = ' | '.join((f'{k}: {v}' for k, v in row.items() if v))[:900]
                                add(
                                    sid, f"{name} – {path.stem} / {i + 1}",
                                    url + f"#row-{path.stem}-{i + 1}",
                                    f"Official historical export {path.name}: " + body,
                                )

                else:
                    from defusedxml import ElementTree as ET

                    for path in sorted(root.glob(f"{sid}_*.xml"))[-2:]:
                        if path.stat().st_size > 15_000_000:
                            continue
                        for (i, (_, elem)) in enumerate(ET.iterparse(path, events=('end',))):
                            if i > 5000:
                                break
                            body = " ".join(elem.itertext())[:900]
                            if body.strip():
                                add(
                                    sid,
                                    f"EASA Rules – {path.stem} / {i}",
                                    url + f"#xml-{path.stem}-{i}",
                                    body,
                                )
                            elem.clear()

            elif sid == 'SRC_031':
                contact = os.getenv('EWS_CONTACT_EMAIL', '').strip().removeprefix('mailto:')

                if "@" not in contact:
                    output.append('ESEF: EWS_CONTACT_EMAIL missing')
                    continue

                headers = {
                    "User-Agent":
                        f"AeroEWS Academic Research {contact}",
                    "Accept":
                        "application/vnd.api+json, application/json",
                }

                report_headers = {
                    "User-Agent": f"AeroEWS Academic Research {contact}",
                    "Accept": "application/xhtml+xml, text/html, application/xml;q=0.9",
                }
                records = collect_esef_metadata(
                    query,
                    limit,
                    fetch=lambda params: get(
                        sid,
                        params=params,
                        headers=headers,
                        max_bytes=2_000_000,
                    ),
                    within_scope=is_date_within_scope,
                    fetch_report=lambda rep_url: get(
                        sid,
                        url=rep_url,
                        headers=report_headers,
                        max_bytes=25_000_000,
                        check_robots=True,
                    ),
                )

                for item in records:
                    add(
                        sid,
                        item["title"],
                        item["url"],
                        item["body"],
                        item["date"],
                        force=True,
                        **item["metadata"],
                    )
                esef_added = len(output) - group_start
                record_connector_telemetry(
                    name, sid, query, len(records), esef_added, 0,
                    operational_status="AVAILABLE",
                    search_outcome="RESULTS_RETRIEVED" if esef_added else "NO_MATCH",
                )

            elif sid == 'SRC_027':
                contact = os.getenv('EWS_CONTACT_EMAIL', '').strip().removeprefix('mailto:')

                if "@" not in contact:
                    output.append('SEC EDGAR: EWS_CONTACT_EMAIL is missing.')

                    continue

                selected_companies = select_sec_targets(query, limit)

                if not selected_companies:
                    continue

                headers = {
                    "User-Agent": f"AeroEWS Academic Research {contact}",
                    "Accept": "application/json, text/html",
                }

                mapping_response = get(
                    sid,
                    "https://www.sec.gov/files/company_tickers.json",
                    headers=headers,
                )

                if mapping_response is None or mapping_response.status_code != 200:
                    continue

                cik_map = {
                    str(value["ticker"]).upper(): int(value["cik_str"])
                    for value in mapping_response.json().values()
                    if isinstance(value, dict)
                       and value.get("ticker")
                       and value.get("cik_str")
                }

                for (sec_group, company_name, ticker) in selected_companies:
                    ticker_variants = (
                        ticker.upper(),
                        ticker.upper().replace(".", "-"),
                        ticker.upper().replace("-", "."),
                    )
                    mapped_cik = next((cik_map[variant] for variant in ticker_variants
                                       if variant in cik_map), None)
                    override_cik = SEC_CIK_OVERRIDES.get(company_name)
                    if mapped_cik and override_cik and int(mapped_cik) != int(override_cik):
                        print(f'[SEC] TICKER_CIK_CONFLICT: {company_name} ({ticker})')
                        continue
                    cik = override_cik or mapped_cik

                    if cik is None:
                        print(f'[SEC] UNRESOLVED_ENTITY: {company_name} ({ticker})')
                        continue

                    cik = int(cik)

                    company_filing_count = 0
                    company_fetches = 0
                    per_company_limit = max(2, limit // max(1, len(selected_companies)))
                    max_company_fetches = min(4, per_company_limit + 1)

                    issuer_registry_url = f"https://data.sec.gov/submissions/CIK{cik:010d}.json"
                    submissions = get(sid, issuer_registry_url, headers=headers)

                    if submissions is None or submissions.status_code != 200:
                        continue

                    submissions_payload = submissions.json()

                    if not isinstance(submissions_payload, dict):
                        continue

                    # The CIK must agree with the requested issuer.
                    if str(submissions_payload.get('cik') or '').lstrip('0') != str(cik):
                        print(f'[SEC] CIK_MISMATCH: {company_name} expected={cik}')
                        continue
                    issuer_name = str(submissions_payload.get('name') or '').strip()
                    if not issuer_name:
                        print(f'[SEC] ISSUER_NAME_MISSING: {company_name} CIK={cik}')
                        continue

                    filings = submissions_payload.get('filings', {}).get('recent', {})
                    allowed_forms = {
                        "8-K", "8-K/A", "10-Q", "10-Q/A", "10-K", "10-K/A",
                        "6-K", "20-F", "20-F/A", "40-F",
                    }
                    periodic_forms = {"10-Q", "10-Q/A", "10-K", "10-K/A", "20-F", "20-F/A", "40-F"}
                    candidate_indices = [
                        (i, form) for i, form in enumerate(filings.get('form', [])[:120])
                        if form in allowed_forms
                           and i < len(filings.get("filingDate", []))
                           and is_date_within_scope(filings["filingDate"][i])
                    ]
                    candidate_indices.sort(key=lambda pair: (0 if pair[1] in periodic_forms else 1, pair[0]))

                    for (i, form) in candidate_indices:
                        if (
                                len(output) - group_start >= limit
                                or company_filing_count >= per_company_limit
                                or company_fetches >= max_company_fetches
                        ):
                            break
                        company_fetches += 1

                        filing_date = filings["filingDate"][i]

                        if not is_date_within_scope(filing_date):
                            continue

                        accession = filings["accessionNumber"][i]

                        primary_document = filings["primaryDocument"][i]

                        if not accession or not primary_document:
                            continue

                        document_url = (
                            f"https://www.sec.gov/Archives/edgar/data/"
                            f"{cik}/{accession.replace('-', '')}/"
                            f"{quote(primary_document)}"
                        )

                        acceptance_times = filings.get('acceptanceDateTime', [])

                        accepted_at = acceptance_times[i] if i < len(acceptance_times) else ''

                        body = (
                            f"SEC EDGAR OFFICIAL FILING. "
                            f"Verified issuer: {issuer_name}. SEC CIK: {cik}. "
                            f"Company ticker: {ticker}. "
                            f"Form: {form}. "
                            f"Filing date: {filing_date}. "
                            f"Acceptance time: {accepted_at}. "
                            f"Accession number: {accession}. "
                        )

                        excerpts, text_length, source_text = [], 0, ""
                        source_bytes = b""
                        evidence_url, evidence_date = document_url, filing_date
                        original_source_url = document_url
                        evidence_origin = "SEC_EDGAR"
                        evidence_hash = sec_filing_hash = ""
                        sec_primary_document_retrieved = False
                        ir_content_retrieved = False
                        retrieval_status = "DISABLED_BY_CONFIGURATION"

                        if os.getenv("EWS_SEC_FETCH_FULL_TEXT", "1") == "1":
                            filing_page = get(
                                sid, document_url, headers=headers, check_robots=True,
                                max_bytes=12_000_000,
                            )
                            sec_final_url = (_trusted_response_url(filing_page, document_url,
                                             {"www.sec.gov", "sec.gov"}) if filing_page is not None else "")
                            if filing_page is None:
                                retrieval_status = "UNAVAILABLE_OR_POLICY_BLOCKED"
                            elif filing_page.status_code != 200:
                                retrieval_status = f"HTTP_{filing_page.status_code}"
                            elif getattr(filing_page, "aero_content_truncated", False):
                                retrieval_status = "INCOMPLETE_RESPONSE"
                            elif "html" not in filing_page.headers.get("Content-Type", "").lower():
                                retrieval_status = "NON_HTML_RESPONSE"
                            elif not sec_final_url or urlparse(sec_final_url).path != urlparse(document_url).path:
                                retrieval_status = "UNAPPROVED_SOURCE_REDIRECT"
                            else:
                                source_bytes = filing_page.content
                                evidence_url = sec_final_url
                                sec_filing_hash = hashlib.sha256(source_bytes).hexdigest()
                                evidence_hash = sec_filing_hash
                                excerpts, text_length, source_text = _sec_relevant_excerpts(
                                    source_bytes, query, structured=True, return_source_text=True,
                                )
                                sec_primary_document_retrieved = bool(source_text)
                                retrieval_status = "EXCERPTS_FOUND" if excerpts else "NO_QUERY_MATCHING_PASSAGES"

                        sec_retrieval_status = retrieval_status
                        sec_source_text_length = text_length
                        ir_fallback_status = "NOT_ATTEMPTED"
                        if (os.getenv("EWS_SEC_FETCH_FULL_TEXT", "1") == "1"
                                and not excerpts and (fallback := _sec_ir_fallback(ticker, accession))):
                            ir_url, ir_date = fallback
                            ir_page = get(
                                sid, ir_url, headers=headers, check_robots=True,
                                max_bytes=8_000_000,
                            )
                            ir_final_url = (_trusted_response_url(ir_page, ir_url,
                                            {urlparse(ir_url).hostname}) if ir_page is not None else "")
                            ir_fallback_status = "UNAVAILABLE_OR_UNTRUSTED_SOURCE"
                            if (ir_page is not None and ir_page.status_code == 200
                                    and not getattr(ir_page, "aero_content_truncated", False)
                                    and "html" in ir_page.headers.get("Content-Type", "").lower()
                                    and ir_final_url):
                                ir_content_retrieved = True
                                ir_excerpts, ir_text_length, ir_source_text = _sec_relevant_excerpts(
                                    ir_page.content, query, structured=True, return_source_text=True,
                                )
                                ir_fallback_status = "EXCERPTS_FOUND" if ir_excerpts else "NO_QUERY_MATCHING_PASSAGES"
                                if ir_excerpts:
                                    excerpts, text_length, source_text = ir_excerpts, ir_text_length, ir_source_text
                                    source_bytes = ir_page.content
                                    original_source_url = ir_url
                                    evidence_url = ir_final_url
                                    evidence_date = ir_date
                                    evidence_origin = "OFFICIAL_ISSUER_IR"
                                    evidence_hash = hashlib.sha256(source_bytes).hexdigest()
                                    retrieval_status = "IR_FALLBACK_EXCERPTS_FOUND"

                        document_title = f"{ticker} SEC {form} {accession}"
                        evidence_passages = _sec_verified_passages(
                            excerpts, source_text, source_bytes, source_url=evidence_url,
                            original_source_url=original_source_url, filing_url=document_url,
                            issuer_name=issuer_name, issuer_cik=cik, filing_date=filing_date,
                            publication_date=evidence_date, filing_form=form,
                            document_title=document_title,
                            authority=evidence_origin, query=query,
                            accession_number=accession,
                        ) if source_bytes else []
                        rejected_passages = len(excerpts) - len(evidence_passages)
                        if rejected_passages:
                            retrieval_status = "PASSAGE_VALIDATION_FAILED"
                        if evidence_passages:
                            body += (f"SOURCE-MATCHED ISSUER CLAIMS ({evidence_origin}; "
                                     "not independent regulatory decisions): "
                                     + " [...] ".join(
                                         f"[{item['excerpt_id']} {item['claim_type']} "
                                         f"offset={item['start']}] {item['text']}"
                                         for item in evidence_passages
                                     ))
                        else:
                            body += (
                                f"NO_VERIFIED_QUERY_PASSAGE ({retrieval_status}). "
                                "Filing metadata are not evidence of the event."
                            )

                        verified = bool(evidence_passages)
                        if not verified and form not in periodic_forms:
                            continue
                        document_type = (
                            "SEC_FILING_VERIFIED_EXCERPTS" if verified and evidence_origin == "SEC_EDGAR"
                            else "ISSUER_IR_VERIFIED_EXCERPTS" if verified
                            else "SEC_FILING_METADATA_ONLY"
                        )

                        add(
                            sid,
                            (document_title if evidence_origin == "SEC_EDGAR"
                             else f"{ticker} issuer IR evidence for SEC {form} {accession}"),
                            evidence_url,
                            body,
                            evidence_date,
                            force=True,
                            body_limit=24000,
                            document_type=document_type,
                            content_status="PARTIAL_TEXT" if verified else "METADATA_ONLY",
                            source_type=("CORPORATE_IR_EXCERPT" if evidence_origin != "SEC_EDGAR"
                                         else "CORPORATE_FILING_EXCERPT" if verified
                                         else "CORPORATE_FILING_METADATA"),
                            full_text_available=False,
                            source_text_completeness=("UNVERIFIED_IR_PAGE" if evidence_origin == "OFFICIAL_ISSUER_IR"
                                                      else "UNVERIFIED_PRIMARY_DOCUMENT" if sec_primary_document_retrieved
                                                      else "NOT_RETRIEVED"),
                            source_text_scope=("ISSUER_IR_PAGE" if evidence_origin == "OFFICIAL_ISSUER_IR"
                                               else "PRIMARY_FILING_DOCUMENT" if sec_primary_document_retrieved
                                               else "NO_SOURCE_TEXT"),
                            source_content_retrieved=(sec_primary_document_retrieved or ir_content_retrieved),
                            sec_filing_content_retrieved=sec_primary_document_retrieved,
                            sec_primary_document_retrieved=sec_primary_document_retrieved,
                            evidence_verified=verified,
                            evidence_authority=evidence_origin if verified else "FILING_INDEX_METADATA",
                            claim_authority=("ISSUER_REPORTED" if verified and evidence_origin == "SEC_EDGAR"
                                             else "ISSUER_ATTRIBUTION_UNCONFIRMED" if verified
                                             else "NO_SUBSTANTIVE_CLAIM"),
                            evidence_scope="SOURCE_STATEMENT_ONLY" if verified else "FILING_EXISTENCE_ONLY",
                            direct_kiq_answer_verified=False,
                            evidence_issuer_identity_verified=verified and evidence_origin == "SEC_EDGAR",
                            regulator_decision_verified=False,
                            passage_verification_status=("VERIFIED_PASSAGE" if verified
                                                         else "NO_VERIFIED_PASSAGE"),
                            claim_verification_status=("ISSUER_REPORTED_SOURCE_TEXT_CONFIRMED"
                                                       if verified and evidence_origin == "SEC_EDGAR"
                                                       else "SOURCE_PASSAGE_VERIFIED_ISSUER_UNCONFIRMED" if verified
                                                       else "NO_SUBSTANTIVE_CLAIM_VERIFIED"),
                            evidence_passages=evidence_passages,
                            rejected_passage_count=rejected_passages,
                            quote_hashes=[item["passage_sha256"] for item in evidence_passages],
                            matched_query_facets=sorted({facet for passage in evidence_passages
                                                        for facet in passage["matched_query_facets"]}),
                            source_content_sha256=evidence_hash,
                            sec_filing_content_sha256=sec_filing_hash,
                            evidence_origin=evidence_origin,
                            evidence_url=evidence_url if verified else "",
                            source_url=evidence_url if verified else document_url,
                            original_source_url=original_source_url if verified else document_url,
                            sec_filing_url=document_url,
                            sec_retrieval_status=sec_retrieval_status,
                            ir_fallback_status=ir_fallback_status,
                            evidence_retrieval_status=retrieval_status,
                            sec_extracted_passage_count=len(excerpts),
                            sec_verified_passage_count=len(evidence_passages),
                            sec_source_text_length=sec_source_text_length,
                            evidence_source_text_length=text_length,
                            origin_type=("PRIMARY_ISSUER_IR" if evidence_origin == "OFFICIAL_ISSUER_IR"
                                         else "PRIMARY_ISSUER_FILING"),
                            accession_number=accession,
                            filing_form=form,
                            sec_filing_date=filing_date,
                            accepted_at=accepted_at,
                            issuer_name=issuer_name,
                            issuer_cik=cik,
                            issuer_ticker=ticker,
                            issuer_identity_verified=True,
                            issuer_identity_source=issuer_registry_url,
                            sec_company=company_name,
                            sec_group=sec_group,
                            sec_ticker=ticker,
                            sec_cik=cik,
                        )
                        company_filing_count += 1

                    sec_added = len(output) - group_start
                    record_connector_telemetry(
                        "SEC EDGAR", "SRC_027", query, sec_added, sec_added, 0,
                        operational_status="AVAILABLE",
                        search_outcome="RESULTS_RETRIEVED" if sec_added else "NO_MATCH",
                    )

            elif sid == 'SRC_028':
                from tools import get_time_window_utc

                scope_start, scope_end = get_time_window_utc()

                date_filter = f' AND PD>={scope_start:%Y%m%d}' if scope_start else ''

                search_term = query[:75].replace('"', " ").strip()

                if not search_term:
                    search_term = "aircraft"

                payload = {
                    "query": (
                        f'FT~"{search_term}"'
                        f"{date_filter} "
                        "SORT BY publication-date DESC"
                    ),
                    "fields": [
                        "publication-number",
                        "publication-date",
                        "notice-title",
                    ],
                    "page": 1,
                    "limit": max(10, limit),
                    "scope": "ALL",
                }

                data = official_api_post(sid, url, payload) or {}

                for item in data.get('notices', []):
                    if len(output) - group_start >= limit:
                        break

                    number = str(item.get('publication-number') or '')

                    publication_date = str(item.get('publication-date') or 'DATE_UNKNOWN')

                    if not number:
                        continue

                    if not is_date_within_scope(publication_date):
                        continue

                    titles = item.get("notice-title") or {}

                    if isinstance(titles, dict):
                        title = titles.get('eng') or next(iter(titles.values()), '')

                    else:

                        title = str(titles)

                    document_url = 'https://ted.europa.eu/en/notice/' + quote(number)

                    body = (
                        f"TED PROCUREMENT NOTICE. "
                        f"Number: {number}. "
                        f"Publication date: {publication_date}. "
                        f"Title: {title}. "
                        "This is a procurement signal, not a safety incident."
                    )

                    add(
                        sid,
                        f"TED {number} – {str(title)[:150]}",
                        document_url,
                        body,
                        publication_date,
                        force=True,
                        document_type="PROCUREMENT_NOTICE",
                        notice_number=number,
                    )

            elif sid == 'SRC_029':
                from tools import get_time_window_utc

                scope_start, scope_end = get_time_window_utc()

                date_start = scope_start.date().isoformat() if scope_start else '2000-01-01'

                payload = {
                    "filters": {
                        "keywords": [query[:160]],
                        "award_type_codes": ["A", "B", "C", "D"],
                        "time_period": [{
                            "start_date": date_start,
                            "end_date": scope_end.date().isoformat(),
                            "date_type": "action_date",
                        }],
                    },
                    "fields": [
                        "Award ID",
                        "Recipient Name",
                        "Start Date",
                        "End Date",
                        "Award Amount",
                        "Description",
                    ],
                    "page": 1,
                    "limit": max(5, limit),
                    "sort": "Award Amount",
                    "order": "desc",
                }

                awards = official_api_post(sid, url, payload) or {}

                for award in awards.get('results', []):
                    if len(output) - group_start >= limit:
                        break

                    award_id = str(award.get("Award ID") or "")

                    internal_id = award.get('generated_internal_id') or award.get('internal_id')

                    if not award_id or not internal_id:
                        continue

                    transactions = official_api_post(
                        sid,
                        "https://api.usaspending.gov/api/v2/transactions/",
                        {'award_id': internal_id, 'page': 1, 'limit': 100},
                    ) or {}

                    recent = [
                        transaction
                        for transaction in transactions.get("results", [])
                        if transaction.get("action_date")
                           and is_date_within_scope(
                            str(transaction["action_date"])
                        )
                    ]

                    recent.sort(key=lambda x: str(x['action_date']), reverse=True)

                    for transaction in recent[:2]:
                        if len(output) - group_start >= limit:
                            break

                        action_date = str(transaction.get('action_date') or '')

                        modification = str(transaction.get('modification_number') or 'UNKNOWN')

                        obligation = transaction.get('federal_action_obligation')

                        action_type = str(transaction.get('action_type_description') or '')

                        if modification in ('', 'UNKNOWN', '0'):
                            document_type = "CONTRACT_TRANSACTION"

                        else:

                            document_type = "CONTRACT_MODIFICATION"

                        body = (
                            f"USASPENDING OFFICIAL TRANSACTION. "
                            f"Award: {award_id}. "
                            f"Recipient: {award.get('Recipient Name')}. "
                            f"Original award start: {award.get('Start Date')}. "
                            f"Transaction date: {action_date}. "
                            f"Modification: {modification}. "
                            f"Action type: {action_type}. "
                            f"Incremental obligation: {obligation}. "
                            f"Total award: {award.get('Award Amount')}. "
                            f"Description: {str(award.get('Description') or '')[:450]}. "
                            "This transaction is not necessarily a new contract."
                        )

                        document_url = (
                                "https://www.usaspending.gov/award/"
                                + quote(str(internal_id))
                                + "#"
                                + quote(action_date + "-" + modification)
                        )

                        add(
                            sid,
                            f"USAspending {award_id} {modification}",
                            document_url,
                            body,
                            action_date,
                            force=True,
                            document_type=document_type,
                            award_id=award_id,
                            modification_number=modification,
                            action_date=action_date,
                            incremental_obligation=obligation,
                        )

        except (
                OSError, ValueError, KeyError, IndexError,
                requests.RequestException, ImportError
        ) as exc:
            output.append(f"{name}: unavailable ({type(exc).__name__}: {exc})")

    return "\n".join(output)

