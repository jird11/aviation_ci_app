# =============================================================================
# aviation_ci_app | OSINT collection orchestration and source allocation
#
# Responsibility: Distribute KIT/KIQ queries across governed source connectors
#   and enforce per-source retrieval budgets.
# Design boundary: Collection produces evidence candidates; source relevance
#   and event validity are determined downstream.
# =============================================================================

"""Source-specific OSINT collection and KIQ-driven query orchestration."""

import ast
import json
import re
import urllib.parse
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

import feedparser
from bs4 import BeautifulSoup

from aero_ews.collection.queries import (
    AGENCIES, COMPONENTS, NEED_SEARCH_TERMS, REGULATORY_RE,
    _model_aliases, _model_tokens, build_federal_register_queries,
    build_social_video_queries, classify_information_needs,
    get_program_engine_domain,
)
from aero_ews.collection.query_expansion import build_cross_program_queries
from ews_sources_extra import collect_extra
from ews_state import (
    Callable, KIQPlan, List, PIPELINE_STATE, SOURCE_REGISTRY,
    extract_youtube_transcript, logger, math, os, reset_collected_urls,
    scrape_airshow_website, scrape_manufacturer_pr_news,
    scrape_ntsb_investigations, scrape_regulatory_agencies,
    search_aerospace_news, search_bluesky_aviation,
)
from tools import (
    AEROSPACE_SUPPLIER_REGISTRY, get_dynamic_limit, get_scope_days,
    is_date_within_scope, news_api_search_key, record_connector_telemetry,
    register_collected_document, safe_http_get,
)

# Registry of runtime-registered optional connectors and classification patterns (preserved verbatim).
OPTIONAL_SOURCE_CONNECTORS = {}

_PURPOSE_PATTERNS = (
    ("HISTORICAL_STATUS", r"\b(?:historical|previous\s+status|as\s+of\s+(?:20\d{2}|[a-z]+\s+20\d{2}))\b"),
    ("CONTRADICTION_CHECK", r"\b(?:contradict\w*|conflict\w*|disput\w*|denial|denied)\b"),
    ("RESOLUTION", r"\b(?:resolv\w*|restor\w*|resum\w*|complet\w*|certified|approved|lifted|reopen\w*|ended)\b"),
    ("CAUSE", r"\b(?:caus\w*|reason\w*|root\s+cause|due\s+to|trigger\w*)\b"),
    ("IMPACT", r"\b(?:impact\w*|effect\w*|consequence\w*|delivery\s+delay\w*|capacity\s+loss)\b"),
    ("CURRENT_STATUS", r"\b(?:status|latest|current|decision|progress|update\w*)\b"),
)
_ENGINE_VARIANT_RE = re.compile(r"\b(?:[A-Z]{2,}[A-Z0-9]*-\d+[A-Z0-9-]*|[A-Z]{2,}\d+[A-Z0-9-]*)\b", re.I)
_ISSUE_PATTERN = re.compile(
    r"\b(?:delay\w*|shortag\w*|defect\w*|failur\w*|fault\w*|ground\w*|restrict\w*|disrupt\w*|"
    r"backlog\w*|recall\w*|risk\w*|issue\w*|problem\w*|constraint\w*|incident\w*|investigat\w*|"
    r"compliance|bottleneck\w*)\b", re.I,
)
_STATUS_TOPIC = re.compile(
    r"\b(?:delay\w*|shortag\w*|disrupt\w*|backlog\w*|suspend\w*|ground\w*|defect\w*|failur\w*|"
    r"certif\w*|approv\w*|compliance|restrict\w*|inspection\s+requirements?|production\s+halt\w*|"
    r"status|progress|resolution)\b", re.I,
)
_INCOMPLETE_STATUSES = frozenset({
    "RETRIEVAL_INCOMPLETE", "RETRIEVAL_FAILED", "SOURCE_ACCESS_BLOCKED",
    "SOURCE_ERROR", "SOURCE_UNAVAILABLE", "FILTER_UNAVAILABLE",
})
_INCOMPLETE_PRIORITY = (
    "SOURCE_ACCESS_BLOCKED", "RETRIEVAL_INCOMPLETE", "RETRIEVAL_FAILED",
    "SOURCE_ERROR", "SOURCE_UNAVAILABLE", "FILTER_UNAVAILABLE",
)
_LEGACY_STATUS = re.compile(
    r"(?im)^\s*\[?(RETRIEVAL_INCOMPLETE|RETRIEVAL_FAILED|SOURCE_ACCESS_BLOCKED|"
    r"SOURCE_ERROR|SOURCE_UNAVAILABLE|FILTER_UNAVAILABLE|NO_RESULTS|NO_RECORDS)\]?(?=\s|:|$)"
)
_QUERY_STOPWORDS = frozenset({"a", "an", "the", "of", "for", "on", "in", "about", "with", "from"})
_NEED_TO_PURPOSE = (
    ("INSPECTION_OBLIGATION", "REGULATORY_REQUIREMENT"),
    ("INSPECTION_DEADLINE", "COMPLIANCE_DEADLINE"),
    ("REGULATORY_REVISION", "REGULATORY_REVISION"),
    ("RETURN_TO_SERVICE", "RETURN_TO_SERVICE"),
    ("INSPECTION_COMPLETION", "INSPECTION_COMPLETION"),
)
_VALID_COLLECTION_STATUSES = _INCOMPLETE_STATUSES | {"RECORDS", "NO_RESULTS"}
_ENGINE_TOPIC_RE = re.compile(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", re.I)


@contextmanager
def _scoped_dynamic_limit(value: int | None = None):
    """Preserve and restore EWS_DYNAMIC_LIMIT across a connector invocation."""
    prev = os.environ.get("EWS_DYNAMIC_LIMIT")
    if value is not None:
        os.environ["EWS_DYNAMIC_LIMIT"] = str(value)
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop("EWS_DYNAMIC_LIMIT", None)
        else:
            os.environ["EWS_DYNAMIC_LIMIT"] = prev


def _semantic_query_key(query: str) -> tuple[str, ...]:
    """Deduplicate word-order variants without merging opposite or different statuses."""
    return tuple(sorted(w for w in re.findall(r"[a-z0-9]+", query.casefold()) if w not in _QUERY_STOPWORDS))


def _kit_query_parts(kit: str) -> tuple[str, str, str]:
    """Extract explicit subject, issue, and date/agency constraints without inventing scope."""
    original = re.sub(r"\s+", " ", str(kit or "")).strip()
    date_re = (r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
               r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+20\d{2}\b"
               r"|\b20\d{2}-\d{2}(?:-\d{2})?\b")
    constraints = [m.group() for m in re.finditer(date_re, original, re.I)]
    constraints.extend(a.upper() for a in AGENCIES if re.search(rf"\b{re.escape(a)}\b", original, re.I))

    subject = ""
    for entry in AEROSPACE_SUPPLIER_REGISTRY:
        for alias in sorted((entry["official_name"], *entry.get("aliases", [])), key=len, reverse=True):
            if len(alias) >= 4 and (m := re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", original, re.I)):
                subject = m.group()
                break
        if subject:
            break
    if not subject:
        subject = next((m.group() for m in _ENGINE_VARIANT_RE.finditer(original)), "")

    issue = re.sub(rf"(?<!\w){re.escape(subject)}(?!\w)", " ", original, count=1, flags=re.I) if subject else original
    for c in constraints:
        issue = re.sub(rf"(?<!\w){re.escape(c)}(?!\w)", " ", issue, count=1, flags=re.I)
    issue = re.sub(r"\s+", " ", re.sub(r"\b(?:latest|current|status|updates?|progress)\b", " ", issue, flags=re.I)).strip()
    return subject, issue, " ".join(dict.fromkeys(constraints))


def _engine_variants(text: str) -> set[str]:
    """Preserve distinct named engine/model variants without assuming a fixed catalog."""
    return {m.group().upper() for m in _ENGINE_VARIANT_RE.finditer(str(text or ""))
            if not re.search(r"-(?:19|20)\d{2}(?:-|$)", m.group(), re.I)}


def _normalize_planned_queries(value: object, kit: str) -> List[str]:
    """Repair unambiguous Planner serialization errors; never guess missing queries."""
    if isinstance(value, str):
        raw = value.strip()
        if len(raw) > 10000:
            logger.warning("[KIQ PLANNER] Oversized query payload; falling back to original KIT")
            return [kit]
        if raw.startswith("[") and raw.endswith("]"):
            try:
                value = json.loads(raw)
            except ValueError:
                try:
                    value = ast.literal_eval(raw)
                except (ValueError, SyntaxError):
                    value = None
        elif "\n" in raw:
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            parsed = [re.fullmatch(r"(?:[-*•]|\d+[.)])\s+(.+)", ln) for ln in lines]
            value = [m.group(1) for m in parsed] if parsed and all(parsed) else None
        else:
            value = [raw] if raw and not raw.startswith(("{", "[")) and not re.search(r"\S\s*,\s*\S", raw) else None

    if not isinstance(value, list) or len(value) > 24 or any(not isinstance(q, str) or len(q) > 350 or "\x00" in q for q in value):
        logger.warning("[KIQ PLANNER] Invalid query structure; falling back to original KIT")
        return [kit]
    return [q.strip() for q in value if q.strip()] or [kit]


def _model_search_aliases(model: str) -> set[str]:
    """Normalize published aircraft aliases without losing the exact variant."""
    codes = [model, model[1:]] if re.match(r"B\d{3}(?!\d)", model, re.I) else [model]
    return {re.sub(r"[\s-]+", "", v.casefold()) for c in codes for v in _model_aliases(c)}


def _query_purpose(query: str) -> str:
    """Classify the primary evidence search purpose of a query."""
    for purpose, pat in _PURPOSE_PATTERNS[:2]:
        if re.search(pat, query, re.I):
            return purpose
    needs = classify_information_needs(query)
    if matched := next((p for n, p in _NEED_TO_PURPOSE if n in needs), None):
        return matched
    return next((p for p, pat in _PURPOSE_PATTERNS if re.search(pat, query, re.I)), "EVENT_DISCOVERY")


def _kit_precision(kit: str) -> str:
    """Classify KIT scope specificity as EXACT, PROGRAM, or BROAD."""
    if re.search(r"\bFAA-20\d{2}-\d{3,7}\b", kit, re.I):
        return "EXACT"
    models, variants = _model_tokens(kit), _engine_variants(kit)
    has_constraint = (
        any(re.search(rf"\b{re.escape(a)}\b", kit, re.I) for a in AGENCIES)
        or bool(re.search(r"\b(?:20\d{2}|\d{4}-\d{2}(?:-\d{2})?)\b", kit))
        or bool(re.search(r"\b(?:inspection\s+requirements?|compliance\s+deadlines?|mandatory\s+inspections?|gearbox|specific\s+component|docket)\b", kit, re.I))
    )
    remainder = kit
    for m in models:
        for alias in _model_aliases(m[1:] if re.match(r"B\d{3}(?!\d)", m, re.I) else m):
            remainder = re.sub(re.escape(alias), " ", remainder, flags=re.I)
    details = re.findall(r"\b[a-z]{4,}\b", remainder, re.I)
    if (models or variants) and (has_constraint or len(details) >= 6 or len(variants) > 1):
        return "EXACT"
    return "PROGRAM" if (models or variants) else "BROAD"


def _status_query(kit: str, outcome_index: int = 0) -> str:
    """Build a targeted follow-up query for a requested evidence need."""
    if _query_purpose(kit) == "HISTORICAL_STATUS" or outcome_index < 0:
        return ""
    needs = classify_information_needs(kit)
    terms = [term for i in range(2) for need in needs for term in NEED_SEARCH_TERMS[need][i:i + 1]]
    if not terms or len(_model_tokens(kit)) > 2 or len(_engine_variants(kit)) > 2 or outcome_index >= len(terms):
        return ""
    subject, issue, qualifiers = _kit_query_parts(kit)
    if not issue or sum(1 for a in AGENCIES if re.search(rf"\b{re.escape(a)}\b", kit, re.I)) > 1:
        return ""
    return " ".join(p for p in (subject, issue, qualifiers, terms[outcome_index]) if p)


def _preserves_kit(kit: str, query: str, precision: str) -> bool:
    """Permit semantic alternatives and verified engine expansion while retaining mandatory identities."""
    orig_models, q_models = _model_tokens(kit), _model_tokens(query)
    variants, q_variants = _engine_variants(kit), _engine_variants(query)
    allowed_models, allowed_variants = list(orig_models), set(variants)

    if precision != "EXACT" and orig_models and not variants and _ENGINE_TOPIC_RE.search(kit):
        eng_str = " ".join(get_program_engine_domain(kit)["engine_models"])
        allowed_models.extend(_model_tokens(eng_str))
        allowed_variants.update(_engine_variants(eng_str))

    if allowed_models and any(not any(_model_search_aliases(m) & _model_search_aliases(o) for o in allowed_models) for m in q_models):
        return False
    if q_variants - allowed_variants:
        return False
    if precision == "EXACT":
        if any(not any(_model_search_aliases(m) & _model_search_aliases(o) for o in q_models) for m in orig_models):
            return False
        if variants - q_variants:
            return False
        norm_regs = lambda s: {re.sub(r"[-\s]+", "", m.group().casefold()) for m in REGULATORY_RE.finditer(s)}
        if not norm_regs(kit).issubset(norm_regs(query)):
            return False
        if any(re.search(pat, kit, re.I) and not re.search(pat, query, re.I) for pat, _ in COMPONENTS):
            return False
        wanted = set(classify_information_needs(kit)) - {"GENERAL_STATUS"}
        if wanted and not (wanted & set(classify_information_needs(query))):
            return False

    subject, _, _ = _kit_query_parts(kit)
    if subject and not orig_models and not variants and not re.search(rf"(?<!\w){re.escape(subject)}(?!\w)", query, re.I):
        return False
    return True


def _plan_queries(kit: str, planned: List[str]) -> List[dict]:
    """Filter, deduplicate, and classify planner queries by evidence purpose."""
    items, seen, precision = [], set(), _kit_precision(kit)
    make_item = lambda q: {"query": q, "purpose": _query_purpose(q), "needs": classify_information_needs(q)}

    for raw_q in _normalize_planned_queries(planned, kit):
        q = (raw_q or "").strip()
        if (key := _semantic_query_key(q)) and key not in seen and _preserves_kit(kit, q, precision):
            items.append(make_item(q))
            seen.add(key)

    covered = {n for item in items for n in item["needs"]}
    kit_key = _semantic_query_key(kit)
    if (precision == "BROAD" or (set(classify_information_needs(kit)) - covered) or not items) and kit_key not in seen:
        items.insert(0, make_item(kit))
        seen.add(kit_key)
    if not items:
        items.append(make_item(kit))
    if not any(i["needs"] for i in items) and (sq := _status_query(kit)) and _semantic_query_key(sq) not in seen:
        items.append(make_item(sq))
    if precision == "EXACT":
        items.sort(key=lambda i: i["purpose"] not in {"REGULATORY_REQUIREMENT", "COMPLIANCE_DEADLINE", "REGULATORY_REVISION", "CURRENT_STATUS"})
    return items


def _bluesky_status_queries(kit: str, planned: List[str]) -> List[str]:
    """Backwards-compatible, position-independent status-query expansion."""
    return [item["query"] for item in _plan_queries(kit, planned)]


def _has_status_candidates(progress: dict) -> bool:
    """Return True when at least one search yielded candidate records (not proof of verification)."""
    return any(i["records"] > 0 and i["status"] == "RECORDS" for i in progress.get("collection_results", []))


def _next_gap_query(kit: str, progress: dict) -> tuple[str, str]:
    """Find a specific unsearched evidence need only after a proven empty search."""
    results = progress.get("collection_results", [])
    if not results or progress.get("unavailable"):
        return "", ""
    requested, attempted = classify_information_needs(kit), progress.get("attempted", set())
    for need in requested:
        related = [i for i in results if need in i["needs"]]
        if not related or any(i["status"] != "NO_RESULTS" for i in related):
            continue
        for idx in range(len(requested) * 2):
            alt = _status_query(kit, idx)
            if not alt or need not in classify_information_needs(alt):
                continue
            key = _semantic_query_key(alt)
            if key in attempted:
                continue
            words = set(key)
            if any(len(words & set(ex)) / len(words | set(ex)) >= 0.88 for ex in attempted if words | set(ex)):
                continue
            return alt, need
    return "", ""


@dataclass(frozen=True)
class CollectionResult:
    """Typed connector boundary; record count never implies verified evidence."""
    records: int
    query: str
    source: str
    status: str
    coverage: object = field(default_factory=dict)
    error: str = ""
    raw_text: str = ""


def _collection_result(response: object, query: str, source: str) -> CollectionResult:
    """Accept typed connector data or conservatively adapt the legacy raw-text contract."""
    if isinstance(response, CollectionResult):
        st = response.status if response.status in _VALID_COLLECTION_STATUSES else "UNKNOWN"
        return CollectionResult(response.records, query, response.source or source, st, response.coverage, response.error, response.raw_text)
    if isinstance(response, Mapping):
        payload = response.get("records", [])
        records = len(payload) if isinstance(payload, (list, tuple)) else (payload if type(payload) is int and payload >= 0 else 0)
        raw = response.get("raw_text") or response.get("text") or (
            "\n".join(json.dumps(i, ensure_ascii=False, default=str) for i in payload) if isinstance(payload, (list, tuple)) else ""
        )
        st = str(response.get("status") or "UNKNOWN").upper()
        st = ("RECORDS" if records else "UNKNOWN") if st in {"OK", "SUCCESS", "COMPLETED"} else ("NO_RESULTS" if st == "NO_RECORDS" else st)
        if st not in _VALID_COLLECTION_STATUSES or (records and st == "NO_RESULTS"):
            st = "UNKNOWN"
        return CollectionResult(records, query, str(response.get("source") or source), st, response.get("coverage") or {}, str(response.get("error") or ""), str(raw))
    if not isinstance(response, str):
        return CollectionResult(0, query, source, "UNKNOWN", error="Unsupported connector response type")

    markers = {m.group(1).upper() for m in _LEGACY_STATUS.finditer(response)}
    records = len(re.findall(r"(?m)^\s*DATE:\s*", response))
    st = next((n for n in _INCOMPLETE_PRIORITY if n in markers), None) or ("RECORDS" if records else ("NO_RESULTS" if markers & {"NO_RESULTS", "NO_RECORDS"} else "UNKNOWN"))
    if response.startswith("News API disabled for this process"):
        st = "SOURCE_UNAVAILABLE"
    return CollectionResult(records, query, source, st, "UNKNOWN", raw_text=response)


def register_optional_connector(name: str, platform_key: str, source_id: str, collector):
    """Register a governed optional evidence connector after verifying policy eligibility."""
    if (source := SOURCE_REGISTRY.get(source_id)) is None:
        raise ValueError(f"Unknown source ID: {source_id}")
    if source.get("legal_status") not in {"ALLOWED", "RESTRICTED"}:
        raise ValueError(f"Source {source_id} is not enabled for collection")
    if not callable(getattr(collector, "run", None)):
        raise TypeError("Collector must implement run(query)")
    OPTIONAL_SOURCE_CONNECTORS[name] = {"platform_key": platform_key.lower(), "source_id": source_id, "collector": collector}


def run_kiq_batch(
    tool_obj: Callable, queries: List[str], total_limit: int, source_label: str,
    progress: dict | None = None, max_calls: int | None = None,
) -> str:
    """Execute unique KIQ queries within a shared retrieval quota and emit typed audit markers."""
    progress = {} if progress is None else progress
    attempted = progress.setdefault("attempted", set())
    pending, batch_keys = [], set()
    for q in queries:
        if isinstance(q, str) and q.strip() and (key := _semantic_query_key(q)) and key not in attempted and key not in batch_keys:
            pending.append(q.strip())
            batch_keys.add(key)

    remaining = max(0, total_limit - progress.get("records", 0))
    allowed = max(0, (len(pending) if max_calls is None else max_calls) - progress.get("calls", 0))
    output, executed = [f"=== SOURCE: {source_label} ==="], 0
    cap = min(len(pending), allowed)

    with _scoped_dynamic_limit():
        for i, query in enumerate(pending[:allowed]):
            if PIPELINE_STATE.get("cancel_requested") or remaining <= 0:
                break
            quota = max(1, math.ceil(remaining / (cap - i)))
            os.environ["EWS_DYNAMIC_LIMIT"] = str(quota)
            attempted.add(_semantic_query_key(query))
            executed += 1
            progress["calls"] = progress.get("calls", 0) + 1
            logger.info("[KIQ COLLECTION -> %s] %s (quota=%d)", source_label, query, quota)
            try:
                res = _collection_result(tool_obj.run(query), query, source_label)
            except Exception as exc:
                logger.exception("[KIQ COLLECTION -> %s] Connector failed", source_label)
                res = CollectionResult(0, query, source_label, "SOURCE_ERROR", error=type(exc).__name__)

            found = res.records
            progress["records"] = progress.get("records", 0) + found
            remaining = max(0, total_limit - progress["records"])
            progress.setdefault("results", {})[query.casefold()] = found
            summary = {"query": res.query, "source": res.source, "records": found, "status": res.status, "coverage": res.coverage, "error": res.error}
            progress.setdefault("collection_results", []).append({**summary, "needs": classify_information_needs(query)})
            if res.status in _INCOMPLETE_STATUSES:
                progress["unavailable"] = True
            if res.status == "UNKNOWN":
                progress["uncounted"] = progress.get("uncounted", 0) + 1
            progress.setdefault("quota_audit", []).append({
                "query": query, "allocated": quota, "returned": found, "unused": max(0, quota - found),
                "redistributed": found < quota and i + 1 < cap, "status": res.status, "coverage": res.coverage, "error": res.error,
            })
            if found > quota:
                output.append(f"[BUDGET_WARNING] {source_label}: connector returned {found} > allocation {quota}")
            output.append("[COLLECTION_RESULT] " + json.dumps(summary, ensure_ascii=False, default=str))
            if res.raw_text and (found or res.status == "UNKNOWN"):
                output.append(f"[{'SEARCH_PURPOSE: ' + _query_purpose(query) if found else 'UNVERIFIED_OUTPUT'} | QUERY: {query}]\n{res.raw_text}")
            if res.status == "NO_RESULTS":
                output.append(f"[NO_RESULTS] {source_label}: {query}")
            elif res.status in _INCOMPLETE_STATUSES:
                output.append(f"[{res.status}] {source_label}: {res.error or res.raw_text[:250]}")
                break  # Stop querying the same source once it reports unavailable/incomplete retrieval.

    if len(pending) > executed:
        reason = "CANCELLED" if PIPELINE_STATE.get("cancel_requested") else ("RECORD_LIMIT" if remaining <= 0 else "CALL_LIMIT")
        output.extend(f"[QUERY_NOT_RUN: {reason}] {q}" for q in pending[executed:])
    if progress.get("calls", 0) and not progress.get("records") and not progress.get("unavailable") and not progress.get("uncounted"):
        output.append(f"[NO_RECORDS] Searches executed: {progress.get('calls', 0)}")
    output.append(f"[SOURCE_COVERAGE] calls={progress.get('calls', 0)}; records={progress.get('records', 0)}")
    output.append("[QUOTA_AUDIT] " + json.dumps(progress.get("quota_audit", []), ensure_ascii=False))
    return "\n".join(output) + "\n"


def _extra_source_groups(kit: str, platforms: List[str]) -> List[str]:
    """Prevent broad platform labels from activating unrelated official datasets."""
    selected = " ".join(platforms).lower()
    statistical = bool(re.search(r"\b(?:statistics?|statistical|eurostat|bts|traffic\s+volume|passenger\s+volume|operational\s+data)\b", kit, re.I))
    regulatory = bool(re.search(r"\b(?:faa|easa|airworthiness|certif\w*|type\s+approval|regulat\w*|directive|safety\s+notice)\b", kit, re.I))
    commercial = bool(re.search(r"\b(?:tender\w*|procurement|public\s+contracts?|award\w*|trade\s+deals?)\b", kit, re.I))
    issuer = (
        bool(re.search(r"\b(?:sec|edgar|filings?|10-[kq]|20-f|6-k)\b", kit, re.I))
        or any(re.search(rf"(?<!\w){re.escape(a)}(?!\w)", kit, re.I) for s in AEROSPACE_SUPPLIER_REGISTRY for a in (s["official_name"], *s.get("aliases", [])) if len(a) >= 3)
        or (bool(_ENGINE_TOPIC_RE.search(kit)) and bool(get_program_engine_domain(kit).get("engine_manufacturers")))
    )
    faa_only = bool(re.search(r"\bfaa\b", kit, re.I)) and not re.search(r"\beasa\b|\beuropean\b", kit, re.I)
    return [
        grp for cond, grp in (
            (statistical and any(p in selected for p in ("news", "eurostat", "statistics", "market")), "news"),
            (regulatory and not faa_only and any(p in selected for p in ("regul", "easa", "faa")), "regulatory"),
            (issuer and any(p in selected for p in ("pr", "sec", "filing")), "pr"),
            (commercial and "airshow" in selected, "airshow"),
        ) if cond
    ]


def _filter_cross_program_queries(user_query: str, related: List[dict], precision: str, regulatory_kit: bool) -> List[dict]:
    """Keep cross-program PR scans aligned with explicitly named suppliers and supply-chain intent."""
    if not related:
        return []
    has_supply = bool(re.search(r"\b(?:shortag\w*|suppl\w*|bottleneck\w*|production|manufactur\w*|deliver\w*|capacity|backlog)\b", user_query, re.I))
    if (precision == "EXACT" or regulatory_kit) and not has_supply:
        return []

    def _named_suppliers(text: str) -> set[str]:
        return {
            official for entry in AEROSPACE_SUPPLIER_REGISTRY
            if entry.get("default_tier") != "OEM (Final Assembler)"
            for official in [str(entry.get("official_name") or "").strip()]
            if any(len(str(a)) >= 3 and re.search(rf"(?<!\w){re.escape(str(a))}(?!\w)", text, re.I) for a in (official, *(entry.get("aliases") or [])))
        }

    explicit = _named_suppliers(user_query)
    return related if not explicit else [i for i in related if not (qs := _named_suppliers(str(i.get("query") or ""))) or (qs & explicit)]


class OfficialIndustryPRCollector:
    """Thin adapter exposing manufacturer PR scraping through the standard run(query) interface."""
    def run(self, query: str) -> str:
        return scrape_manufacturer_pr_news.run(query)


def collect_osint_data(
    user_query: str, kiq_plan: KIQPlan, platforms: List[str], scope: str, limit: int, run_workspace: str,
) -> str:
    """Orchestrate selected source connectors, enforce budgets, and persist raw_osint_data.txt."""
    reset_collected_urls()
    platforms_str = " ".join(platforms).lower()
    cancelled = lambda: bool(PIPELINE_STATE.get("cancel_requested"))
    financial_kit = bool(re.search(r"\b(?:sec|edgar|esef|xbrl|10-[kq]|20-f|6-k|filings?|annual\s+reports?|financial\s+statements?)\b", user_query, re.I))
    regulatory_kit = bool(re.search(r"\b(?:faa|easa|ntsb|certif\w*|type\s+approval|airworthiness|directive|regulat\w*|investigat\w*|accident|incident|crash|safety\s+notice|compliance)\b", user_query, re.I))
    precision = _kit_precision(user_query)

    media_tasks = _plan_queries(user_query, getattr(kiq_plan, "media_and_pr_queries", None))
    raw_plan_reg = getattr(kiq_plan, "regulatory_and_ntsb_queries", None)
    regulatory_tasks = [] if (isinstance(raw_plan_reg, list) and not raw_plan_reg and not regulatory_kit) else _plan_queries(user_query, raw_plan_reg)
    social_tasks = _plan_queries(user_query, getattr(kiq_plan, "social_and_video_queries", None))

    airshow_query = getattr(kiq_plan, "airshow_query", "")
    if not isinstance(airshow_query, str) or len(airshow_query) > 350 or airshow_query.strip().startswith(("[", "{")):
        logger.warning("[KIQ PLANNER] Invalid airshow query; preserving original KIT")
        airshow_query = user_query
    airshow_query = airshow_query.strip() or user_query

    media_queries = [i["query"] for i in media_tasks]
    raw_reg_queries = [i["query"] for i in regulatory_tasks]
    raw_social_queries = [i["query"] for i in social_tasks]

    # Source-specific adaptation for FAA/EASA (short identifiers instead of verbose sentences).
    engine_topic = bool(re.search(r"\b(?:engine|engines|propulsion|turbine|hpt|hpc|gtf|leap)\b", user_query, re.I))
    domain_info = get_program_engine_domain(user_query) if (precision != "EXACT" and engine_topic) else {"engine_models": (), "engine_manufacturers": ()}

    reg_queries = [
        item for q in raw_reg_queries
        for item in (build_federal_register_queries(user_query) if re.search(r"\b(?:official\s+decisions?\s+and\s+notices?|latest\s+developments?)\b", q, re.I) else [q])
    ] + (build_federal_register_queries(user_query) if domain_info["engine_models"] else [])
    regulatory_queries = list(dict.fromkeys(q.strip() for q in reg_queries if q and q.strip()))

    # Short 2-4 word queries for Bluesky and YouTube (Planner queries retain priority).
    soc_queries = [item for q in raw_social_queries for item in (build_social_video_queries(q) if len(q.split()) > 5 else [q])]
    if domain_info["engine_models"]:
        soc_queries += build_social_video_queries(user_query)
    social_queries = list(dict.fromkeys(q.strip() for q in soc_queries if q and q.strip())) or raw_social_queries

    # Append engine-manufacturer queries from the program domain map for Official Industry PR.
    pr_queries = list(media_queries)
    if domain_info["engine_manufacturers"]:
        eng_hint = domain_info["engine_models"][0] if domain_info["engine_models"] else "engine"
        pr_queries = list(dict.fromkeys(pr_queries + [f"{oem} {eng_hint}" for oem in domain_info["engine_manufacturers"][:2]]))

    call_budget = min({"BROAD": 4, "PROGRAM": 3, "EXACT": 3}[precision], max(1, limit))
    initial_calls = call_budget - int(bool(_status_query(user_query)) and call_budget > 1)
    raw_related = build_cross_program_queries(user_query, max_queries=2) if os.getenv("EWS_CROSS_PROGRAM_SCAN", "0") == "1" and "pr" in platforms_str else []
    related_queries = _filter_cross_program_queries(user_query, raw_related, precision, regulatory_kit)
    pr_initial_calls = initial_calls - int(bool(related_queries) and initial_calls > 1)
    news_progress, regulatory_progress, pr_progress = {}, {}, {}

    parts = [
        f"--- RAW OSINT COLLECTION DATA FOR KIT '{user_query}' ---\n"
        f"Time Scope: {scope} | Per-Source Limit: {limit} | Platforms: {', '.join(platforms)}\n"
        f"Query Precision: {precision} | Search Purposes: {', '.join(dict.fromkeys(t['purpose'] for t in media_tasks + regulatory_tasks + social_tasks))}\n"
        f"Decomposition Strategy (KIQ Rationale): {getattr(kiq_plan, 'strategy_rationale', '')}\n"
        f"  - Media & PR searches: {media_tasks}\n"
        f"  - Regulatory & NTSB searches: {regulatory_tasks}\n"
        f"  - Social & Video searches: {social_tasks}\n"
        f"  - Airshow KIQ: {airshow_query}\n" + ("=" * 70) + "\n\n"
    ]

    if "news" in platforms_str and not cancelled():
        unique_news, seen_news = [], set()
        for q in media_queries:
            if (key := news_api_search_key(q)) in seen_news:
                logger.info("[NEWS API DEDUP] Skipped equivalent query: %r -> %s", q, key)
            else:
                seen_news.add(key)
                unique_news.append(q)
        parts.append(run_kiq_batch(search_aerospace_news, unique_news, limit, "News API", news_progress, initial_calls) + "\n")

    reg_selected = any(p in platforms_str for p in ("regul", "easa", "faa"))
    if reg_selected and regulatory_queries and (not financial_kit or regulatory_kit) and not cancelled():
        parts.append(run_kiq_batch(scrape_regulatory_agencies, regulatory_queries, limit, "FAA & EASA Regulations", regulatory_progress, initial_calls) + "\n")
    elif financial_kit and not regulatory_kit:
        parts.append("[SOURCE ROUTING] FAA/EASA skipped: financial filing KIT without regulatory intent.\n")

    incident_kit = bool(re.search(r"\b(?:ntsb|accident\w*|incident\w*|crash\w*|investigat\w*|mishap\w*|safety\s+event|runway\s+incursion|door\s+plug)\b", user_query, re.I))
    if "ntsb" in platforms_str and incident_kit and not cancelled():
        parts.append(run_kiq_batch(scrape_ntsb_investigations, regulatory_queries, limit, "NTSB Investigations", max_calls=min(call_budget, 2)) + "\n")
    elif "ntsb" in platforms_str and not incident_kit:
        parts.append("[SOURCE ROUTING] NTSB not searched: no incident/investigation KIT.\n")

    if "pr" in platforms_str and not cancelled():
        parts.append(run_kiq_batch(OfficialIndustryPRCollector(), pr_queries, limit, "Official Industry PR", pr_progress, pr_initial_calls) + "\n")
    if related_queries and not cancelled():
        parts.append(run_kiq_batch(OfficialIndustryPRCollector(), [i["query"] for i in related_queries], limit, "Official Industry PR – Cross-Program", pr_progress, initial_calls) + "\n")
    if ("bluesky" in platforms_str or "soc" in platforms_str) and not cancelled():
        parts.append(run_kiq_batch(search_bluesky_aviation, social_queries, limit, "Bluesky Social Network", max_calls=call_budget) + "\n")
    if ("youtube" in platforms_str or "vide" in platforms_str) and not cancelled():
        parts.append(run_kiq_batch(extract_youtube_transcript, social_queries[:10], min(limit, 20), "YouTube Videos", max_calls=1) + "\n")

    commercial_kit = bool(re.search(
        r"\b(?:air\s?shows?|exhibitions?|trade\s+fairs?|farnborough|paris\s+air\s+show|dubai\s+air\s+show|"
        r"singapore\s+air\s+show|aircraft\s+orders?|orderbook|contracts?|sales|partnerships?|alliances?|"
        r"product\s+launch(?:es)?|unveil\w*|trade\s+deals?)\b", user_query, re.I,
    ))
    if "airshow" in platforms_str and not cancelled():
        if commercial_kit:
            with _scoped_dynamic_limit(limit):
                parts.append(scrape_airshow_website.run(airshow_query) + "\n")
        else:
            logger.info("[SOURCE ROUTING] Skipped airshow scraper: no exhibition/commercial KIT intent")
            parts.append("[SOURCE ROUTING] Airshow not searched: no exhibition/commercial KIT intent.\n")

    # Run targeted evidence-gap follow-ups only after an explicitly empty response.
    if _status_query(user_query) and not cancelled():
        regulator_eligible = reg_selected and (not financial_kit or regulatory_kit)
        for selected, collector, label, prog in (
            (regulator_eligible, scrape_regulatory_agencies, "FAA & EASA Regulations", regulatory_progress),
            ("news" in platforms_str, search_aerospace_news, "News API", news_progress),
            ("pr" in platforms_str, OfficialIndustryPRCollector(), "Official Industry PR", pr_progress),
        ):
            if not selected:
                continue
            if prog.get("unavailable"):
                failures = [e["status"] for e in prog.get("collection_results", []) if e["status"] in _INCOMPLETE_STATUSES]
                parts.append(f"[EVIDENCE_GAP] {label}: {failures[-1] if failures else 'SOURCE_UNAVAILABLE'}; fix access or use another permitted source.\n")
                continue
            followup, need = _next_gap_query(user_query, prog)
            if followup:
                parts.append(f"[EVIDENCE_GAP] {label}: missing candidate for {need}; searching alternative evidence wording.\n")
                parts.append(run_kiq_batch(collector, [followup], limit, f"{label} – Evidence Gap", prog, call_budget) + "\n")
            elif _has_status_candidates(prog):
                parts.append(f"[EVIDENCE_REVIEW] {label}: evidence candidates collected; no facts or outcomes confirmed.\n")
            elif prog.get("collection_results"):
                parts.append(f"[EVIDENCE_GAP] {label}: evidence unresolved; no justified repeat query.\n")
        if regulatory_kit and not regulator_eligible:
            parts.append("[EVIDENCE_GAP] OFFICIAL_SOURCE_NOT_SELECTED; regulatory evidence not verified.\n")

    if not cancelled():
        extra_groups = _extra_source_groups(user_query, platforms)
        parts.append(f"[EXTRA_SOURCE_ROUTING] Enabled groups: {', '.join(extra_groups) or 'none'}\n")
        if extra_groups:
            parts.append(collect_extra(user_query, extra_groups, limit) + "\n")

    for name, cfg in OPTIONAL_SOURCE_CONNECTORS.items():
        if cancelled():
            break
        if cfg["platform_key"] in platforms_str:
            parts.append(run_kiq_batch(cfg["collector"], media_queries[:1], limit, name, max_calls=1) + "\n")

    raw_data = "".join(parts)
    for out_path in ("raw_osint_data.txt", os.path.join(run_workspace, "raw_osint_data.txt")):
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(raw_data)
    return raw_data


