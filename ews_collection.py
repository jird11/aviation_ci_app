# =============================================================================
# aviation_ci_app | OSINT collection orchestration and source allocation
#
# Responsibility: Distribute KIT/KIQ queries across governed source connectors and enforce per-source
#   retrieval budgets.
# Design boundary: Collection produces evidence candidates; source relevance and event validity are
#   determined downstream.
# =============================================================================

"""Source-specific OSINT collection and KIQ-driven query orchestration."""

import ast
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from collections.abc import Mapping

import feedparser
from bs4 import BeautifulSoup

from tools import (
    AEROSPACE_SUPPLIER_REGISTRY,
    get_dynamic_limit,
    get_scope_days,
    is_date_within_scope,
    news_api_search_key,
    record_connector_telemetry,
    register_collected_document,
    safe_http_get,
)

from ews_state import (
    Callable,
    KIQPlan,
    List,
    PIPELINE_STATE,
    extract_youtube_transcript,
    logger,
    math,
    os,
    reset_collected_urls,
    scrape_airshow_website,
    scrape_manufacturer_pr_news,
    scrape_ntsb_investigations,
    scrape_regulatory_agencies,
    search_aerospace_news,
    search_bluesky_aviation,
)
from ews_state import SOURCE_REGISTRY
from ews_sources_extra import collect_extra
from aero_ews.collection.query_expansion import build_cross_program_queries
from aero_ews.collection.queries import (
    AGENCIES, COMPONENTS, NEED_SEARCH_TERMS, REGULATORY_RE,
    _model_aliases, _model_tokens, build_federal_register_queries,
    build_social_video_queries, classify_information_needs,
    get_program_engine_domain,
)

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
    r"\b(?:delay\w*|shortag\w*|defect\w*|failur\w*|fault\w*|"
    r"ground\w*|restrict\w*|disrupt\w*|backlog\w*|recall\w*|"
    r"risk\w*|issue\w*|problem\w*|constraint\w*|incident\w*|"
    r"investigat\w*|compliance|bottleneck\w*)\b", re.I,
)
_STATUS_TOPIC = re.compile(
    r"\b(?:delay\w*|shortag\w*|disrupt\w*|backlog\w*|suspend\w*|"
    r"ground\w*|defect\w*|failur\w*|certif\w*|approv\w*|compliance|restrict\w*|"
    r"inspection\s+requirements?|production\s+halt\w*|status|progress|resolution)\b", re.I,
)


def _semantic_query_key(query: str) -> tuple[str, ...]:
    """Deduplicate word-order variants without merging opposite or different statuses."""
    stopwords = {"a", "an", "the", "of", "for", "on", "in", "about", "with", "from"}
    words = [w for w in re.findall(r"[a-z0-9]+", query.casefold()) if w not in stopwords]
    return tuple(sorted(words))


def _kit_query_parts(kit: str) -> tuple[str, str, str]:
    """Keep the explicit subject, issue and constraints rather than inventing a scope."""
    original = re.sub(r"\s+", " ", str(kit or "")).strip()
    constraints = []
    date_re = (r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
               r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\s+20\d{2}\b"
               r"|\b20\d{2}-\d{2}(?:-\d{2})?\b")
    for match in re.finditer(date_re, original, re.I):
        constraints.append(match.group())
    for agency in AGENCIES:
        if re.search(rf"\b{re.escape(agency)}\b", original, re.I):
            constraints.append(agency.upper())

    subject = ""
    for entry in AEROSPACE_SUPPLIER_REGISTRY:
        aliases = sorted((entry["official_name"], *entry.get("aliases", [])), key=len, reverse=True)
        for alias in aliases:
            match = re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", original, re.I) if len(alias) >= 4 else None
            if match:
                subject = match.group()
                break
        if subject:
            break
    if not subject:
        subject = next((match.group() for match in _ENGINE_VARIANT_RE.finditer(original)), "")
    issue = re.sub(rf"(?<!\w){re.escape(subject)}(?!\w)", " ", original, count=1, flags=re.I) if subject else original
    for constraint in constraints:
        issue = re.sub(rf"(?<!\w){re.escape(constraint)}(?!\w)", " ", issue, count=1, flags=re.I)
    issue = re.sub(r"\b(?:latest|current|status|updates?|progress)\b", " ", issue, flags=re.I)
    issue = re.sub(r"\s+", " ", issue).strip()
    return subject, issue, " ".join(dict.fromkeys(constraints))


def _engine_variants(text: str) -> set[str]:
    """Preserve distinct named variants without assuming a fixed engine catalogue."""
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
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            parsed = [re.fullmatch(r"(?:[-*•]|\d+[.)])\s+(.+)", line) for line in lines]
            value = [match.group(1) for match in parsed] if parsed and all(parsed) else None
        else:
            value = ([raw] if raw and not raw.startswith(("{", "["))
                     and not re.search(r"\S\s*,\s*\S", raw) else None)
    if (not isinstance(value, list) or len(value) > 24
            or any(not isinstance(q, str) or len(q) > 350 or "\x00" in q for q in value)):
        logger.warning("[KIQ PLANNER] Invalid query structure; falling back to original KIT")
        return [kit]
    queries = [q.strip() for q in value if q.strip()]
    return queries or [kit]


def _model_search_aliases(model: str) -> set[str]:
    """Compare published aircraft aliases without losing the exact variant."""
    codes = [model]
    if re.match(r"B\d{3}(?!\d)", model, re.I):
        codes.append(model[1:])
    return {
        re.sub(r"[\s-]+", "", variant.casefold())
        for code in codes for variant in _model_aliases(code)
    }


def _query_purpose(query: str) -> str:
    for purpose, pattern in _PURPOSE_PATTERNS[:2]:
        if re.search(pattern, query, re.I):
            return purpose
    needs = classify_information_needs(query)
    if "INSPECTION_OBLIGATION" in needs:
        return "REGULATORY_REQUIREMENT"
    if "INSPECTION_DEADLINE" in needs:
        return "COMPLIANCE_DEADLINE"
    if "REGULATORY_REVISION" in needs:
        return "REGULATORY_REVISION"
    if "RETURN_TO_SERVICE" in needs:
        return "RETURN_TO_SERVICE"
    if "INSPECTION_COMPLETION" in needs:
        return "INSPECTION_COMPLETION"
    return next((purpose for purpose, pattern in _PURPOSE_PATTERNS
                 if re.search(pattern, query, re.I)), "EVENT_DISCOVERY")


def _kit_precision(kit: str) -> str:
    models = _model_tokens(kit)
    variants = _engine_variants(kit)
    has_authority = any(re.search(rf"\b{re.escape(a)}\b", kit, re.I) for a in AGENCIES)
    has_date = bool(re.search(r"\b(?:20\d{2}|\d{4}-\d{2}(?:-\d{2})?)\b", kit))
    has_mandatory_issue = bool(re.search(
        r"\b(?:inspection\s+requirements?|compliance\s+deadlines?|mandatory\s+inspections?|"
        r"gearbox|specific\s+component|docket)\b", kit, re.I,
    ))
    if re.search(r"\bFAA-20\d{2}-\d{3,7}\b", kit, re.I):
        return "EXACT"
    remainder = kit
    for model in models:
        for alias in _model_aliases(model[1:] if re.match(r"B\d{3}(?!\d)", model, re.I) else model):
            remainder = re.sub(re.escape(alias), " ", remainder, flags=re.I)
    details = re.findall(r"\b[a-z]{4,}\b", remainder, re.I)
    return ("EXACT" if (models or variants) and (has_authority or has_date or has_mandatory_issue or
                        len(details) >= 6 or len(variants) > 1)
            else "PROGRAM" if models or variants else "BROAD")


def _status_query(kit: str, outcome_index: int = 0) -> str:
    """Search the requested evidence need, never an unrequested lifecycle stage."""
    if _query_purpose(kit) == "HISTORICAL_STATUS" or outcome_index < 0:
        return ""
    needs = classify_information_needs(kit)
    terms = [term for i in range(2) for need in needs
             for term in NEED_SEARCH_TERMS[need][i:i + 1]]
    models = _model_tokens(kit)
    variants = _engine_variants(kit)
    if not terms or len(models) > 2 or len(variants) > 2 or outcome_index >= len(terms):
        return ""
    subject, issue, qualifiers = _kit_query_parts(kit)
    if not issue or len([a for a in AGENCIES if re.search(rf"\b{re.escape(a)}\b", kit, re.I)]) > 1:
        return ""
    return " ".join(part for part in (subject, issue, qualifiers, terms[outcome_index]) if part)


def _preserves_kit(kit: str, query: str, precision: str) -> bool:
    """Permit semantic alternatives and verified engine expansion while retaining mandatory identities."""
    original_models, queried_models = _model_tokens(kit), _model_tokens(query)
    variants, queried_variants = _engine_variants(kit), _engine_variants(query)

    domain_expansion = bool(
        precision != "EXACT"
        and original_models
        and not variants
        and re.search(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", kit, re.I)
    )
    allowed_models = list(original_models)
    allowed_variants = set(variants)
    if domain_expansion:
        domain = get_program_engine_domain(kit)
        allowed_models.extend(_model_tokens(" ".join(domain["engine_models"])))
        allowed_variants.update(_engine_variants(" ".join(domain["engine_models"])))

    if allowed_models and any(not any(_model_search_aliases(model) & _model_search_aliases(other)
                                      for other in allowed_models) for model in queried_models):
        return False
    if precision == "EXACT" and any(not any(
            _model_search_aliases(model) & _model_search_aliases(other)
            for other in queried_models) for model in original_models):
        return False
    if queried_variants - allowed_variants or precision == "EXACT" and variants - queried_variants:
        return False
    original_regs = {re.sub(r"[-\s]+", "", m.group().casefold()) for m in REGULATORY_RE.finditer(kit)}
    if precision == "EXACT" and not original_regs.issubset(
            {re.sub(r"[-\s]+", "", m.group().casefold()) for m in REGULATORY_RE.finditer(query)}):
        return False
    if precision == "EXACT":
        if any(re.search(pattern, kit, re.I) and not re.search(pattern, query, re.I)
               for pattern, _ in COMPONENTS):
            return False
        wanted = set(classify_information_needs(kit)) - {"GENERAL_STATUS"}
        if wanted and not wanted.intersection(classify_information_needs(query)):
            return False
    subject, _, _ = _kit_query_parts(kit)
    if subject and not original_models and not variants and not re.search(
            rf"(?<!\w){re.escape(subject)}(?!\w)", query, re.I):
        return False
    return True


def _plan_queries(kit: str, planned: List[str]) -> List[dict]:
    """Classify planner queries by evidence purpose; keep exact model identity."""
    items, seen = [], set()
    precision = _kit_precision(kit)
    for query in _normalize_planned_queries(planned, kit):
        query = (query or "").strip()
        key = _semantic_query_key(query)
        if not key or key in seen:
            continue
        if not _preserves_kit(kit, query, precision):
            continue
        items.append({"query": query, "purpose": _query_purpose(query),
                      "needs": classify_information_needs(query)})
        seen.add(key)
    covered = {need for item in items for need in item["needs"]}
    required = set(classify_information_needs(kit))
    if (precision == "BROAD" or required - covered or not items) and _semantic_query_key(kit) not in seen:
        items.insert(0, {"query": kit, "purpose": _query_purpose(kit),
                         "needs": classify_information_needs(kit)})
        seen.add(_semantic_query_key(kit))
    if not items:
        items.append({"query": kit, "purpose": _query_purpose(kit),
                      "needs": classify_information_needs(kit)})
    if not any(i["needs"] for i in items):
        query = _status_query(kit)
        if query and _semantic_query_key(query) not in seen:
            items.append({"query": query, "purpose": _query_purpose(query),
                          "needs": classify_information_needs(query)})
    if precision == "EXACT":
        items.sort(key=lambda i: i["purpose"] not in {"REGULATORY_REQUIREMENT", "COMPLIANCE_DEADLINE", "REGULATORY_REVISION", "CURRENT_STATUS"})
    return items


def _bluesky_status_queries(kit: str, planned: List[str]) -> List[str]:
    """Backwards-compatible, position-independent status-query expansion."""
    return [item["query"] for item in _plan_queries(kit, planned)]


def _has_status_candidates(progress: dict) -> bool:
    """Candidate counts must not be interpreted as verification of an outcome."""
    return any(item["records"] > 0 and item["status"] == "RECORDS"
               for item in progress.get("collection_results", []))


def _next_gap_query(kit: str, progress: dict) -> tuple[str, str]:
    """Find a specific unsearched evidence need only after a proven empty search."""
    results = progress.get("collection_results", [])
    if not results or progress.get("unavailable"):
        return "", ""
    requested = classify_information_needs(kit)
    attempted = progress.get("attempted", set())
    for need in requested:
        related = [item for item in results if need in item["needs"]]
        if not related or any(item["status"] != "NO_RESULTS" for item in related):
            continue
        for index in range(len(requested) * 2):
            alternative = _status_query(kit, index)
            if not alternative or need not in classify_information_needs(alternative):
                continue
            key = _semantic_query_key(alternative)
            if key in attempted:
                continue
            words = set(key)
            if any(len(words & set(existing)) / len(words | set(existing)) >= .88
                   for existing in attempted if words | set(existing)):
                continue
            return alternative, need
    return "", ""


@dataclass(frozen=True)
class CollectionResult:
    """Typed connector boundary; records count never implies verified evidence."""
    records: int
    query: str
    source: str
    status: str
    coverage: object = field(default_factory=dict)
    error: str = ""
    raw_text: str = ""


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


def _collection_result(response: object, query: str, source: str) -> CollectionResult:
    """Accept typed connector data, or conservatively adapt the legacy RAW contract."""
    if isinstance(response, CollectionResult):
        status = response.status if response.status in _INCOMPLETE_STATUSES | {"RECORDS", "NO_RESULTS"} else "UNKNOWN"
        return CollectionResult(response.records, query, response.source or source,
                                status, response.coverage, response.error, response.raw_text)
    if isinstance(response, Mapping):
        payload = response.get("records", [])
        records = len(payload) if isinstance(payload, (list, tuple)) else (
            payload if type(payload) is int and payload >= 0 else 0)
        raw = response.get("raw_text") or response.get("text") or ""
        if not raw and isinstance(payload, (list, tuple)):
            raw = "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in payload)
        status = str(response.get("status") or "UNKNOWN").upper()
        if status in {"OK", "SUCCESS", "COMPLETED"}:
            status = "RECORDS" if records else "UNKNOWN"
        if status == "NO_RECORDS":
            status = "NO_RESULTS"
        if status not in _INCOMPLETE_STATUSES | {"RECORDS", "NO_RESULTS"}:
            status = "UNKNOWN"
        if records and status == "NO_RESULTS":
            status = "UNKNOWN"
        return CollectionResult(records, query, str(response.get("source") or source), status,
                                response.get("coverage") or {}, str(response.get("error") or ""), str(raw))
    if not isinstance(response, str):
        return CollectionResult(0, query, source, "UNKNOWN", error="Unsupported connector response type")
    markers = {match.group(1).upper() for match in _LEGACY_STATUS.finditer(response)}
    status = next((name for name in _INCOMPLETE_PRIORITY if name in markers), None)
    records = len(re.findall(r"(?m)^\s*DATE:\s*", response))
    if not status:
        status = "RECORDS" if records else "NO_RESULTS" if markers & {"NO_RESULTS", "NO_RECORDS"} else "UNKNOWN"
    # Compatibility with the existing NewsAPI circuit breaker message.
    if response.startswith("News API disabled for this process"):
        status = "SOURCE_UNAVAILABLE"
    return CollectionResult(records, query, source, status, "UNKNOWN", raw_text=response)

# Register an optional connector only when its source policy permits collection.
def register_optional_connector(name: str, platform_key: str, source_id: str, collector):
    """Register a governed optional evidence connector."""
    source = SOURCE_REGISTRY.get(source_id)

    if source is None:
        raise ValueError(f"Unknown source ID: {source_id}")

    if source.get("legal_status") not in {"ALLOWED", "RESTRICTED"}:
        raise ValueError(f'Source {source_id} is not enabled for collection')

    if not callable(getattr(collector, "run", None)):
        raise TypeError("Collector must implement run(query)")

    OPTIONAL_SOURCE_CONNECTORS[name] = {
        "platform_key": platform_key.lower(),
        "source_id": source_id,
        "collector": collector,
    }

# Run unique KIQ queries within a shared, dynamically allocated retrieval quota.
# Do not exceed the remaining per-source retrieval budget across KIQ queries.
def run_kiq_batch(tool_obj: Callable, queries: List[str], total_limit: int, source_label: str,
                  progress: dict | None = None, max_calls: int | None = None) -> str:
    """Share budgets and audit typed collection states without guessing relevance."""
    progress = progress if progress is not None else {}
    attempted = progress.setdefault("attempted", set())
    pending, batch_keys = [], set()
    for query in queries:
        if not isinstance(query, str) or not query.strip():
            continue
        key = _semantic_query_key(query)
        if key and key not in attempted and key not in batch_keys:
            pending.append(query.strip())
            batch_keys.add(key)
    remaining = max(0, total_limit - progress.get("records", 0))
    allowed = max(0, (max_calls if max_calls is not None else len(pending)) - progress.get("calls", 0))
    output = [f"=== SOURCE: {source_label} ==="]
    executed = 0
    previous_limit = os.environ.get("EWS_DYNAMIC_LIMIT")
    try:
        for i, query in enumerate(pending[:allowed]):
            if PIPELINE_STATE.get("cancel_requested") or remaining <= 0:
                break
            quota = max(1, math.ceil(remaining / (min(len(pending), allowed) - i)))
            os.environ["EWS_DYNAMIC_LIMIT"] = str(quota)
            attempted.add(_semantic_query_key(query))
            executed += 1
            progress["calls"] = progress.get("calls", 0) + 1
            logger.info("[KIQ COLLECTION -> %s] %s (quota=%d)", source_label, query, quota)
            try:
                result = _collection_result(tool_obj.run(query), query, source_label)
            except Exception as exc:
                logger.exception("[KIQ COLLECTION -> %s] Connector failed", source_label)
                result = CollectionResult(0, query, source_label, "SOURCE_ERROR",
                                          error=type(exc).__name__)
            found = result.records
            progress["records"] = progress.get("records", 0) + found
            remaining = max(0, total_limit - progress["records"])
            progress.setdefault("results", {})[query.casefold()] = found
            progress.setdefault("collection_results", []).append({
                "query": result.query, "source": result.source, "records": found,
                "status": result.status, "coverage": result.coverage,
                "error": result.error, "needs": classify_information_needs(query),
            })
            if result.status in _INCOMPLETE_STATUSES:
                progress["unavailable"] = True
            if result.status == "UNKNOWN":
                progress["uncounted"] = progress.get("uncounted", 0) + 1
            progress.setdefault("quota_audit", []).append({
                "query": query, "allocated": quota, "returned": found,
                "unused": max(0, quota - found),
                "redistributed": found < quota and i + 1 < min(len(pending), allowed),
                "status": result.status, "coverage": result.coverage, "error": result.error,
            })
            if found > quota:
                output.append(f"[BUDGET_WARNING] {source_label}: connector returned {found} > allocation {quota}")
            output.append("[COLLECTION_RESULT] " + json.dumps({
                "query": result.query, "source": result.source, "records": found,
                "status": result.status, "coverage": result.coverage,
                "error": result.error,
            }, ensure_ascii=False, default=str))
            if result.raw_text and (found or result.status == "UNKNOWN"):
                tag = "SEARCH_PURPOSE: " + _query_purpose(query) if found else "UNVERIFIED_OUTPUT"
                output.append(f"[{tag} | QUERY: {query}]\n{result.raw_text}")
            if result.status == "NO_RESULTS":
                output.append(f"[NO_RESULTS] {source_label}: {query}")
            elif result.status in _INCOMPLETE_STATUSES:
                output.append(f"[{result.status}] {source_label}: {result.error or result.raw_text[:250]}")
                break  # Same source has already reported incomplete/unavailable retrieval.
    finally:
        if previous_limit is None:
            os.environ.pop("EWS_DYNAMIC_LIMIT", None)
        else:
            os.environ["EWS_DYNAMIC_LIMIT"] = previous_limit
    if len(pending) > executed:
        reason = ("CANCELLED" if PIPELINE_STATE.get("cancel_requested") else
                  "RECORD_LIMIT" if remaining <= 0 else "CALL_LIMIT")
        output.extend(f"[QUERY_NOT_RUN: {reason}] {query}" for query in pending[executed:])
    if (progress.get("calls", 0) and not progress.get("records")
            and not progress.get("unavailable") and not progress.get("uncounted")):
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
            or any(
        any(re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", kit, re.I)
            for alias in (s["official_name"], *s.get("aliases", [])) if len(alias) >= 3)
        for s in AEROSPACE_SUPPLIER_REGISTRY
    )
            or (
                    bool(re.search(r"\b(?:engine|engines|propulsion|powerplant|turbine|gtf|leap)\b", kit, re.I))
                    and bool(get_program_engine_domain(kit).get("engine_manufacturers"))
            )
    )
    groups = []
    if statistical and any(p in selected for p in ("news", "eurostat", "statistics", "market")):
        groups.append("news")
    faa_only = bool(re.search(r"\bfaa\b", kit, re.I)) and not re.search(r"\beasa\b|\beuropean\b", kit, re.I)
    if regulatory and not faa_only and any(p in selected for p in ("regul", "easa", "faa")):
        groups.append("regulatory")
    if issuer and any(p in selected for p in ("pr", "sec", "filing")):
        groups.append("pr")
    if commercial and "airshow" in selected:
        groups.append("airshow")
    return groups

def _filter_cross_program_queries(
        user_query: str, related: List[dict], precision: str, regulatory_kit: bool
) -> List[dict]:
    """Keep cross-program PR scans aligned with explicitly named suppliers and supply-chain intent."""
    if not related:
        return []
    has_supply_intent = bool(re.search(
        r"\b(?:shortag\w*|suppl\w*|bottleneck\w*|production|manufactur\w*|deliver\w*|capacity|backlog)\b",
        user_query, re.I,
    ))
    if (precision == "EXACT" or regulatory_kit) and not has_supply_intent:
        return []

    def _named_suppliers(text: str) -> set[str]:
        found = set()
        for entry in AEROSPACE_SUPPLIER_REGISTRY:
            if entry.get("default_tier") == "OEM (Final Assembler)":
                continue
            official = str(entry.get("official_name") or "").strip()
            aliases = (official, *(entry.get("aliases") or []))
            if any(
                len(str(alias)) >= 3
                and re.search(rf"(?<!\w){re.escape(str(alias))}(?!\w)", text, re.I)
                for alias in aliases
            ):
                found.add(official)
        return found

    explicit_suppliers = _named_suppliers(user_query)
    if not explicit_suppliers:
        return related

    return [
        item for item in related
        if not (q_suppliers := _named_suppliers(str(item.get("query") or "")))
        or q_suppliers.intersection(explicit_suppliers)
    ]

class OfficialIndustryPRCollector:
    def run(self, query: str) -> str:
        return scrape_manufacturer_pr_news.run(query)

# Orchestrate the selected source connectors and aggregate their raw evidence output.
# Preserve evidence provenance and stable output contracts for downstream stages.
def collect_osint_data(
        user_query: str, kiq_plan: KIQPlan, platforms: List[str], scope: str, limit: int, run_workspace: str
) -> str:
    # Build selected connector workloads from the active KIT/KIQ plan.
    reset_collected_urls()
    platforms_str = " ".join(platforms).lower()
    financial_kit = bool(re.search(
        r"\b(?:sec|edgar|esef|xbrl|10-[kq]|20-f|6-k|filings?|annual\s+reports?|financial\s+statements?)\b",
        user_query, re.I,
    ))
    regulatory_kit = bool(re.search(
        r"\b(?:faa|easa|ntsb|certif\w*|type\s+approval|airworthiness|directive|regulat\w*|"
        r"investigat\w*|accident|incident|crash|safety\s+notice|compliance)\b",
        user_query, re.I,
    ))
    precision = _kit_precision(user_query)
    media_tasks = _plan_queries(user_query, getattr(kiq_plan, "media_and_pr_queries", None))
    raw_plan_regulatory = getattr(kiq_plan, "regulatory_and_ntsb_queries", None)
    regulatory_tasks = (
        [] if (isinstance(raw_plan_regulatory, list) and not raw_plan_regulatory and not regulatory_kit)
        else _plan_queries(user_query, raw_plan_regulatory)
    )
    social_tasks = _plan_queries(user_query, getattr(kiq_plan, "social_and_video_queries", None))
    airshow_query = getattr(kiq_plan, "airshow_query", "")
    if (not isinstance(airshow_query, str) or len(airshow_query) > 350
            or airshow_query.strip().startswith(("[", "{"))):
        logger.warning("[KIQ PLANNER] Invalid airshow query; preserving original KIT")
        airshow_query = user_query
    airshow_query = airshow_query.strip() or user_query
    media_queries = [item["query"] for item in media_tasks]
    raw_regulatory_queries = [item["query"] for item in regulatory_tasks]
    raw_social_queries = [item["query"] for item in social_tasks]

    # Zdrojově specifická úprava pro FAA/EASA (krátké identifikátory místo obecných vět).
    engine_topic = bool(re.search(r"\b(?:engine|engines|propulsion|turbine|hpt|hpc|gtf|leap)\b", user_query, re.I))
    domain_info = get_program_engine_domain(user_query) if (precision != "EXACT" and engine_topic) else {
        "engine_models": (), "engine_manufacturers": (),
    }
    regulatory_queries = []
    for q in raw_regulatory_queries:
        if re.search(r"\b(?:official\s+decisions?\s+and\s+notices?|latest\s+developments?)\b", q, re.I):
            regulatory_queries.extend(build_federal_register_queries(user_query))
        else:
            regulatory_queries.append(q)
    if domain_info["engine_models"]:
        regulatory_queries = regulatory_queries + build_federal_register_queries(user_query)
    regulatory_queries = list(dict.fromkeys(q.strip() for q in regulatory_queries if q and q.strip()))

    # Krátké 2-4slovné dotazy pro Bluesky a YouTube (dotazy Planneru mají přednost).
    social_queries = []
    for q in raw_social_queries:
        if len(q.split()) > 5:
            social_queries.extend(build_social_video_queries(q))
        else:
            social_queries.append(q)
    if domain_info["engine_models"]:
        social_queries = social_queries + build_social_video_queries(user_query)
    social_queries = list(dict.fromkeys(q.strip() for q in social_queries if q and q.strip())) or raw_social_queries

    # Pro Official Industry PR přidej dotazy na výrobce motorů z doménové mapy.
    pr_queries = list(media_queries)
    if domain_info["engine_manufacturers"]:
        eng_hint = domain_info["engine_models"][0] if domain_info["engine_models"] else "engine"
        for oem in domain_info["engine_manufacturers"][:2]:
            pr_queries.append(f"{oem} {eng_hint}")
        pr_queries = list(dict.fromkeys(pr_queries))

    call_budget = min({"BROAD": 4, "PROGRAM": 3, "EXACT": 3}[precision], max(1, limit))
    initial_calls = call_budget - int(bool(_status_query(user_query)) and call_budget > 1)
    raw_related = (build_cross_program_queries(user_query, max_queries=2)
                   if os.getenv("EWS_CROSS_PROGRAM_SCAN", "0") == "1" and "pr" in platforms_str else [])
    related_queries = _filter_cross_program_queries(user_query, raw_related, precision, regulatory_kit)
    pr_initial_calls = initial_calls - int(bool(related_queries) and initial_calls > 1)
    news_progress, regulatory_progress, pr_progress = {}, {}, {}

    raw_data = (
            f"--- RAW OSINT COLLECTION DATA FOR KIT '{user_query}' ---\n"
            f"Time Scope: {scope} | Per-Source Limit: {limit} | Platforms: {', '.join(platforms)}\n"
            f"Query Precision: {precision} | Search Purposes: "
            f"{', '.join(dict.fromkeys(t['purpose'] for t in media_tasks + regulatory_tasks + social_tasks))}\n"
            f"Decomposition Strategy (KIQ Rationale): {getattr(kiq_plan, 'strategy_rationale', '')}\n"
            f"  - Media & PR searches: {media_tasks}\n"
            f"  - Regulatory & NTSB searches: {regulatory_tasks}\n"
            f"  - Social & Video searches: {social_tasks}\n"
            f"  - Airshow KIQ: {airshow_query}\n"
            + ("=" * 70)
            + "\n\n"
    )

    if 'news' in platforms_str and (not PIPELINE_STATE.get('cancel_requested')):
        unique_news_queries = []
        seen_news_keys = set()

        for q in media_queries:
            key = news_api_search_key(q)

            if key in seen_news_keys:
                logger.info('[NEWS API DEDUP] Skipped equivalent query: %r -> %s', q, key)
                continue

            seen_news_keys.add(key)
            unique_news_queries.append(q)

        raw_data += run_kiq_batch(search_aerospace_news, unique_news_queries, limit, 'News API',
                                  news_progress, initial_calls) + '\n'

    if ("regul" in platforms_str or "easa" in platforms_str or "faa" in platforms_str) and regulatory_queries and (
            not financial_kit or regulatory_kit) and not PIPELINE_STATE.get(
            "cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    scrape_regulatory_agencies, regulatory_queries, limit, "FAA & EASA Regulations",
                    regulatory_progress, initial_calls,
                )
                + "\n"
        )
    elif financial_kit and not regulatory_kit:
        raw_data += "[SOURCE ROUTING] FAA/EASA skipped: financial filing KIT without regulatory intent.\n"

    incident_kit = bool(re.search(
        r"\b(?:ntsb|accident\w*|incident\w*|crash\w*|investigat\w*|"
        r"mishap\w*|safety\s+event|runway\s+incursion|door\s+plug)\b",
        user_query, re.I,
    ))
    if "ntsb" in platforms_str and incident_kit and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(
                scrape_ntsb_investigations, regulatory_queries, limit, "NTSB Investigations",
                max_calls=min(call_budget, 2),
                )
                + "\n"
        )
    elif "ntsb" in platforms_str and not incident_kit:
        raw_data += "[SOURCE ROUTING] NTSB not searched: no incident/investigation KIT.\n"

    if "pr" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(
                    OfficialIndustryPRCollector(),
                    pr_queries,
                    limit,
                    "Official Industry PR",
                    pr_progress,
                    pr_initial_calls,
                )
                + "\n"
        )

    if related_queries and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += run_kiq_batch(
            OfficialIndustryPRCollector(),
            [item["query"] for item in related_queries],
            limit,
            "Official Industry PR – Cross-Program",
            pr_progress,
            initial_calls,
        ) + "\n"

    if ("bluesky" in platforms_str or "soc" in platforms_str) and not PIPELINE_STATE.get("cancel_requested"):
        raw_data += (
                run_kiq_batch(search_bluesky_aviation, social_queries, limit,
                          "Bluesky Social Network", max_calls=call_budget)
                + "\n"
        )

    if ("youtube" in platforms_str or "vide" in platforms_str) and not PIPELINE_STATE.get("cancel_requested"):
        yt_limit = min(limit, 20)
        raw_data += (
                run_kiq_batch(extract_youtube_transcript, social_queries[:10], yt_limit,
                          "YouTube Videos", max_calls=1)
                + "\n"
        )

    # The Planner always supplies an airshow query; that alone is not a business KIT.
    commercial_kit = bool(re.search(
        r"\b(?:air\s?shows?|exhibitions?|trade\s+fairs?|farnborough|"
        r"paris\s+air\s+show|dubai\s+air\s+show|singapore\s+air\s+show|"
        r"aircraft\s+orders?|orderbook|contracts?|sales|partnerships?|"
        r"alliances?|product\s+launch(?:es)?|unveil\w*|trade\s+deals?)\b",
        user_query, re.I,
    ))
    if "airshow" in platforms_str and not PIPELINE_STATE.get("cancel_requested"):
        if commercial_kit:
            airshow_cap = limit
            previous_limit = os.environ.get("EWS_DYNAMIC_LIMIT")
            os.environ["EWS_DYNAMIC_LIMIT"] = str(airshow_cap)
            try:
                raw_data += scrape_airshow_website.run(airshow_query) + "\n"
            finally:
                if previous_limit is None:
                    os.environ.pop("EWS_DYNAMIC_LIMIT", None)
                else:
                    os.environ["EWS_DYNAMIC_LIMIT"] = previous_limit
        else:
            logger.info("[SOURCE ROUTING] Skipped airshow scraper: no exhibition/commercial KIT intent")
            raw_data += "[SOURCE ROUTING] Airshow not searched: no exhibition/commercial KIT intent.\n"

    # A gap search requires an identifiable evidence need and an explicitly
    # empty response. Unknown/incomplete retrieval cannot justify another query.
    if _status_query(user_query) and not PIPELINE_STATE.get("cancel_requested"):
        regulator_selected = (any(p in platforms_str for p in ("regul", "faa", "easa"))
                              and (not financial_kit or regulatory_kit))
        gap_sources = (
            (regulator_selected, scrape_regulatory_agencies, "FAA & EASA Regulations", regulatory_progress),
            ("news" in platforms_str, search_aerospace_news, "News API", news_progress),
            ("pr" in platforms_str, OfficialIndustryPRCollector(), "Official Industry PR", pr_progress),
        )
        for selected, collector, label, progress in gap_sources:
            if not selected:
                continue
            if progress.get("unavailable"):
                failures = [entry["status"] for entry in progress.get("collection_results", [])
                            if entry["status"] in _INCOMPLETE_STATUSES]
                raw_data += f"[EVIDENCE_GAP] {label}: {failures[-1] if failures else 'SOURCE_UNAVAILABLE'}; fix access or use another permitted source.\n"
                continue
            followup, need = _next_gap_query(user_query, progress)
            if followup:
                raw_data += f"[EVIDENCE_GAP] {label}: missing candidate for {need}; searching alternative evidence wording.\n"
                raw_data += run_kiq_batch(collector, [followup], limit,
                                          f"{label} – Evidence Gap", progress, call_budget) + "\n"
            elif _has_status_candidates(progress):
                raw_data += f"[EVIDENCE_REVIEW] {label}: evidence candidates collected; no facts or outcomes confirmed.\n"
            elif progress.get("collection_results"):
                raw_data += f"[EVIDENCE_GAP] {label}: evidence unresolved; no justified repeat query.\n"
        if regulatory_kit and not regulator_selected:
            raw_data += "[EVIDENCE_GAP] OFFICIAL_SOURCE_NOT_SELECTED; regulatory evidence not verified.\n"

    if not PIPELINE_STATE.get("cancel_requested"):
        extra_groups = _extra_source_groups(user_query, platforms)
        raw_data += f"[EXTRA_SOURCE_ROUTING] Enabled groups: {', '.join(extra_groups) or 'none'}\n"
        if extra_groups:
            raw_data += collect_extra(user_query, extra_groups, limit) + "\n"

    for name, config in OPTIONAL_SOURCE_CONNECTORS.items():
        if PIPELINE_STATE.get("cancel_requested"):
            break

        if config["platform_key"] not in platforms_str:
            continue

        raw_data += run_kiq_batch(
            config["collector"],
            media_queries[:1],
            limit,
            name,
            max_calls=1,
        ) + "\n"
    with open("raw_osint_data.txt", "w", encoding="utf-8") as f:
        f.write(raw_data)
    with open(os.path.join(run_workspace, "raw_osint_data.txt"), "w", encoding="utf-8") as f:
        f.write(raw_data)

    return raw_data


