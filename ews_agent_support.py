# =============================================================================
# aviation_ci_app | Agent execution recovery and baseline intelligence analysis
#
# Responsibility: Recover structured candidate events, consolidate duplicate
#   findings, measure LLM usage, and execute resilient CrewAI calls.
# Design boundary: Fallback text and provisional outputs do not replace
#   source-level verification by the deterministic Harness.
# =============================================================================

"""Agent execution, structured-output recovery, and baseline analysis utilities."""

import uuid
from collections import Counter, deque
from itertools import islice
from threading import Lock

from pydantic import ValidationError

from ews_state import (
    ActionItem, Any, CIDimension, Callable, ConfidenceLevel, Crew, Dict,
    EWSReport, LLM_RUNTIME_STATS, List, Optional, PropagationEffect, RiskType,
    RunOutcomeStatus, SCMTier, SequenceMatcher, ThreatAssessment,
    TripleAPillar, Tuple, classify_llm_error, json, logger,
    lookup_supplier_in_registry, re, time,
)
from ews_validation import _normalize_for_quote_match

# Baseline extraction vocabulary and recovery directives (preserved verbatim).
_HIGH_RISK_KW = {
    "grounding", "directive", "emergency", "accident",
    "halt", "defect", "crack", "shortage", "delay",
}
_RECOVERY_NOTE = (
    "SCHEMA_RECOVERY_MALFORMED_CONFIRMED_FACTS: "
    "Malformed analyst factual text was discarded; "
    "no factual assertion is verified until the source is checked."
)
_RETRY_DIRECTIVE = (
    "\n\nRETRY DIRECTIVE: "
    "Keep the response concise. "
    "Return valid JSON only. "
    "Avoid unnecessary explanations."
)

# Shared runtime telemetry buffers and compiled source-identifier patterns.
_CREW_OUTPUT_LAST_USAGE = {}
_AUDIT_LOCK = Lock()
_RECOVERY_COUNTS = Counter()
_RECOVERY_EVENTS = deque(maxlen=128)
_LLM_CALL_EVENTS = deque(maxlen=512)
_FALLBACK_COUNTS = Counter()
_MAX_JSON_CANDIDATES = 32
_NTSB_CASE_RE = re.compile(r"\b(?:DCA|ERA|WPR|CEN|ANC)\d{2}[A-Z]{2}\d{3}\b", re.I)
_EASA_AD_BASE_RE = re.compile(r"\b(?:EASA\s+AD\s*)?(20\d{2}-\d{4})(?:[RC]\d+)?\b", re.I)
_FAA_LIFECYCLE_VERIFIED_RE = re.compile(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$")
_FAA_DOCKET_RE = re.compile(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$")
_OFFICIAL_SUMMARY_RE = re.compile(r"(?im)^Official Summary:\s*(.+)$")


class BatchRecoveryError(ValueError):
    """Unrecoverable Analyst batch with a machine-readable failure category."""

    def __init__(self, error_type: str, reason: str, document_ids=()):
        self.error_type = _classify_failure(error_type)
        self.document_ids = list(dict.fromkeys(document_ids))
        super().__init__(f"{self.error_type}: {reason}; document_ids={self.document_ids}")


class _EmptyLLMResponse(ValueError):
    """Internal sentinel raised when an LLM or Crew returns empty content."""
    error_type = "EMPTY_RESPONSE"


def _classify_failure(error, classified=None) -> str:
    """Translate provider and validation failures into one stable audit vocabulary."""
    raw = (classified if classified is not None else error if isinstance(error, str)
           else "SCHEMA_MISMATCH" if isinstance(error, ValidationError)
           else getattr(error, "error_type", None) or classify_llm_error(error))
    code, name = str(raw or "").upper(), (type(error).__name__.upper() if isinstance(error, Exception) else "")
    if "TIMEOUT" in code or "TIMEOUT" in name:
        return "LLM_TIMEOUT"
    if any(t in code or t in name for t in ("RATE_LIMIT", "429", "TOO_MANY_REQUESTS")):
        return "RATE_LIMIT"
    if code in {"INVALID_JSON", "JSON_SYNTAX_ERROR"} or "JSONDECODE" in name:
        return "INVALID_JSON"
    if code in {"SCHEMA_MISMATCH", "INVALID_STRUCTURE", "INVALID_FIELDS"}:
        return "SCHEMA_MISMATCH"
    if code in {"EMPTY_RESPONSE", "UNUSABLE_RESPONSE"} or ("EMPTY" in name and "RESPONSE" in name):
        return "EMPTY_RESPONSE"
    return "PROVIDER_ERROR"


def _audit_recovery(method: str, outcome: str, document_ids=(), reason: str = ""):
    """Record a bounded recovery attempt or fallback event under _AUDIT_LOCK."""
    with _AUDIT_LOCK:
        _RECOVERY_COUNTS[(method, outcome)] += 1
        if outcome in {"SUCCESS", "RETRY"}:
            _FALLBACK_COUNTS[reason or method] += 1
        _RECOVERY_EVENTS.append({"method": method, "outcome": outcome, "reason": reason or method, "document_ids": list(dict.fromkeys(document_ids))})


def get_batch_recovery_telemetry():
    """Return thread-safe snapshots of batch recovery attempts, fallbacks, and recent events."""
    with _AUDIT_LOCK:
        return {
            "attempts": [{"method": m, "outcome": s, "count": n} for (m, s), n in sorted(_RECOVERY_COUNTS.items())],
            "fallbacks": [{"reason": r, "count": n} for r, n in sorted(_FALLBACK_COUNTS.items())],
            "recent_events": list(_RECOVERY_EVENTS),
        }


def _find_json_payload(text: str, pattern: str, predicate: Callable[[Any], bool]) -> Any:
    """Scan up to _MAX_JSON_CANDIDATES anchors and return the first JSON value matching predicate."""
    decoder = json.JSONDecoder()
    for match in islice(re.finditer(pattern, text), _MAX_JSON_CANDIDATES):
        try:
            cand, _ = decoder.raw_decode(text[match.start():])
            if predicate(cand):
                return cand
        except ValueError:
            continue
    return None


def _candidate_list(value, *, nested=False, depth=0):
    """Accept only an unambiguous list of assessment dictionaries."""
    if depth > 4:
        return None
    if isinstance(value, list):
        return value if all(isinstance(i, dict) for i in value) and (nested or (bool(value) and all("company_affected" in i for i in value))) else None
    if not isinstance(value, dict):
        return None
    matches = [
        parsed for k, child in value.items()
        if ((kl := str(k).lower()) in {"threats", "candidates", "events", "results", "assessments"} and isinstance(child, list)
            or kl in {"data", "result", "output", "analysis", "payload", "response"})
        and (parsed := _candidate_list(child, nested=True, depth=depth + 1)) is not None
    ]
    return matches[0] if len(matches) == 1 else None


def _recover_batch_list(text: str, document_ids):
    """Repair JSON wrapper containers only; never synthesize missing assessment fields."""
    clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I)
    if len(clean) > 1_000_000:
        _audit_recovery("SCHEMA_MISMATCH", "FAILED", document_ids)
        raise BatchRecoveryError("SCHEMA_MISMATCH", "Oversized Analyst payload", document_ids)
    try:
        parsed = json.loads(clean)
        if parsed == []:
            return [], "DIRECT_JSON"
        if (items := _candidate_list(parsed)) is not None:
            return items, "DIRECT_JSON"
        _audit_recovery("SCHEMA_MISMATCH", "FAILED", document_ids)
        raise BatchRecoveryError("SCHEMA_MISMATCH", "Unexpected or ambiguous Analyst JSON structure", document_ids)
    except json.JSONDecodeError:
        failure_type = "INVALID_JSON"

    if (payload := _find_json_payload(clean, r"[\[{]", lambda v: _candidate_list(v) is not None)) is not None:
        return _candidate_list(payload), "WRAPPER_EXTRACTION"

    decoder, recovered = json.JSONDecoder(), []
    for match in islice(re.finditer(r"\{", clean), _MAX_JSON_CANDIDATES):
        try:
            item, _ = decoder.raw_decode(clean[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and "company_affected" in item and "evidence_ids" in item:
            recovered.append(item)
    if recovered:
        return recovered, "CANDIDATE_OBJECT_SALVAGE"

    _audit_recovery(failure_type, "FAILED", document_ids)
    raise BatchRecoveryError(failure_type, "No recoverable Analyst assessment list", document_ids)


def generate_keyword_baseline_report(
    user_query: str, docs: List[Dict[str, Any]], scope: str, run_id: str,
) -> EWSReport:
    """Generate a non-LLM keyword baseline over the collected OSINT documents."""
    default_comp = user_query.split(",")[0].strip() or "Aerospace Entity"
    threats: List[ThreatAssessment] = []
    for d in docs[:12]:
        text_low = f"{d.get('title', '')} {d.get('text', '')}".lower()
        kw_hits = sum(1 for kw in _HIGH_RISK_KW if kw in text_low)
        score = min(9, max(3, 3 + kw_hits * 2))
        supplier = lookup_supplier_in_registry(text_low)
        first_sentence = (d.get("text") or d.get("title") or "Keyword match in OSINT document.").split(".")[0][:220] + "."
        threats.append(ThreatAssessment(
            company_affected=supplier["official_name"] if supplier else default_comp,
            ci_dimension=CIDimension.TACTICAL,
            risk_type=RiskType.REGULATORY if d.get("source_type") == "REGULATORY" else RiskType.SUPPLY_CHAIN,
            scm_tier=SCMTier.TIER_1 if (supplier and "Tier 1" in supplier["default_tier"]) else SCMTier.OEM,
            propagation_effect=PropagationEffect.DIRECT, geographic_epicenter="Global / Unspecified",
            threat_description=f"[Rule-Based Baseline] Keyword match on '{d.get('title', '')[:120]}'.",
            confirmed_facts=first_sentence,
            analytical_interpretation="Generated by deterministic keyword baseline without multi-agent LLM synthesis.",
            hypothetical_scenario="Baseline rule alert.", fact_check_quote=first_sentence,
            evidence_ids=[d["doc_id"]], source_urls=[d["url"]],
            publication_time=d.get("published_at", "DATE_UNKNOWN"), evidence_citation=d["url"],
            adversarial_scenario="Keyword frequency heuristic triggered (no 5-factor I&W LLM reasoning).",
            threat_score=score, score_rationale=f"Rule-based keyword hit count: {kw_hits}",
            confidence_level=ConfidenceLevel.MEDIUM if d.get("verified_domain") else ConfidenceLevel.LOW,
            is_critical=score >= 8,
        ))
    return EWSReport(
        run_id=run_id, outcome_status=RunOutcomeStatus.COMPLETED,
        executive_summary=f"Rule-based non-LLM baseline (P2-05) matched {len(threats)} documents using keyword heuristics for '{user_query}'.",
        qa_audit_summary="Baseline mode: LLM QA Agent bypassed; deterministic URL binding applied.",
        hitl_status="WAITING_FOR_HITL", threats=threats,
        action_plan=[ActionItem(
            action="Review keyword-matched baseline alerts manually.",
            pros_and_cons="PRO: Zero LLM latency/cost; CON: High noise and no multi-tier causal reasoning.",
            triple_a_impact=TripleAPillar.AGILITY, owner="OSINT Analyst",
            deadline="Within 7 days", kpi="False positive rate vs multi-agent EWS",
        )],
    )


def _extract_batch_threats_fallback(
    raw_text: str, *, expected_doc_ids: Optional[List[str]] = None,
    documents_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    diagnostics: Optional[Dict[str, Any]] = None,
) -> Tuple[List[ThreatAssessment], int]:
    """Recover source-grounded candidate objects while retaining exact rejection reasons."""
    def validate_candidate(data):
        validated = ThreatAssessment.model_validate(data, context={"documents": documents_by_id})
        if expected_doc_ids is not None and not set(validated.evidence_ids).issubset(expected_doc_ids):
            raise ValueError(f"Evidence IDs outside the Analyst batch: {validated.evidence_ids}")
        return validated

    document_ids = list(dict.fromkeys((expected_doc_ids or []) + re.findall(r"\bDOC_[A-Z0-9_-]+\b", raw_text or "", re.I)))
    if not raw_text or not raw_text.strip():
        _audit_recovery("EMPTY_RESPONSE", "FAILED", document_ids)
        raise BatchRecoveryError("EMPTY_RESPONSE", "Analyst returned an empty response", document_ids)

    text = raw_text.strip()
    if text.lower() == "no data to analyze":
        if expected_doc_ids:
            _audit_recovery("EMPTY_RESPONSE", "FAILED", document_ids)
            raise BatchRecoveryError("EMPTY_RESPONSE", "Analyst did not examine the supplied documents", document_ids)
        return [], 0

    try:
        raw_list, method = _recover_batch_list(text, document_ids)
    except BatchRecoveryError as exc:
        if diagnostics is not None:
            diagnostics.update(error_type=exc.error_type, document_ids=exc.document_ids)
        raise

    accepted, rejected, rejected_details = [], 0, []
    for position, item in enumerate(raw_list, start=1):
        raw_ids = item.get("evidence_ids") if isinstance(item, dict) else None
        item_ids = raw_ids if isinstance(raw_ids, list) else []
        try:
            accepted.append(validate_candidate(item))
        except Exception as exc:
            errs = exc.errors() if isinstance(exc, ValidationError) else []
            # Discard only malformed JSON in confirmed_facts; never rewrite quotes or risk types.
            if (isinstance(item, dict) and len(errs) == 1 and tuple(errs[0].get("loc", ())) == ("confirmed_facts",)
                    and "confirmed_facts contains malformed JSON" in errs[0].get("msg", "")):
                prior_gap = str(item.get("missing_data") or "").strip()
                rec_item = {**item, "confirmed_facts": "", "missing_data": f"{prior_gap} | {_RECOVERY_NOTE}" if prior_gap else _RECOVERY_NOTE}
                try:
                    val = validate_candidate(rec_item)
                    val.confirmed_facts, val.claim_support_status, val.causal_support_status = "", "UNSUPPORTED", "UNSUPPORTED"
                    val.confidence_level = ConfidenceLevel.LOW
                    val.verification_status = "UNVERIFIED: Analyst confirmed_facts was malformed; independent evidence verification required"
                    accepted.append(val)
                    _audit_recovery("DISCARD_MALFORMED_FACTS", "SUCCESS", item_ids)
                    logger.warning("[CANDIDATE %d RECOVERED] Malformed confirmed_facts discarded.", position)
                    continue
                except Exception as rec_exc:
                    logger.warning("[CANDIDATE %d RECOVERY FAILED] %s", position, rec_exc)
            rejected += 1
            rejected_details.append({"position": position, "reason": "SCHEMA_MISMATCH", "fields": [str(e.get("loc", ())) for e in errs], "document_ids": item_ids})
            _audit_recovery("SCHEMA_MISMATCH", "FAILED", item_ids or document_ids)
            logger.warning("[CANDIDATE %d REJECTED] Pydantic validation: %s", position, exc)

    if raw_list and not accepted:
        if method != "DIRECT_JSON":
            _audit_recovery(method, "FAILED", document_ids)
        if diagnostics is not None:
            diagnostics.update(error_type="SCHEMA_MISMATCH", document_ids=document_ids, rejected_candidates=rejected, rejected_details=rejected_details, recovery_method=method)
        raise BatchRecoveryError("SCHEMA_MISMATCH", f"All {rejected} candidates failed Pydantic validation; not a negative finding", document_ids)

    if method != "DIRECT_JSON":
        _audit_recovery(method, "SUCCESS", document_ids)
    if diagnostics is not None:
        diagnostics.update(error_type=None, recovery_method=method, document_ids=document_ids, accepted_candidates=len(accepted), rejected_candidates=rejected, rejected_details=rejected_details)
    return accepted, rejected


def _verified_faa_docket(doc: Optional[Dict[str, Any]]) -> str:
    """Return the verified FAA docket ID from a lifecycle-checked SRC_001 document."""
    if not doc or doc.get("source_id") != "SRC_001" or not _FAA_LIFECYCLE_VERIFIED_RE.search(text := doc.get("text", "")):
        return ""
    return m.group(1) if (m := _FAA_DOCKET_RE.search(text)) else ""


def _split_faa_candidates(candidates, documents):
    """Split a regulatory candidate when it merges evidence from multiple verified FAA dockets."""
    docs, result = {d["doc_id"]: d for d in documents}, []
    for cand in candidates:
        if cand.risk_type.value != "REGULATORY":
            result.append(cand)
            continue
        groups = {}
        for eid in cand.evidence_ids:
            if (d := docs.get(eid)) and (docket := _verified_faa_docket(d)):
                groups.setdefault(docket, []).append(d)
        if len(groups) <= 1:
            result.append(cand)
            continue

        logger.warning("[FAA SPLIT] Candidate %s contains %d different dockets", cand.event_id, len(groups))
        for docket, group in groups.items():
            d = group[0]
            if not (m := _OFFICIAL_SUMMARY_RE.search(d.get("text", ""))):
                logger.warning("[FAA SPLIT] Missing official summary: %s", docket)
                continue
            summary, clone = m.group(1).strip(), cand.model_copy(deep=True)
            clone.event_id = f"EVT_{uuid.uuid4().hex[:8].upper()}"
            clone.evidence_ids, clone.source_urls, clone.evidence_citation = [d["doc_id"]], [d["url"]], d["url"]
            clone.publication_time = d.get("published_at", "DATE_UNKNOWN")
            clone.fact_check_quote, clone.threat_description, clone.confirmed_facts = " ".join(summary.split()[:23]), summary[:600], summary[:400]
            clone.affected_component, clone.corroboration_summary = "Unknown / Not specified in source", {}
            clone.analytical_interpretation = "Official FAA regulatory action identified. Downstream operational impacts require verification."
            clone.adversarial_scenario = "Hypothetical scenario: inspection requirements could increase maintenance workload if capacity is constrained. Actual disruption is not established."
            result.append(clone)
    return result


def _extract_case_ids(candidate, docs_by_id, source_id: str, pattern: re.Pattern, fields: Tuple[str, ...]) -> set[str]:
    """Extract normalized uppercase case/directive identifiers from matching source documents."""
    return {
        m.upper() for eid in (candidate.evidence_ids or [])
        if (doc := docs_by_id.get(eid)) and doc.get("source_id") == source_id
        for m in pattern.findall(" ".join(str(doc.get(k) or "") for k in fields))
    }


def _candidate_ntsb_case_ids(candidate, docs_by_id):
    """Extract NTSB investigation identifiers for case-aware duplicate detection."""
    return _extract_case_ids(candidate, docs_by_id, "SRC_003", _NTSB_CASE_RE, ("title", "text", "url"))


def _candidate_easa_ad_bases(candidate, docs_by_id):
    """Extract base EASA airworthiness directive numbers across revision suffixes."""
    return _extract_case_ids(candidate, docs_by_id, "SRC_002", _EASA_AD_BASE_RE, ("title", "text"))


def _compatible_event_statuses(first, second):
    """Different known lifecycle milestones represent distinct events."""
    status = lambda c: str(getattr(v := getattr(c, "event_status", None), "value", v) or "").strip().upper()
    left, right = status(first), status(second)
    return not (left and right and left != right)


def _consolidate_candidate_threats(
    candidates: List[ThreatAssessment], documents: Optional[List[Dict[str, Any]]] = None,
) -> List[ThreatAssessment]:
    """Consolidate duplicate findings without merging distinct FAA, EASA, or NTSB proceedings."""
    documents = documents or []
    candidates = _split_faa_candidates(candidates, documents)
    docs_by_id = {d["doc_id"]: d for d in documents}
    cand_dockets_of = lambda c: {dk for eid in c.evidence_ids if (dk := _verified_faa_docket(docs_by_id.get(eid)))}
    consolidated: List[Tuple[ThreatAssessment, str]] = []

    for cand in candidates:
        cand_urls = set(cand.source_urls or ([cand.evidence_citation] if cand.evidence_citation else []))
        cand_docs, cand_comp_low, cand_prog_low = set(cand.evidence_ids or []), cand.company_affected.lower(), (cand.affected_program or "").lower()
        cand_norm = _normalize_for_quote_match(f"{cand.confirmed_facts} {cand.threat_description}")
        cand_ntsb, cand_easa, cand_dockets = _candidate_ntsb_case_ids(cand, docs_by_id), _candidate_easa_ad_bases(cand, docs_by_id), cand_dockets_of(cand)

        for idx, (existing, ex_norm) in enumerate(consolidated):
            if not _compatible_event_statuses(cand, existing):
                continue
            ex_dockets = cand_dockets_of(existing)
            if cand_dockets and ex_dockets and cand_dockets != ex_dockets:
                continue
            ex_easa = _candidate_easa_ad_bases(existing, docs_by_id)
            if cand_easa and ex_easa and cand_easa != ex_easa:
                continue

            no_dockets = not cand_dockets and not ex_dockets and cand.risk_type == existing.risk_type
            same_easa = len(cand_easa) == len(ex_easa) == 1 and cand_easa == ex_easa and no_dockets
            ex_ntsb = _candidate_ntsb_case_ids(existing, docs_by_id)
            same_ntsb = len(cand_ntsb) == len(ex_ntsb) == 1 and cand_ntsb == ex_ntsb and no_dockets
            ex_urls = set(existing.source_urls or ([existing.evidence_citation] if existing.evidence_citation else []))
            same_source = bool((cand_urls & ex_urls) or (cand_docs & set(existing.evidence_ids or [])))
            desc_sim = SequenceMatcher(None, cand_norm, ex_norm).ratio()

            if same_ntsb or same_easa or (
                cand_comp_low == existing.company_affected.lower() and cand_prog_low == (existing.affected_program or "").lower()
                and cand.risk_type == existing.risk_type and ((same_source and desc_sim >= 0.45) or desc_sim >= 0.75)
            ):
                merged = existing.model_copy(deep=True)
                merged.evidence_ids = list(dict.fromkeys(existing.evidence_ids + cand.evidence_ids))
                merged.source_urls = list(dict.fromkeys(existing.source_urls + cand.source_urls))
                merged.kiq_ids = list(dict.fromkeys(existing.kiq_ids + cand.kiq_ids))
                merged.threat_score = max(existing.threat_score, cand.threat_score)
                try:
                    consolidated[idx] = (ThreatAssessment.model_validate(merged.model_dump(mode="python"), context={"documents": docs_by_id or None}), ex_norm)
                except ValidationError as exc:
                    logger.warning("[CONSOLIDATION] Candidate merge rejected: %s", exc)
                    continue
                break
        else:
            consolidated.append((cand, cand_norm))

    return [item for item, _ in consolidated]


def _usage_fields(value):
    """Normalize prompt, completion, and request counters across provider result formats."""
    if value is None:
        return None

    def read(*names):
        for name in names:
            if (raw := value.get(name) if isinstance(value, dict) else getattr(value, name, None)) is not None:
                try:
                    return cnt if (cnt := int(raw)) >= 0 else None
                except (ValueError, TypeError):
                    continue
        return None

    fields = (read("prompt_tokens", "input_tokens", "prompt_token_count"),
              read("completion_tokens", "output_tokens", "completion_token_count", "candidates_token_count"),
              read("successful_requests", "requests"))
    return fields if any(f is not None for f in fields) else None


def _llm_identity(llm):
    """Extract normalized (model, provider) labels from an LLM wrapper instance."""
    model = str(getattr(llm, "model", None) or getattr(llm, "model_name", None) or "UNKNOWN")
    return model, str(getattr(llm, "provider", None) or (model.split("/", 1)[0] if "/" in model else "UNKNOWN"))


def _first_crew_llm(crew):
    """Return the first configured LLM instance among a crew's agents."""
    return next((llm for a in (getattr(crew, "agents", []) or []) if (llm := getattr(a, "llm", None)) is not None), None)


def _record_llm_call(llm, task_type, attempt, status, usage=None, method="UNKNOWN", error_type=None, model=None, provider=None):
    """Append a bounded per-attempt LLM telemetry record and track unknown-usage counts."""
    m_name, p_name = _llm_identity(llm)
    inputs, outputs, reqs = usage or (None, None, None)
    state = "UNKNOWN" if inputs is None or outputs is None else ("PROVISIONAL" if method == "CREW_OUTPUT_UNVERIFIED" else "MEASURED")
    entry = {
        "task_type": task_type, "attempt": attempt, "status": status,
        "model": model or m_name, "provider": provider or p_name,
        "usage_method": method, "usage_status": state,
        "input_tokens": inputs if inputs is not None else "UNKNOWN",
        "output_tokens": outputs if outputs is not None else "UNKNOWN",
        "provider_requests": reqs if reqs is not None else "UNKNOWN", "error_type": error_type,
    }
    with _AUDIT_LOCK:
        _LLM_CALL_EVENTS.append(entry)
    if state == "UNKNOWN":
        LLM_RUNTIME_STATS["usage_unknown_calls"] = LLM_RUNTIME_STATS.get("usage_unknown_calls", 0) + 1


def get_llm_call_telemetry():
    """Return bounded per-attempt audit data; missing usage is never reported as zero."""
    with _AUDIT_LOCK:
        return list(_LLM_CALL_EVENTS)


def reset_agent_support_telemetry():
    """Reset in-memory usage and recovery telemetry at the start of a new run."""
    with _AUDIT_LOCK:
        for store in (_LLM_CALL_EVENTS, _RECOVERY_COUNTS, _RECOVERY_EVENTS, _FALLBACK_COUNTS, _CREW_OUTPUT_LAST_USAGE):
            store.clear()


def _llm_usage_snapshot(llm):
    """Read normalized token usage from an LLM instance when supported."""
    if callable(getter := getattr(llm, "get_token_usage_summary", None)):
        try:
            return _usage_fields(getter())
        except Exception as exc:
            logger.warning("[TOKEN AUDIT] LLM usage snapshot failed: %s", exc)
    return None


def call_tracked_llm(llm, messages, *, task_type: str, attempt: int = 1):
    """Measure direct model calls, including FR03 and format repairs."""
    before = _llm_usage_snapshot(llm)
    LLM_RUNTIME_STATS["api_calls"] = LLM_RUNTIME_STATS.get("api_calls", 0) + 1
    try:
        result = llm.call(messages)
        if result is None or (isinstance(result, str) and not result.strip()):
            raise _EmptyLLMResponse("Model returned no content")
    except Exception as exc:
        _record_llm_call(llm, task_type, attempt, "FAILED", error_type=_classify_failure(exc))
        raise

    after = _llm_usage_snapshot(llm)
    if before and after and all(v is not None for v in before[:2] + after[:2]):
        delta = tuple(max(0, end - start) for start, end in zip(before[:2], after[:2]))
        if any(delta):
            _record_llm_call(llm, task_type, attempt, "SUCCESS", (*delta, None), "LLM_DELTA")
            return result
    usage = _usage_fields(getattr(result, "usage", None))
    _record_llm_call(llm, task_type, attempt, "SUCCESS", usage, "DIRECT_RESPONSE" if usage else "UNKNOWN")
    return result


def call_external_llm_tracked(request: Callable[[], Any], *, task_type: str, model: str, provider: str, attempt: int = 1):
    """Record direct SDK calls with provider-reported usage when available."""
    LLM_RUNTIME_STATS["api_calls"] = LLM_RUNTIME_STATS.get("api_calls", 0) + 1
    try:
        response = request()
        if response is None or (isinstance(response, str) and not response.strip()):
            raise _EmptyLLMResponse("Provider returned no content")
    except Exception as exc:
        _record_llm_call(None, task_type, attempt, "FAILED", error_type=_classify_failure(exc), model=model, provider=provider)
        raise
    usage = _usage_fields(getattr(response, "usage_metadata", None) or getattr(response, "usage", None))
    actual_model = str(getattr(response, "model_version", None) or model)
    _record_llm_call(None, task_type, attempt, "SUCCESS", usage, "DIRECT_RESPONSE" if usage else "UNKNOWN", model=actual_model, provider=provider)
    return response


def _crew_llm_usage_snapshot(crew):
    """Collect lifetime token usage snapshots across all distinct LLMs attached to a crew."""
    agents = list(getattr(crew, "agents", []) or [])
    if (mgr := getattr(crew, "manager_agent", None)) is not None:
        agents.append(mgr)
    result = {}
    for agent in agents:
        if (llm := getattr(agent, "llm", None)) is not None and id(llm) not in result and (fields := _llm_usage_snapshot(llm)) is not None:
            result[id(llm)] = fields
    return result


def _crew_token_delta(crew, before, result, phase_label, attempt=1):
    """Calculate incremental token usage for one CrewAI kickoff without double-counting."""
    after, llm = _crew_llm_usage_snapshot(crew), _first_crew_llm(crew)
    if before and before.keys() == after.keys() and all(before[k][i] is not None and after[k][i] is not None for k in before for i in (0, 1)):
        p_tok, c_tok = sum(max(0, after[k][0] - before[k][0]) for k in before), sum(max(0, after[k][1] - before[k][1]) for k in before)
        if p_tok or c_tok:
            _record_llm_call(llm, phase_label, attempt, "SUCCESS", (p_tok, c_tok, None), "LLM_DELTA")
            logger.info("[TOKEN AUDIT] %s method=LLM_DELTA input=%s output=%s", phase_label, p_tok, c_tok)
            return p_tok, c_tok

    if (usage := _usage_fields(getattr(result, "token_usage", None))) is None:
        _record_llm_call(llm, phase_label, attempt, "SUCCESS")
        logger.warning("[TOKEN AUDIT] %s usage=UNKNOWN", phase_label)
        return 0, 0

    llm_ids = tuple(sorted({id(getattr(a, "llm")) for a in (getattr(crew, "agents", []) or []) if getattr(a, "llm", None)}))
    previous = _CREW_OUTPUT_LAST_USAGE.get(llm_ids)
    _CREW_OUTPUT_LAST_USAGE[llm_ids] = usage
    p_tok, c_tok, requests = usage
    if previous and all(x is not None for x in (*usage, *previous)) and requests > previous[2] > 0 and p_tok >= previous[0] and c_tok >= previous[1]:
        p_tok, c_tok, method = p_tok - previous[0], c_tok - previous[1], "CREW_CUMULATIVE_DELTA"
    else:
        method = "CREW_OUTPUT_UNVERIFIED"
        logger.warning("[TOKEN AUDIT] %s token usage may be cumulative; verify against provider usage records.", phase_label)

    _record_llm_call(llm, phase_label, attempt, "SUCCESS", (p_tok, c_tok, requests), method)
    logger.info("[TOKEN AUDIT] %s method=%s input=%s output=%s", phase_label, method, p_tok, c_tok)
    return p_tok or 0, c_tok or 0


def get_shared_llm_usage_snapshot():
    """Read lifetime usage once per shared CrewAI LLM instance, keyed by model ID."""
    from agents import fast_llm, reasoning_llm

    result, seen_ids = {}, set()
    for llm in (fast_llm, reasoning_llm):
        if llm is None or id(llm) in seen_ids:
            continue
        seen_ids.add(id(llm))
        if (data := _llm_usage_snapshot(llm)) and all(v is not None for v in data):
            model_name, _ = _llm_identity(llm)
            key = model_name if model_name and model_name != "UNKNOWN" else f"UNVERIFIED_LLM_{id(llm)}"
            result[key] = tuple(p + c for p, c in zip(result[key], data)) if key in result else data
    return result


def _kickoff_crew_with_smart_recovery(
    crew: Crew, phase_label: str, shrink_callback: Optional[Callable[[], None]] = None,
) -> Tuple[Any, int, int]:
    """Execute Crew using the configured LLM only with a bounded smart single retry."""
    max_attempts = 1 if phase_label.startswith("BATCH_") else 2
    for attempt in range(1, max_attempts + 1):
        LLM_RUNTIME_STATS["api_calls"] += 1
        try:
            usage_before = _crew_llm_usage_snapshot(crew)
            res = crew.kickoff()
            if res is None or (isinstance(res, str) and not res.strip()):
                raise _EmptyLLMResponse("Crew returned no content")
            return res, *_crew_token_delta(crew, usage_before, res, phase_label, attempt)
        except Exception as err:
            err_type = classify_llm_error(err)
            failure_code = _classify_failure(err, err_type)
            _record_llm_call(_first_crew_llm(crew), phase_label, attempt, "FAILED", error_type=failure_code)
            logger.warning("[LLM ERROR - %s] Attempt %d/%d, type=%s (provider=%s): %s", phase_label, attempt, max_attempts, failure_code, err_type, str(err)[:200])

            if failure_code == "RATE_LIMIT":
                logger.error("[LLM] Rate limit reached during %s. Model switching is disabled.", phase_label)
                raise
            if attempt >= max_attempts:
                logger.error("[LLM] %s failed after %s attempts.", phase_label, max_attempts)
                raise
            if err_type in {"LENGTH_LIMIT", "EMPTY_RESPONSE", "INVALID_JSON"} or failure_code == "EMPTY_RESPONSE":
                if shrink_callback:
                    shrink_callback()
                for task in crew.tasks:
                    if _RETRY_DIRECTIVE not in task.description:
                        task.description += _RETRY_DIRECTIVE
            elif err_type == "SERVICE_503" or failure_code == "LLM_TIMEOUT":
                time.sleep(1 if failure_code == "LLM_TIMEOUT" else 3)
            else:
                raise
            LLM_RUNTIME_STATS["retries"] = LLM_RUNTIME_STATS.get("retries", 0) + 1
            _audit_recovery("LLM_RETRY", "RETRY", reason=failure_code)
