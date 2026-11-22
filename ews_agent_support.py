# =============================================================================
# aviation_ci_app | Agent execution recovery and baseline intelligence analysis
#
# Responsibility: Recover structured candidate events, consolidate duplicate findings, measure LLM usage,
#   and execute resilient CrewAI calls.
# Design boundary: Fallback text and provisional outputs do not replace source-level verification by the
#   deterministic Harness.
# =============================================================================

"""Agent execution, structured-output recovery, and baseline analysis utilities."""

from collections import Counter, deque
from itertools import islice
from threading import Lock

from pydantic import ValidationError

from ews_state import (
    ActionItem, Any, CIDimension, Callable, ConfidenceLevel,
    Crew, Dict, EWSReport, LLM_RUNTIME_STATS, List, Optional,
    PropagationEffect, RiskType, RunOutcomeStatus, SCMTier,
    SequenceMatcher, ThreatAssessment, TripleAPillar, Tuple,
    classify_llm_error, json, logger, lookup_supplier_in_registry, re, time,
)
from ews_validation import _normalize_for_quote_match

# Baseline extraction terms and recovery metadata.
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

_CREW_OUTPUT_LAST_USAGE = {}
_AUDIT_LOCK = Lock()
_RECOVERY_COUNTS = Counter()
_RECOVERY_EVENTS = deque(maxlen=128)
_LLM_CALL_EVENTS = deque(maxlen=512)
_FALLBACK_COUNTS = Counter()
_MAX_JSON_CANDIDATES = 32
_NTSB_CASE_RE = re.compile(r"\b(?:DCA|ERA|WPR|CEN|ANC)\d{2}[A-Z]{2}\d{3}\b", re.I)
_EASA_AD_BASE_RE = re.compile(r"\b(?:EASA\s+AD\s*)?(20\d{2}-\d{4})(?:[RC]\d+)?\b", re.I)


class BatchRecoveryError(ValueError):
    """Unrecoverable Analyst batch with a machine-readable failure category."""

    def __init__(self, error_type: str, reason: str, document_ids=()):
        self.error_type = _classify_failure(error_type)
        self.document_ids = list(dict.fromkeys(document_ids))
        super().__init__(f"{self.error_type}: {reason}; document_ids={self.document_ids}")


class _EmptyLLMResponse(ValueError):
    error_type = "EMPTY_RESPONSE"


def _classify_failure(error, classified=None) -> str:
    """Translate provider and validation failures into one stable audit vocabulary."""
    raw = (classified if classified is not None else error if isinstance(error, str)
           else "SCHEMA_MISMATCH" if isinstance(error, ValidationError)
           else getattr(error, "error_type", None) or classify_llm_error(error))
    code = str(raw or "").upper()
    name = type(error).__name__.upper() if isinstance(error, Exception) else ""
    if "TIMEOUT" in code or "TIMEOUT" in name:
        return "LLM_TIMEOUT"
    if any(term in code or term in name for term in ("RATE_LIMIT", "429", "TOO_MANY_REQUESTS")):
        return "RATE_LIMIT"
    if code in {"INVALID_JSON", "JSON_SYNTAX_ERROR"} or "JSONDECODE" in name:
        return "INVALID_JSON"
    if code in {"SCHEMA_MISMATCH", "INVALID_STRUCTURE", "INVALID_FIELDS"}:
        return "SCHEMA_MISMATCH"
    if code in {"EMPTY_RESPONSE", "UNUSABLE_RESPONSE"} or "EMPTY" in name and "RESPONSE" in name:
        return "EMPTY_RESPONSE"
    return "PROVIDER_ERROR"


def _audit_recovery(method: str, outcome: str, document_ids=(), reason: str = ""):
    with _AUDIT_LOCK:
        _RECOVERY_COUNTS[(method, outcome)] += 1
        if outcome in {"SUCCESS", "RETRY"}:
            _FALLBACK_COUNTS[reason or method] += 1
        _RECOVERY_EVENTS.append({"method": method, "outcome": outcome,
                                 "reason": reason or method,
                                 "document_ids": list(dict.fromkeys(document_ids))})


def get_batch_recovery_telemetry():
    with _AUDIT_LOCK:
        return {"attempts": [{"method": m, "outcome": s, "count": n}
                             for (m, s), n in sorted(_RECOVERY_COUNTS.items())],
                "fallbacks": [{"reason": reason, "count": n}
                              for reason, n in sorted(_FALLBACK_COUNTS.items())],
                "recent_events": list(_RECOVERY_EVENTS)}

# Recover a bounded JSON object or array from imperfect model output.
def _find_json_payload(text: str, pattern: str, predicate: Callable[[Any], bool]) -> Any:
    decoder = json.JSONDecoder()
    for match in islice(re.finditer(pattern, text), _MAX_JSON_CANDIDATES):
        try:
            candidate, _ = decoder.raw_decode(text[match.start():])
            if predicate(candidate):
                return candidate
        except ValueError:
            continue
    return None


def _candidate_list(value, *, nested=False, depth=0):
    """Accept only an unambiguous list of assessment dictionaries."""
    if depth > 4:
        return None
    if isinstance(value, list):
        return value if all(isinstance(item, dict) for item in value) and (
            nested or bool(value) and all("company_affected" in item for item in value)
        ) else None
    if not isinstance(value, dict):
        return None
    matches = []
    for key, child in value.items():
        key = str(key).lower()
        if key in {"threats", "candidates", "events", "results", "assessments"}:
            if isinstance(child, list):
                parsed = _candidate_list(child, nested=True, depth=depth + 1)
                if parsed is not None:
                    matches.append(parsed)
        elif key in {"data", "result", "output", "analysis", "payload", "response"}:
            parsed = _candidate_list(child, nested=True, depth=depth + 1)
            if parsed is not None:
                matches.append(parsed)
    return matches[0] if len(matches) == 1 else None


def _recover_batch_list(text: str, document_ids):
    """Repair containers only; never synthesize missing assessment fields."""
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

    payload = _find_json_payload(clean, r"[\[{]", lambda value: _candidate_list(value) is not None)
    if payload is not None:
        return _candidate_list(payload), "WRAPPER_EXTRACTION"

    decoder = json.JSONDecoder()
    recovered = []
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

# Produce a non-LLM comparison baseline from collected documents.
# Source-derived candidates remain provisional until the deterministic evidence checks run.
def generate_keyword_baseline_report(
    user_query: str, docs: List[Dict[str, Any]], scope: str, run_id: str
) -> EWSReport:
    # The baseline is intentionally lexical; its scores must not be treated as validated events.
    """Generate a non-LLM keyword baseline over the collected OSINT documents."""
    default_comp = user_query.split(",")[0].strip() or "Aerospace Entity"
    threats: List[ThreatAssessment] = []

    for d in docs[:12]:
        text_low = f"{d.get('title', '')} {d.get('text', '')}".lower()
        kw_hits = sum(1 for kw in _HIGH_RISK_KW if kw in text_low)
        score = min(9, max(3, 3 + kw_hits * 2))
        supplier = lookup_supplier_in_registry(text_low)
        first_sentence = (d.get("text") or d.get("title") or "Keyword match in OSINT document.").split(".")[0][:220] + "."

        threats.append(
            ThreatAssessment(
                company_affected=supplier["official_name"] if supplier else default_comp,
                ci_dimension=CIDimension.TACTICAL,
                risk_type=RiskType.REGULATORY if d.get("source_type") == "REGULATORY" else RiskType.SUPPLY_CHAIN,
                scm_tier=SCMTier.TIER_1 if (supplier and "Tier 1" in supplier["default_tier"]) else SCMTier.OEM,
                propagation_effect=PropagationEffect.DIRECT,
                geographic_epicenter="Global / Unspecified",
                threat_description=f"[Rule-Based Baseline] Keyword match on '{d.get('title', '')[:120]}'.",
                confirmed_facts=first_sentence,
                analytical_interpretation="Generated by deterministic keyword baseline without multi-agent LLM synthesis.",
                hypothetical_scenario="Baseline rule alert.",
                fact_check_quote=first_sentence,
                evidence_ids=[d["doc_id"]],
                source_urls=[d["url"]],
                publication_time=d.get("published_at", "DATE_UNKNOWN"),
                evidence_citation=d["url"],
                adversarial_scenario="Keyword frequency heuristic triggered (no 5-factor I&W LLM reasoning).",
                threat_score=score,
                score_rationale=f"Rule-based keyword hit count: {kw_hits}",
                confidence_level=ConfidenceLevel.MEDIUM if d.get("verified_domain") else ConfidenceLevel.LOW,
                is_critical=score >= 8,
            )
        )

    return EWSReport(
        run_id=run_id,
        outcome_status=RunOutcomeStatus.COMPLETED,
        executive_summary=f"Rule-based non-LLM baseline (P2-05) matched {len(threats)} documents using keyword heuristics for '{user_query}'.",
        qa_audit_summary="Baseline mode: LLM QA Agent bypassed; deterministic URL binding applied.",
        hitl_status="WAITING_FOR_HITL",
        threats=threats,
        action_plan=[
            ActionItem(
                action="Review keyword-matched baseline alerts manually.",
                pros_and_cons="PRO: Zero LLM latency/cost; CON: High noise and no multi-tier causal reasoning.",
                triple_a_impact=TripleAPillar.AGILITY,
                owner="OSINT Analyst",
                deadline="Within 7 days",
                kpi="False positive rate vs multi-agent EWS",
            )
        ],
    )

# Recover valid candidate assessments from partial Analyst batch output.
# Recover individually valid records without accepting malformed surrounding model output.
def _extract_batch_threats_fallback(
    raw_text: str, *, expected_doc_ids: Optional[List[str]] = None,
    documents_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    diagnostics: Optional[Dict[str, Any]] = None,
) -> Tuple[List[ThreatAssessment], int]:
    """Recover source-grounded candidate objects; retain exact rejection reasons."""
    def validate_candidate(data):
        validated = ThreatAssessment.model_validate(
            data, context={"documents": documents_by_id}
        )
        if expected_doc_ids is not None and not set(validated.evidence_ids).issubset(expected_doc_ids):
            raise ValueError(f"Evidence IDs outside the Analyst batch: {validated.evidence_ids}")
        return validated

    document_ids = list(dict.fromkeys((expected_doc_ids or []) +
                                   re.findall(r"\bDOC_[A-Z0-9_-]+\b", raw_text or "", re.I)))
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
    accepted: List[ThreatAssessment] = []
    rejected = 0
    rejected_details = []

    for position, item in enumerate(raw_list, start=1):
        item_ids = (item.get("evidence_ids") or [] if isinstance(item, dict) else [])
        item_ids = item_ids if isinstance(item_ids, list) else []
        try:
            accepted.append(validate_candidate(item))
        except Exception as exc:
            validation_errors = exc.errors() if isinstance(exc, ValidationError) else []

            # JSON recovery cannot infer a different risk or rewrite a source quote.
            facts_only_error = (
                isinstance(item, dict)
                and len(validation_errors) == 1
                and tuple(validation_errors[0].get("loc", ())) == ("confirmed_facts",)
                and "confirmed_facts contains malformed JSON" in validation_errors[0].get("msg", "")
            )
            if facts_only_error:
                prior_gap = str(item.get("missing_data") or "").strip()
                recovered_item = {
                    **item,
                    "confirmed_facts": "",
                    "missing_data": f"{prior_gap} | {_RECOVERY_NOTE}" if prior_gap else _RECOVERY_NOTE,
                }
                try:
                    validated = validate_candidate(recovered_item)
                    validated.confirmed_facts = ""
                    validated.claim_support_status = "UNSUPPORTED"
                    validated.causal_support_status = "UNSUPPORTED"
                    validated.confidence_level = ConfidenceLevel.LOW
                    validated.verification_status = "UNVERIFIED: Analyst confirmed_facts was malformed; independent evidence verification required"
                    accepted.append(validated)
                    _audit_recovery("DISCARD_MALFORMED_FACTS", "SUCCESS", item_ids)
                    logger.warning("[CANDIDATE %d RECOVERED] Malformed confirmed_facts discarded.", position)
                    continue
                except Exception as recovery_exc:
                    logger.warning("[CANDIDATE %d RECOVERY FAILED] %s", position, recovery_exc)

            rejected += 1
            rejected_details.append({"position": position, "reason": "SCHEMA_MISMATCH",
                                     "fields": [str(e.get("loc", ())) for e in validation_errors],
                                     "document_ids": item_ids})
            _audit_recovery("SCHEMA_MISMATCH", "FAILED", item_ids or document_ids)
            logger.warning("[CANDIDATE %d REJECTED] Pydantic validation: %s", position, exc)

    if raw_list and not accepted:
        if method != "DIRECT_JSON":
            _audit_recovery(method, "FAILED", document_ids)
        if diagnostics is not None:
            diagnostics.update(error_type="SCHEMA_MISMATCH", document_ids=document_ids,
                               rejected_candidates=rejected, rejected_details=rejected_details,
                               recovery_method=method)
        raise BatchRecoveryError("SCHEMA_MISMATCH", f"All {rejected} candidates failed Pydantic validation; not a negative finding", document_ids)

    if method != "DIRECT_JSON":
        _audit_recovery(method, "SUCCESS", document_ids)
    if diagnostics is not None:
        diagnostics.update(error_type=None, recovery_method=method,
                           document_ids=document_ids, accepted_candidates=len(accepted),
                           rejected_candidates=rejected, rejected_details=rejected_details)
    return accepted, rejected

# Keep distinct FAA proceedings from being merged during candidate consolidation.
# A shared manufacturer or URL does not, by itself, prove two regulatory cases are identical.
def _split_faa_candidates(candidates, documents):
    import uuid
    docs = {d["doc_id"]: d for d in documents}
    result = []

    # Extract docket numbers to preserve separate FAA proceedings.
    def docket_of(d):
        if d.get("source_id") != "SRC_001":
            return ""
        text = d.get("text", "")
        if not re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", text):
            return ""
        m = re.search(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$", text)
        return m.group(1) if m else ""

    for candidate in candidates:
        if candidate.risk_type.value != "REGULATORY":
            result.append(candidate)
            continue

        groups = {}
        for eid in candidate.evidence_ids:
            if d := docs.get(eid):
                if docket := docket_of(d):
                    groups.setdefault(docket, []).append(d)

        if len(groups) <= 1:
            result.append(candidate)
            continue

        logger.warning(
            "[FAA SPLIT] Candidate %s contains %d different dockets",
            candidate.event_id,
            len(groups)
        )

        for docket, group in groups.items():
            d = group[0]
            text = d.get("text", "")
            m = re.search(r"(?im)^Official Summary:\s*(.+)$", text)
            if not m:
                logger.warning("[FAA SPLIT] Missing official summary: %s", docket)
                continue

            summary = m.group(1).strip()
            clone = candidate.model_copy(deep=True)
            clone.event_id = f"EVT_{uuid.uuid4().hex[:8].upper()}"
            clone.evidence_ids = [d["doc_id"]]
            clone.source_urls = [d["url"]]
            clone.evidence_citation = d["url"]
            clone.publication_time = d.get("published_at", "DATE_UNKNOWN")
            clone.fact_check_quote = " ".join(summary.split()[:23])
            clone.threat_description = summary[:600]
            clone.confirmed_facts = summary[:400]
            clone.affected_component = "Unknown / Not specified in source"
            clone.corroboration_summary = {}
            clone.analytical_interpretation = "Official FAA regulatory action identified. Downstream operational impacts require verification."
            clone.adversarial_scenario = "Hypothetical scenario: inspection requirements could increase maintenance workload if capacity is constrained. Actual disruption is not established."
            result.append(clone)

    return result

# Extract NTSB investigation identifiers for case-aware duplicate detection.
def _candidate_ntsb_case_ids(candidate, docs_by_id):
    ids = set()
    for evidence_id in candidate.evidence_ids or []:
        if (doc := docs_by_id.get(evidence_id)) and doc.get("source_id") == "SRC_003":
            record = " ".join(str(doc.get(k) or "") for k in ("title", "text", "url"))
            ids.update(item.upper() for item in _NTSB_CASE_RE.findall(record))
    return ids

# Extract base EASA directive identifiers across revision suffixes.
def _candidate_easa_ad_bases(candidate, docs_by_id):
    result = set()
    for evidence_id in candidate.evidence_ids or []:
        if (doc := docs_by_id.get(evidence_id)) and doc.get("source_id") == "SRC_002":
            text = f"{doc.get('title') or ''} {doc.get('text') or ''}"
            result.update(m.upper() for m in _EASA_AD_BASE_RE.findall(text))
    return result


def _compatible_event_statuses(first, second):
    """Different known lifecycle milestones represent distinct events."""
    def status(candidate):
        value = getattr(candidate, "event_status", None)
        return str(getattr(value, "value", value) or "").strip().upper()

    left, right = status(first), status(second)
    return not (left and right and left != right)

# Merge duplicate candidate findings without collapsing distinct regulatory events.
# Retain independent source references when consolidating repeated coverage.
# Merge candidates only when supporting evidence is consistent with a shared incident.
def _consolidate_candidate_threats(
    candidates: List[ThreatAssessment], documents: Optional[List[Dict[str, Any]]] = None
) -> List[ThreatAssessment]:
    # Deduplicate events while preserving distinct docket/case identities.
    """Consolidate findings without merging distinct FAA proceedings."""
    documents = documents or []
    candidates = _split_faa_candidates(candidates, documents)
    docs_by_id = {d["doc_id"]: d for d in documents}

    # Extract docket identifiers from each candidate’s evidence.
    def candidate_dockets(candidate):
        result = set()
        for eid in candidate.evidence_ids:
            d = docs_by_id.get(eid)
            if not d or d.get("source_id") != "SRC_001":
                continue
            text = d.get("text", "")
            if not re.search(r"(?im)^Regulatory Lifecycle Check:\s*VERIFIED\s*$", text):
                continue
            if m := re.search(r"(?im)^FAA Docket:\s*(FAA-\d{4}-\d+)\s*$", text):
                result.add(m.group(1))
        return result

    consolidated: List[Tuple[ThreatAssessment, str]] = []

    for cand in candidates:
        cand_urls = set(cand.source_urls or ([cand.evidence_citation] if cand.evidence_citation else []))
        cand_docs = set(cand.evidence_ids or [])
        cand_comp_low = cand.company_affected.lower()
        cand_prog_low = (cand.affected_program or "").lower()
        cand_norm = _normalize_for_quote_match(f"{cand.confirmed_facts} {cand.threat_description}")
        cand_ntsb = _candidate_ntsb_case_ids(cand, docs_by_id)
        cand_easa = _candidate_easa_ad_bases(cand, docs_by_id)

        for index, (existing, ex_norm) in enumerate(consolidated):
            if not _compatible_event_statuses(cand, existing):
                continue
            cand_dockets = candidate_dockets(cand)
            existing_dockets = candidate_dockets(existing)
            if cand_dockets and existing_dockets and cand_dockets != existing_dockets:
                continue

            ex_easa = _candidate_easa_ad_bases(existing, docs_by_id)
            if cand_easa and ex_easa and cand_easa != ex_easa:
                continue

            same_easa_case = (
                len(cand_easa) == len(ex_easa) == 1
                and cand_easa == ex_easa
                and cand.risk_type == existing.risk_type
                and not cand_dockets and not existing_dockets
            )
            ex_ntsb = _candidate_ntsb_case_ids(existing, docs_by_id)
            same_ntsb_case = (
                len(cand_ntsb) == len(ex_ntsb) == 1
                and cand_ntsb == ex_ntsb
                and cand.risk_type == existing.risk_type
                and not cand_dockets and not existing_dockets
            )

            ex_urls = set(existing.source_urls or ([existing.evidence_citation] if existing.evidence_citation else []))
            ex_docs = set(existing.evidence_ids or [])
            same_source = bool((cand_urls & ex_urls) or (cand_docs & ex_docs))
            desc_sim = SequenceMatcher(None, cand_norm, ex_norm).ratio()

            # Generic event deduplication without aircraft-specific exceptions.
            duplicate_event = same_ntsb_case or same_easa_case or (
                cand_comp_low == existing.company_affected.lower()
                and cand_prog_low == (existing.affected_program or "").lower()
                and cand.risk_type == existing.risk_type
                and (
                    (same_source and desc_sim >= 0.45)
                    or desc_sim >= 0.75
                )
            )

            if duplicate_event:
                merged = existing.model_copy(deep=True)
                merged.evidence_ids = list(dict.fromkeys(existing.evidence_ids + cand.evidence_ids))
                merged.source_urls = list(dict.fromkeys(existing.source_urls + cand.source_urls))
                merged.kiq_ids = list(dict.fromkeys(existing.kiq_ids + cand.kiq_ids))
                merged.threat_score = max(existing.threat_score, cand.threat_score)
                try:
                    # Re-run the shared ThreatAssessment validators, including criticality policy.
                    consolidated[index] = (
                        ThreatAssessment.model_validate(
                            merged.model_dump(mode="python"),
                            context={"documents": docs_by_id or None},
                        ),
                        ex_norm,
                    )
                except ValidationError as exc:
                    logger.warning("[CONSOLIDATION] Candidate merge rejected: %s", exc)
                    continue
                break
        else:
            consolidated.append((cand, cand_norm))

    return [item for item, _ in consolidated]

# Normalize available token-usage fields across provider result formats.
def _usage_fields(value):
    if value is None:
        return None

    def read(*names):
        for name in names:
            raw = value.get(name) if isinstance(value, dict) else getattr(value, name, None)
            if raw is not None:
                try:
                    count = int(raw)
                    return count if count >= 0 else None
                except (ValueError, TypeError):
                    continue
        return None

    fields = (read("prompt_tokens", "input_tokens", "prompt_token_count"),
              read("completion_tokens", "output_tokens", "completion_token_count", "candidates_token_count"),
              read("successful_requests", "requests"))
    return fields if any(field is not None for field in fields) else None


def _llm_identity(llm):
    model = str(getattr(llm, "model", None) or getattr(llm, "model_name", None) or "UNKNOWN")
    provider = str(getattr(llm, "provider", None) or
                   (model.split("/", 1)[0] if "/" in model else "UNKNOWN"))
    return model, provider


def _record_llm_call(llm, task_type, attempt, status, usage=None, method="UNKNOWN",
                     error_type=None, model=None, provider=None):
    model_name, provider_name = _llm_identity(llm)
    model = model or model_name
    provider = provider or provider_name
    inputs, outputs, requests = usage or (None, None, None)
    state = "UNKNOWN" if inputs is None or outputs is None else (
        "PROVISIONAL" if method == "CREW_OUTPUT_UNVERIFIED" else "MEASURED"
    )
    entry = {
        "task_type": task_type, "attempt": attempt, "status": status,
        "model": model, "provider": provider, "usage_method": method,
        "usage_status": state, "input_tokens": inputs if inputs is not None else "UNKNOWN",
        "output_tokens": outputs if outputs is not None else "UNKNOWN",
        "provider_requests": requests if requests is not None else "UNKNOWN",
        "error_type": error_type,
    }
    with _AUDIT_LOCK:
        _LLM_CALL_EVENTS.append(entry)
    if state == "UNKNOWN":
        LLM_RUNTIME_STATS["usage_unknown_calls"] = LLM_RUNTIME_STATS.get("usage_unknown_calls", 0) + 1


def get_llm_call_telemetry():
    """Return bounded per-attempt audit data; missing usage is never zero."""
    with _AUDIT_LOCK:
        return list(_LLM_CALL_EVENTS)


def reset_agent_support_telemetry():
    """Start a run without carrying usage or recovery observations from prior runs."""
    with _AUDIT_LOCK:
        _LLM_CALL_EVENTS.clear()
        _RECOVERY_COUNTS.clear()
        _RECOVERY_EVENTS.clear()
        _FALLBACK_COUNTS.clear()
        _CREW_OUTPUT_LAST_USAGE.clear()


def _llm_usage_snapshot(llm):
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
        if result is None or isinstance(result, str) and not result.strip():
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


def call_external_llm_tracked(request: Callable[[], Any], *, task_type: str,
                              model: str, provider: str, attempt: int = 1):
    """Record direct SDK calls with provider-reported usage when available."""
    LLM_RUNTIME_STATS["api_calls"] = LLM_RUNTIME_STATS.get("api_calls", 0) + 1
    try:
        response = request()
        if response is None or isinstance(response, str) and not response.strip():
            raise _EmptyLLMResponse("Provider returned no content")
    except Exception as exc:
        _record_llm_call(None, task_type, attempt, "FAILED", error_type=_classify_failure(exc),
                         model=model, provider=provider)
        raise
    usage = _usage_fields(getattr(response, "usage_metadata", None) or
                          getattr(response, "usage", None))
    actual_model = str(getattr(response, "model_version", None) or model)
    _record_llm_call(None, task_type, attempt, "SUCCESS", usage,
                     "DIRECT_RESPONSE" if usage else "UNKNOWN", model=actual_model, provider=provider)
    return response

# Read token usage recorded by a CrewAI execution object.
def _crew_llm_usage_snapshot(crew):
    result = {}
    agents = list(getattr(crew, "agents", []) or [])
    if (manager := getattr(crew, "manager_agent", None)) is not None:
        agents.append(manager)

    for agent in agents:
        if (llm := getattr(agent, "llm", None)) is None or id(llm) in result:
            continue
        if (fields := _llm_usage_snapshot(llm)) is not None:
            result[id(llm)] = fields
    return result

# Calculate incremental token usage attributable to a crew execution.
# Reconcile provider counters so stage-specific usage is not counted twice.
def _crew_token_delta(crew, before, result, phase_label, attempt=1):
    after = _crew_llm_usage_snapshot(crew)
    llms = [getattr(agent, "llm", None) for agent in getattr(crew, "agents", []) or []]
    llm = next((item for item in llms if item is not None), None)
    if before and before.keys() == after.keys() and all(
        before[k][i] is not None and after[k][i] is not None for k in before for i in (0, 1)
    ):
        p_tok = sum(max(0, after[k][0] - before[k][0]) for k in before)
        c_tok = sum(max(0, after[k][1] - before[k][1]) for k in before)
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

    if (previous and all(x is not None for x in (*usage, *previous))
            and requests > previous[2] > 0 and p_tok >= previous[0] and c_tok >= previous[1]):
        p_tok -= previous[0]
        c_tok -= previous[1]
        method = "CREW_CUMULATIVE_DELTA"
    else:
        method = "CREW_OUTPUT_UNVERIFIED"
        logger.warning("[TOKEN AUDIT] %s token usage may be cumulative; verify against provider usage records.", phase_label)

    _record_llm_call(llm, phase_label, attempt, "SUCCESS", (p_tok, c_tok, requests), method)
    logger.info("[TOKEN AUDIT] %s method=%s input=%s output=%s", phase_label, method, p_tok, c_tok)
    return p_tok or 0, c_tok or 0

# Read shared LLM usage counters without double-counting provider instances.
def get_shared_llm_usage_snapshot():
    """Read lifetime usage once per shared CrewAI LLM instance, keyed by model ID."""
    from agents import fast_llm, reasoning_llm
    result = {}
    seen_ids = set()
    for llm in (fast_llm, reasoning_llm):
        if llm is None or id(llm) in seen_ids:
            continue
        seen_ids.add(id(llm))
        if (data := _llm_usage_snapshot(llm)) and all(value is not None for value in data):
            model_name, _ = _llm_identity(llm)
            key = model_name if model_name and model_name != "UNKNOWN" else f"UNVERIFIED_LLM_{id(llm)}"
            if key in result:
                prev = result[key]
                result[key] = tuple(p + c for p, c in zip(prev, data))
            else:
                result[key] = data
    return result

# Run CrewAI with bounded recovery from model/context failures.
# Return an explicit failure if the bounded recovery path cannot produce usable output.
# Recovery is bounded to avoid untracked model retries or silently fabricated results.
def _kickoff_crew_with_smart_recovery(
    crew: Crew, phase_label: str, shrink_callback: Optional[Callable[[], None]] = None
) -> Tuple[Any, int, int]:
    # Run a bounded retry only for recognized model failures and retain telemetry.
    """Execute Crew using the configured LLM only with smart single retry."""
    max_attempts = 1 if phase_label.startswith("BATCH_") else 2

    for attempt in range(1, max_attempts + 1):
        LLM_RUNTIME_STATS["api_calls"] += 1
        try:
            usage_before = _crew_llm_usage_snapshot(crew)
            res = crew.kickoff()
            if res is None or isinstance(res, str) and not res.strip():
                raise _EmptyLLMResponse("Crew returned no content")
            p_tok, c_tok = _crew_token_delta(crew, usage_before, res, phase_label, attempt)
            return res, p_tok, c_tok
        except Exception as err:
            err_type = classify_llm_error(err)
            failure_code = _classify_failure(err, err_type)
            llm = next((getattr(agent, "llm", None) for agent in getattr(crew, "agents", []) or []
                        if getattr(agent, "llm", None) is not None), None)
            _record_llm_call(llm, phase_label, attempt, "FAILED", error_type=failure_code)
            logger.warning("[LLM ERROR - %s] Attempt %d/%d, type=%s (provider=%s): %s",
                           phase_label, attempt, max_attempts, failure_code, err_type, str(err)[:200])

            if failure_code == "RATE_LIMIT":
                logger.error(f"[LLM] Rate limit reached during {phase_label}. Model switching is disabled.")
                raise
            if attempt >= max_attempts:
                logger.error(f"[LLM] {phase_label} failed after {max_attempts} attempts.")
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
