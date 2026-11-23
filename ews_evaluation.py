# =============================================================================
# aviation_ci_app | Research evaluation and reference-case matching
#
# Responsibility: Compare extracted intelligence against manually specified
#   reference cases and calculate experimental quality metrics.
# Design boundary: Reference matching and evidence provenance are assessed
#   separately from the model's self-reported confidence.
# =============================================================================

"""Evaluation metrics and comparisons against reference intelligence cases."""

from collections import defaultdict
from types import SimpleNamespace
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from ews_agent_support import generate_keyword_baseline_report
from ews_state import Any, DB_LOCK, Dict, List, SQLITE_DB, Tuple, app, json, logger, re, sqlite3, time
from ews_validation import (
    HYPOTHETICAL_IN_FACTS_REGEX,
    _detect_specific_variants,
    _normalize_for_quote_match,
)

# Controlled annotation-origin vocabularies (preserved verbatim).
_NON_INDEPENDENT_MARKERS = (
    "SEEDED", "SYNTHETIC", "ILLUSTRATIVE", "HEURISTIC", "MODEL_GENERATED",
    "LLM", "AUTOMATED", "AI_GENERATED", "KEYWORD_ESTIMATE",
)
_INDEPENDENT_ORIGINS = {
    "INDEPENDENT_HUMAN", "HUMAN_INDEPENDENT", "MANUAL_INDEPENDENT", "EXPERT_INDEPENDENT",
}
_ENTITY_STOPWORDS = {"the", "company", "holdings"}


def _pct(num: float, den: float) -> Optional[float]:
    """Compute a 1-decimal percentage or None when the denominator is zero."""
    return round(100 * num / den, 1) if den else None


def _f1_pct(precision: Optional[float], recall: Optional[float], *, zero_as_zero: bool = False) -> Optional[float]:
    """Compute harmonic mean F1 from percentage precision and recall."""
    if precision is None or recall is None:
        return None
    if precision + recall > 0:
        return round(2 * (precision * recall) / (precision + recall), 1)
    return 0.0 if zero_as_zero else None


def _scope_refs_for_text(relevant_refs: List[Dict[str, Any]], query_text_low: str, fallback: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter relevant reference cases whose kit_topic shares a token with the query text."""
    return [
        rc for rc in relevant_refs
        if any(tok in query_text_low for tok in re.findall(r"\b[a-z0-9]{3,}\b", (rc.get("kit_topic") or "").lower()))
    ] or fallback


def _match_event_to_reference_1to1(
    system_events: List[Dict[str, Any]], relevant_refs: List[Dict[str, Any]],
) -> Tuple[int, List[float], int, int]:
    """Match each detected event to at most one reference case.

    Require matching entities, aircraft programs, issue-specific terms, and evidence context.
    Return the true-positive count, scoring errors, SCM matches, and grounded matches.
    """
    used_ref_ids: set[str] = set()
    tp = scm_correct = ref_grounded = 0
    score_diffs: List[float] = []

    for ev in system_events:
        ev_url = (ev.get("canonical_url") or ev.get("evidence_citation") or "").strip()
        ev_comp_low = (ev.get("company_affected") or "").lower()
        ev_text_low = _normalize_for_quote_match(
            f"{ev.get('company_affected', '')} {ev.get('threat_description', '')} "
            f"{ev.get('confirmed_facts', '')} {ev.get('fact_check_quote', '')}"
        )
        best_ref, best_score = None, 0.0

        for rc in relevant_refs:
            if rc["case_id"] in used_ref_ids:
                continue
            rc_url = (rc.get("source_url") or "").strip()
            rc_comp_low = (rc.get("company_affected") or "").lower()
            exact_url_hit = bool(rc_url and rc_url == ev_url)
            comp_tokens = [t for t in re.findall(r"\b[a-z0-9]{3,}\b", rc_comp_low) if t not in _ENTITY_STOPWORDS]
            if not (comp_tokens and any(t in ev_comp_low or t in ev_text_low for t in comp_tokens)) and not exact_url_hit:
                continue

            rc_prog = (rc.get("expected_program") or "").upper()
            if rc_prog not in {"", "UNSPECIFIED"}:
                expected = _detect_specific_variants(rc_prog)
                observed = _detect_specific_variants(ev.get("affected_program", ""))
                if (expected and expected.isdisjoint(observed)) or (not expected and rc_prog.lower() not in (ev.get("affected_program") or "").lower()):
                    continue

            rc_kw_list = [k.strip().lower() for k in (rc.get("problem_keywords") or "").split(",") if k.strip()]
            kw_hits = sum(1 for kw in rc_kw_list if _normalize_for_quote_match(kw) in ev_text_low)
            kw_ratio = (kw_hits / len(rc_kw_list)) if rc_kw_list else 0.0
            strength = (0.6 if exact_url_hit else 0.0) + (0.4 * kw_ratio)
            if ((exact_url_hit and kw_hits >= 1) or kw_ratio >= 0.40) and strength > best_score:
                best_score, best_ref = strength, rc

        if best_ref is not None:
            used_ref_ids.add(best_ref["case_id"])
            tp += 1
            score_diffs.append(abs(int(best_ref.get("reference_threat_score") or 5) - int(ev.get("threat_score") or 5)))
            scm_correct += int((ev.get("scm_tier") or "") == (best_ref.get("expected_scm_tier") or ""))
            ref_quote_norm = _normalize_for_quote_match(best_ref.get("supporting_quote") or "")
            ref_grounded += int((bool(ref_quote_norm) and ref_quote_norm[:30] in ev_text_low) or best_score >= 0.55)

    return tp, score_diffs, scm_correct, ref_grounded


def _safe_evidence_ids(raw):
    """Parse an evidence_ids field from a list or JSON string into a list."""
    if isinstance(raw, list):
        return raw
    try:
        value = json.loads(raw or "[]")
        return value if isinstance(value, list) else []
    except (TypeError, ValueError):
        return []


def _reference_label(reference: Dict[str, Any]) -> Optional[bool | str]:
    """Require an explicit label; missing values never mean IRRELEVANT."""
    raw = reference.get("is_relevant")
    if raw is None:
        raw = reference.get("relevance_label")
    label = str(raw).strip().upper()
    if raw is True or label in {"1", "RELEVANT", "POSITIVE"}:
        return True
    if raw is False or label in {"0", "IRRELEVANT", "NEGATIVE"}:
        return False
    return "AMBIGUOUS" if label in {"AMBIGUOUS", "UNCERTAIN", "UNRESOLVED", "MIXED"} else None


def _independently_annotated(reference: Dict[str, Any]) -> bool:
    """Seeded, inferred, and unproven labels are not independent ground truth."""
    markers = " ".join(str(reference.get(k) or "") for k in ("reference_type", "dataset_type", "label_origin", "annotation_method", "annotation_source")).upper()
    if any(term in markers for term in _NON_INDEPENDENT_MARKERS):
        return False
    explicit = any(
        reference.get(k) is True or str(reference.get(k)).lower() in {"1", "true", "yes"}
        for k in ("is_independently_annotated", "independently_annotated", "reference_independent")
    )
    origin = str(reference.get("annotation_source") or reference.get("label_origin") or "").upper()
    return explicit or origin in _INDEPENDENT_ORIGINS


def _document_identity(row: Dict[str, Any], reference: bool = False) -> Optional[str]:
    """Use stable exact identifiers, never fuzzy headline similarity."""
    if url := str(row.get("source_url" if reference else "url") or "").strip():
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        return "url:" + urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/") or "/", parts.query, ""))
    if global_id := row.get("global_document_id"):
        return f"global:{str(global_id).strip()}"
    return f"run:{row['run_id']}:{row['doc_id']}" if (row.get("run_id") and row.get("doc_id")) else None


def _filter_reference_metrics(
    filter_logs: List[Dict[str, Any]], references: List[Dict[str, Any]], *, independent_only: bool,
) -> Dict[str, Any]:
    """Compute a confusion matrix over unique documents with unambiguous, explicit labels only."""
    labels = defaultdict(set)
    for ref in references:
        if (ident := _document_identity(ref, reference=True)) and (lbl := _reference_label(ref)) is not None:
            if not independent_only or _independently_annotated(ref):
                labels[ident].add(lbl)

    observations, unnamed = defaultdict(set), 0
    for rec in filter_logs:
        if not (ident := _document_identity(rec)):
            unnamed += 1
            continue
        dec = rec.get("is_accepted")
        observations[ident].add(dec if dec in (0, 1, True, False) else "UNKNOWN")

    tp = fp = tn = fn = unannotated = ambiguous = positive = negative = 0
    for ident, decisions in observations.items():
        ref_labels = labels.get(ident, set())
        if "AMBIGUOUS" in ref_labels or len(ref_labels) > 1 or len(decisions) > 1:
            ambiguous += 1
            continue
        if not ref_labels or "UNKNOWN" in decisions:
            unannotated += 1
            continue
        actual, accepted = bool(next(iter(ref_labels))), bool(next(iter(decisions)))
        positive += actual
        negative += not actual
        tp += actual and accepted
        fp += (not actual) and accepted
        tn += (not actual) and (not accepted)
        fn += actual and (not accepted)

    unannotated += unnamed
    precision, recall = _pct(tp, tp + fp), _pct(tp, tp + fn)
    f1 = _f1_pct(precision, recall, zero_as_zero=True)
    evaluated, total_obs = tp + fp + tn + fn, len(observations) + unnamed
    return {
        "status": "MEASURED" if evaluated else ("INSUFFICIENT_INDEPENDENT_LABELS" if independent_only else "NO_EXPLICIT_REFERENCE_LABELS"),
        "evaluation_scope": "INDEPENDENT_HUMAN_ANNOTATIONS" if independent_only else "EXPERIMENTAL_REFERENCE_LABELS_ONLY",
        "sampling_scope": "ANNOTATED_DOCUMENTS_PRESENT_IN_FILTER_LOG",
        "annotated_document_count": evaluated,
        "unannotated_document_count": unannotated,
        "ambiguous_document_count": ambiguous,
        "positive_case_count": positive,
        "negative_case_count": negative,
        "total_documents_evaluated": evaluated,
        "total_unique_documents_observed": total_obs,
        "excluded_from_confusion_matrix_count": unannotated + ambiguous,
        "document_count_consistent": evaluated + unannotated + ambiguous == total_obs,
        "true_positives_kept": tp, "false_positives_kept": fp,
        "correctly_rejected_irrelevant_tn": tn, "mistakenly_rejected_relevant_fn": fn,
        "filter_precision_pct": precision, "filter_recall_pct": recall, "filter_f1_pct": f1,
        "reference_matching_method": "EXACT_URL_OR_GLOBAL_DOCUMENT_ID",
    }


def _compute_baseline_comparison(
    latest_run: Dict[str, Any], stored_docs: List[Dict[str, Any]],
    events: List[Dict[str, Any]], relevant_refs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compare the non-LLM keyword baseline against multi-agent output on the latest run's dataset."""
    latest_run_id = latest_run["run_id"]
    t0, baseline_error = time.time(), None
    try:
        base_report = generate_keyword_baseline_report(
            latest_run.get("query", "Aerospace"), stored_docs, latest_run.get("analysis_scope", "7d"), latest_run_id,
        )
    except Exception as exc:
        logger.exception("[EVALUATION] Keyword baseline failed: %s", exc)
        baseline_error, base_report = type(exc).__name__, SimpleNamespace(threats=[])
    base_time = round(time.time() - t0, 4)
    base_events = [t.model_dump() for t in base_report.threats]

    scoped_refs = _scope_refs_for_text(relevant_refs, (latest_run.get("query") or "").lower(), relevant_refs[:10])
    b_tp, _, b_scm_corr, b_grounded = _match_event_to_reference_1to1(base_events, scoped_refs)
    b_prec, b_rec = _pct(b_tp, len(base_events)), _pct(b_tp, len(scoped_refs))

    latest_events = [e for e in events if e.get("run_id") == latest_run_id]
    l_tp, _, l_scm, l_grounded = _match_event_to_reference_1to1(latest_events, scoped_refs)
    l_prec, l_rec = _pct(l_tp, len(latest_events)), _pct(l_tp, len(scoped_refs))

    return {
        "status": "N/A (Keyword baseline failed)" if baseline_error else "EXPERIMENTAL_REFERENCE_MATCHING",
        "measurement_note": "Event matching is heuristic; reference cases may be seeded. Not independent Precision/Recall/F1.",
        "dataset_run_id": latest_run_id,
        "input_documents_count": len(stored_docs),
        "Keyword_Baseline": {
            "events_generated": len(base_events), "precision_pct": None, "recall_pct": None, "f1_score_pct": None,
            "processing_time_sec": base_time, "tokens_used": 0, "cost_usd": 0.0,
        },
        "aviation_ci_app_MultiAgent": {
            "events_generated": len(latest_events), "precision_pct": None, "recall_pct": None, "f1_score_pct": None,
            "processing_time_sec": latest_run.get("total_duration"),
            "tokens_used": int(latest_run.get("tokens_input") or 0) + int(latest_run.get("tokens_output") or 0),
            "cost_usd": latest_run.get("estimated_cost"),
        },
        "internal_experimental_reference_matching": {
            "keyword_baseline": {
                "estimated_precision_pct": b_prec, "estimated_recall_pct": b_rec,
                "estimated_f1_pct": _f1_pct(b_prec, b_rec),
                "estimated_scm_accuracy_pct": _pct(b_scm_corr, len(base_events)),
                "estimated_grounding_rate_pct": _pct(b_grounded, len(base_events)),
            },
            "multi_agent": {
                "estimated_precision_pct": l_prec, "estimated_recall_pct": l_rec,
                "estimated_f1_pct": _f1_pct(l_prec, l_rec),
                "estimated_scm_accuracy_pct": _pct(l_scm, l_tp),
                "estimated_grounding_rate_pct": _pct(l_grounded, len(latest_events)),
            },
        },
    }


@app.get("/api/evaluation")
def compute_evaluation_metrics():
    """Report independent document-filter metrics and separate internal diagnostics."""
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        fetch = lambda sql, params=(): [dict(r) for r in conn.execute(sql, params).fetchall()]
        runs = fetch("SELECT * FROM analytical_runs WHERE status = 'completed' ORDER BY completed_at DESC")
        events = fetch("SELECT * FROM events WHERE event_status != 'DISMISSED'")
        ref_cases = fetch("SELECT * FROM reference_dataset")
        filter_logs = fetch("SELECT * FROM document_filter_log")
        dismissed_feedback = fetch("SELECT * FROM analyst_feedback WHERE feedback_type = 'DISMISS'")
        stored_docs = fetch("SELECT * FROM source_documents WHERE run_id = ?", (runs[0]["run_id"],)) if runs else []

    total_events = len(events)
    relevant_refs = [c for c in ref_cases if _reference_label(c) is True]
    irrelevant_refs = [c for c in ref_cases if _reference_label(c) is False]
    indep_refs = [c for c in ref_cases if _independently_annotated(c)]

    filter_eval = _filter_reference_metrics(filter_logs, ref_cases, independent_only=True)
    internal_filter_eval = _filter_reference_metrics(filter_logs, ref_cases, independent_only=False)
    filter_eval["total_filter_log_records"] = len(filter_logs)

    trace_rate = qa_rate = sep_rate = scm_acc = None
    if total_events:
        traceable = sum(
            1 for e in events
            if e.get("canonical_url") and "unverified-source.local" not in (e.get("canonical_url") or "")
            and _safe_evidence_ids(e.get("evidence_ids_json")) and len((e.get("fact_check_quote") or "").strip()) >= 12
        )
        qa_supported = sum(1 for e in events if e.get("validation_status") == "SUPPORTED")
        clean_sep = sum(
            1 for e in events
            if e.get("confirmed_facts") and not HYPOTHETICAL_IN_FACTS_REGEX.search(e.get("confirmed_facts") or "")
            and e.get("hypothetical_scenario")
        )
        trace_rate, qa_rate, sep_rate = _pct(traceable, total_events), _pct(qa_supported, total_events), _pct(clean_sep, total_events)

    # Event similarity matching is exploratory, not a human-verified event label.
    precision = recall = f1 = mae = ref_grounding_rate = None
    if total_events and relevant_refs:
        scoped_refs = _scope_refs_for_text(relevant_refs, " ".join((r.get("query") or "").lower() for r in runs), relevant_refs)
        tp, score_diffs, scm_corr, ref_grounded = _match_event_to_reference_1to1(events, scoped_refs)
        precision, recall = _pct(tp, total_events), _pct(tp, len(scoped_refs))
        f1 = _f1_pct(precision, recall)
        mae = round(sum(score_diffs) / len(score_diffs), 2) if score_diffs else None
        scm_acc = _pct(scm_corr, tp)
        ref_grounding_rate = _pct(ref_grounded, total_events)

    total_val_errors = sum(int(r.get("validation_errors") or 0) for r in runs)
    dismissed_cnt = len(dismissed_feedback)
    ungrounded_rate = _pct(dismissed_cnt, total_events + dismissed_cnt) if dismissed_cnt else None
    avg_time = round(sum(float(r.get("total_duration") or 0) for r in runs) / len(runs), 2) if runs else None
    avg_cost = round(sum(float(r.get("estimated_cost") or 0) for r in runs) / len(runs), 5) if runs else None

    baseline_comparison = (
        _compute_baseline_comparison(runs[0], stored_docs, events, relevant_refs)
        if runs and stored_docs else {"status": "N/A (No stored run dataset available yet)"}
    )
    na_data = "N/A (Insufficient Data)"
    return {
        "data_sufficiency_status": "ANNOTATED_SAMPLE_AVAILABLE" if filter_eval["annotated_document_count"] else "INSUFFICIENT_INDEPENDENT_LABELS",
        "measurement_note": (
            "Document-level Precision/Recall/F1 use only explicitly independent human annotations "
            "matched by exact document identity. Unlabeled, ambiguous, and seeded-only cases "
            "are excluded. Recall applies only to the annotated subset present in the filter log, "
            "not to all potentially relevant documents. Event matching and baseline comparison "
            "are exploratory diagnostics, never independent ground truth."
        ),
        "total_runs_evaluated": len(runs),
        "total_unique_events": total_events,
        "reference_dataset_count": len(ref_cases),
        "reference_positive_cases": len(relevant_refs),
        "reference_negative_cases": len(irrelevant_refs),
        "reference_ambiguous_cases": sum(_reference_label(rc) == "AMBIGUOUS" for rc in ref_cases),
        "independent_reference_annotation_counts": {
            "positive": sum(_reference_label(rc) is True for rc in indep_refs),
            "negative": sum(_reference_label(rc) is False for rc in indep_refs),
            "ambiguous": sum(_reference_label(rc) == "AMBIGUOUS" for rc in indep_refs),
        },
        "semantic_filter_evaluation": filter_eval,
        "internal_experimental_filter_evaluation": internal_filter_eval,
        "analytical_output_evaluation": {
            "status": "NOT_INDEPENDENTLY_ANNOTATED",
            "precision_pct": None, "recall_pct": None, "f1_score_pct": None,
            "scm_classification_accuracy_pct": None,
            "citation_traceability_rate_pct": trace_rate if trace_rate is not None else na_data,
            "reference_content_grounding_rate_pct": None,
            "internal_qa_support_rate_pct": qa_rate if qa_rate is not None else na_data,
            "fact_vs_hypothesis_separation_rate_pct": sep_rate if sep_rate is not None else na_data,
            "threat_score_mae": None,
        },
        "internal_experimental_event_matching": {
            "estimated_precision_pct": precision, "estimated_recall_pct": recall,
            "estimated_f1_pct": f1, "estimated_scm_accuracy_pct": scm_acc,
            "estimated_reference_grounding_rate_pct": ref_grounding_rate,
            "estimated_threat_score_mae": mae,
        },
        "error_and_hallucination_breakdown": {
            "automated_validation_errors_count": total_val_errors,
            "manually_verified_ungrounded_claims_count": dismissed_cnt,
            "verified_ungrounded_claim_rate_pct": ungrounded_rate if ungrounded_rate is not None else "N/A (Requires Manual Analyst Verification)",
            "note": "Automated validation errors reflect harness rejections (e.g. snippet/quote mismatches), not necessarily LLM hallucinations.",
        },
        "baseline_comparison": baseline_comparison,
        "grounding_rate_pct": qa_rate,
        "grounding_metric_scope": "INTERNAL_QA_VALIDATION_STATUS",
        "hallucination_rate_pct": ungrounded_rate if ungrounded_rate is not None else f"{total_val_errors} auto-val errors (N/A manual)",
        "avg_processing_time_sec": avg_time if avg_time is not None else "N/A",
        "avg_cost_per_run_usd": avg_cost if avg_cost is not None else 0.0,
        "precision_pct": filter_eval["filter_precision_pct"],
        "recall_pct": filter_eval["filter_recall_pct"],
        "f1_score_pct": filter_eval["filter_f1_pct"],
        "precision_metric_scope": "INDEPENDENTLY_ANNOTATED_DOCUMENT_FILTER_LOG",
        "threat_score_mae": None,
    }