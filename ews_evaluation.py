# =============================================================================
# aviation_ci_app | Research evaluation and reference-case matching
#
# Responsibility: Compare extracted intelligence against manually specified reference cases and calculate
#   experimental quality metrics.
# Design boundary: Reference matching and evidence provenance are assessed separately from the model’s
#   self-reported confidence.
# =============================================================================

"""Evaluation metrics and comparisons against reference intelligence cases."""

from collections import defaultdict
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from ews_agent_support import generate_keyword_baseline_report
from ews_state import Any, DB_LOCK, Dict, List, SQLITE_DB, Tuple, app, json, re, sqlite3, time, logger
from ews_validation import (
    HYPOTHETICAL_IN_FACTS_REGEX,
    _detect_specific_variants,
    _normalize_for_quote_match,
)


# Match predictions to reference cases one-to-one using entities, program, and issue evidence.
# Each reference case may be matched only once to prevent inflated true-positive counts.
def _match_event_to_reference_1to1(
        system_events: List[Dict[str, Any]], relevant_refs: List[Dict[str, Any]]
) -> Tuple[int, List[float], int, int]:
    # Reserve reference matches one-to-one to prevent inflated detection scores.
    """Match each detected event to at most one reference case.

    Require matching entities, aircraft programs, issue-specific terms, and evidence context.
    Return the true-positive count, scoring errors, SCM matches, and grounded matches.
    """
    used_ref_ids: set[str] = set()
    tp = 0
    score_diffs: List[float] = []
    scm_correct = 0
    ref_grounded = 0

    for ev in system_events:
        ev_url = (ev.get("canonical_url") or ev.get("evidence_citation") or "").strip()
        ev_comp_low = (ev.get("company_affected") or "").lower()
        ev_text_low = _normalize_for_quote_match(
            f"{ev.get('company_affected', '')} {ev.get('threat_description', '')} "
            f"{ev.get('confirmed_facts', '')} {ev.get('fact_check_quote', '')}"
        )
        ev_variants = _detect_specific_variants(ev_text_low)

        best_ref = None
        best_score = 0.0

        for rc in relevant_refs:
            cid = rc["case_id"]
            if cid in used_ref_ids:
                continue

            rc_url = (rc.get("source_url") or "").strip()
            rc_comp_low = (rc.get("company_affected") or "").lower()
            rc_prog = (rc.get("expected_program") or "").upper()
            rc_kw_list = [k.strip().lower() for k in (rc.get("problem_keywords") or "").split(",") if k.strip()]

            comp_tokens = [t for t in re.findall(r"\b[a-z0-9]{3,}\b", rc_comp_low) if
                           t not in {"the", "company", "holdings"}]
            entity_match = bool(comp_tokens and any(t in ev_comp_low or t in ev_text_low for t in comp_tokens))
            if not entity_match and not (rc_url and rc_url == ev_url):
                continue

            if rc_prog not in {"", "UNSPECIFIED"}:
                expected = _detect_specific_variants(rc_prog)
                observed = _detect_specific_variants(ev.get('affected_program', ''))

                if expected and expected.isdisjoint(observed):
                    continue

                if not expected and rc_prog.lower() not in (
                        ev.get("affected_program") or ""
                ).lower():
                    continue

            kw_hits = sum(1 for kw in rc_kw_list if _normalize_for_quote_match(kw) in ev_text_low)
            kw_ratio = (kw_hits / len(rc_kw_list)) if rc_kw_list else 0.0
            exact_url_hit = bool(rc_url and rc_url == ev_url)

            match_strength = (0.6 if exact_url_hit else 0.0) + (0.4 * kw_ratio)
            if (exact_url_hit and kw_hits >= 1) or kw_ratio >= 0.40:
                if match_strength > best_score:
                    best_score = match_strength
                    best_ref = rc

        if best_ref is not None:
            used_ref_ids.add(best_ref["case_id"])
            tp += 1
            ref_score = int(best_ref.get("reference_threat_score") or 5)
            ev_score = int(ev.get("threat_score") or 5)
            score_diffs.append(abs(ref_score - ev_score))

            if (ev.get("scm_tier") or "") == (best_ref.get("expected_scm_tier") or ""):
                scm_correct += 1

            ref_quote_norm = _normalize_for_quote_match(best_ref.get("supporting_quote") or "")
            if (ref_quote_norm and ref_quote_norm[:30] in ev_text_low) or best_score >= 0.55:
                ref_grounded += 1

    return tp, score_diffs, scm_correct, ref_grounded


# Normalize source identifiers before evaluation and match scoring.
def _safe_evidence_ids(raw):
    if isinstance(raw, list):
        return raw

    try:
        value = json.loads(raw or "[]")

        if isinstance(value, list):
            return value

        return []

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
    if label in {"AMBIGUOUS", "UNCERTAIN", "UNRESOLVED", "MIXED"}:
        return "AMBIGUOUS"
    return None


def _independently_annotated(reference: Dict[str, Any]) -> bool:
    """Seeded, inferred and unproven labels are not independent ground truth."""
    markers = " ".join(str(reference.get(key) or "") for key in (
        "reference_type", "dataset_type", "label_origin", "annotation_method", "annotation_source"
    )).upper()
    if any(term in markers for term in (
            "SEEDED", "SYNTHETIC", "ILLUSTRATIVE", "HEURISTIC", "MODEL_GENERATED",
            "LLM", "AUTOMATED", "AI_GENERATED", "KEYWORD_ESTIMATE",
    )):
        return False
    explicitly_independent = any(
        reference.get(key) is True or str(reference.get(key)).lower() in {"1", "true", "yes"}
        for key in ("is_independently_annotated", "independently_annotated", "reference_independent")
    )
    origin = str(reference.get("annotation_source") or reference.get("label_origin") or "").upper()
    return explicitly_independent or origin in {
        "INDEPENDENT_HUMAN", "HUMAN_INDEPENDENT", "MANUAL_INDEPENDENT", "EXPERT_INDEPENDENT"
    }


def _document_identity(row: Dict[str, Any], reference: bool = False) -> Optional[str]:
    """Use stable exact identifiers, never fuzzy headline similarity."""
    url = str(row.get("source_url" if reference else "url") or "").strip()
    if url:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        path = parts.path.rstrip("/") or "/"
        return "url:" + urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))
    global_id = row.get("global_document_id")
    if global_id:
        return f"global:{str(global_id).strip()}"
    if row.get("run_id") and row.get("doc_id"):
        return f"run:{row['run_id']}:{row['doc_id']}"
    return None


def _filter_reference_metrics(
        filter_logs: List[Dict[str, Any]], references: List[Dict[str, Any]],
        *, independent_only: bool,
) -> Dict[str, Any]:
    """Confusion matrix over unique documents with unambiguous, explicit labels only."""
    labels = defaultdict(set)
    for ref in references:
        identity = _document_identity(ref, reference=True)
        label = _reference_label(ref)
        if not identity:
            continue
        if label is not None and (not independent_only or _independently_annotated(ref)):
            labels[identity].add(label)

    observations = defaultdict(set)
    unnamed_documents = 0
    for record in filter_logs:
        identity = _document_identity(record)
        if not identity:
            unnamed_documents += 1
            continue
        decision = record.get("is_accepted")
        observations[identity].add(decision if decision in (0, 1, True, False) else "UNKNOWN")

    tp = fp = tn = fn = unannotated = ambiguous = 0
    positive = negative = 0
    for identity, decisions in observations.items():
        reference_labels = labels.get(identity, set())
        if "AMBIGUOUS" in reference_labels or len(reference_labels) > 1 or len(decisions) > 1:
            ambiguous += 1
            continue
        if not reference_labels or "UNKNOWN" in decisions:
            unannotated += 1
            continue
        actual = next(iter(reference_labels))
        accepted = bool(next(iter(decisions)))
        positive += bool(actual)
        negative += not actual
        tp += bool(actual and accepted)
        fp += bool(not actual and accepted)
        tn += bool(not actual and not accepted)
        fn += bool(actual and not accepted)

    unannotated += unnamed_documents
    precision = round(100 * tp / (tp + fp), 1) if tp + fp else None
    recall = round(100 * tp / (tp + fn), 1) if tp + fn else None
    f1 = (
        round(2 * precision * recall / (precision + recall), 1)
        if precision is not None and recall is not None and precision + recall
        else 0.0 if precision is not None and recall is not None else None
    )
    evaluated = tp + fp + tn + fn
    return {
        "status": "MEASURED" if evaluated else "INSUFFICIENT_INDEPENDENT_LABELS" if independent_only else "NO_EXPLICIT_REFERENCE_LABELS",
        "evaluation_scope": "INDEPENDENT_HUMAN_ANNOTATIONS" if independent_only else "EXPERIMENTAL_REFERENCE_LABELS_ONLY",
        "sampling_scope": "ANNOTATED_DOCUMENTS_PRESENT_IN_FILTER_LOG",
        "annotated_document_count": evaluated,
        "unannotated_document_count": unannotated,
        "ambiguous_document_count": ambiguous,
        "positive_case_count": positive,
        "negative_case_count": negative,
        "total_documents_evaluated": evaluated,
        "total_unique_documents_observed": len(observations) + unnamed_documents,
        "excluded_from_confusion_matrix_count": unannotated + ambiguous,
        "document_count_consistent": evaluated + unannotated + ambiguous == len(observations) + unnamed_documents,
        "true_positives_kept": tp, "false_positives_kept": fp,
        "correctly_rejected_irrelevant_tn": tn, "mistakenly_rejected_relevant_fn": fn,
        "filter_precision_pct": precision, "filter_recall_pct": recall, "filter_f1_pct": f1,
        "reference_matching_method": "EXACT_URL_OR_GLOBAL_DOCUMENT_ID",
    }


@app.get("/api/evaluation")
def compute_evaluation_metrics():
    """Report independent document-filter metrics and separate internal diagnostics."""
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM analytical_runs WHERE status = 'completed' ORDER BY completed_at DESC")
        runs = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM events WHERE event_status != 'DISMISSED'")
        events = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM reference_dataset")
        ref_cases = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM document_filter_log")
        filter_logs = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT * FROM analyst_feedback WHERE feedback_type = 'DISMISS'")
        dismissed_feedback = [dict(r) for r in cur.fetchall()]

    total_events = len(events)
    relevant_refs = [c for c in ref_cases if _reference_label(c) is True]
    irrelevant_refs = [c for c in ref_cases if _reference_label(c) is False]
    independently_labeled_refs = [c for c in ref_cases if _independently_annotated(c)]
    filter_eval = _filter_reference_metrics(filter_logs, ref_cases, independent_only=True)
    internal_filter_eval = _filter_reference_metrics(filter_logs, ref_cases, independent_only=False)
    filter_eval["total_filter_log_records"] = len(filter_logs)

    if total_events == 0:
        citation_traceability_rate = None
        internal_qa_support_rate = None
        fact_hypothesis_sep_rate = None
        scm_accuracy_pct = None
    else:
        traceable_count = sum(
            1
            for e in events
            if e.get("canonical_url")
            and "unverified-source.local" not in (e.get("canonical_url") or "")
            and _safe_evidence_ids(
                e.get("evidence_ids_json")
            )
            and len((e.get("fact_check_quote") or "").strip()) >= 12
        )
        citation_traceability_rate = round((traceable_count / total_events) * 100, 1)

        qa_supported_count = sum((1 for e in events if e.get('validation_status') == 'SUPPORTED'))
        internal_qa_support_rate = round((qa_supported_count / total_events) * 100, 1)

        clean_fact_sep_count = sum(
            1
            for e in events
            if e.get("confirmed_facts")
            and not HYPOTHETICAL_IN_FACTS_REGEX.search(e.get("confirmed_facts") or "")
            and e.get("hypothetical_scenario")
        )
        fact_hypothesis_sep_rate = round((clean_fact_sep_count / total_events) * 100, 1)

    # Event similarity matching is exploratory, not a human-verified event label.
    precision, recall, f1, mae, ref_content_grounding_rate = None, None, None, None, None
    if total_events > 0 and relevant_refs:
        run_queries_low = " ".join((r.get("query") or "").lower() for r in runs)
        scoped_refs = [
                          rc for rc in relevant_refs
                          if any(
                tok in run_queries_low for tok in re.findall(r"\b[a-z0-9]{3,}\b", (rc.get("kit_topic") or "").lower()))
                      ] or relevant_refs

        tp, score_diffs, scm_corr, ref_grounded = _match_event_to_reference_1to1(events, scoped_refs)
        precision = round((tp / total_events) * 100, 1)
        recall = round((tp / len(scoped_refs)) * 100, 1) if scoped_refs else None
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1 = round(2 * (precision * recall) / (precision + recall), 1)
        if score_diffs:
            mae = round(sum(score_diffs) / len(score_diffs), 2)
        scm_accuracy_pct = round((scm_corr / max(1, tp)) * 100, 1) if tp > 0 else None
        ref_content_grounding_rate = round((ref_grounded / total_events) * 100, 1)

    total_val_errors = sum(int(r.get("validation_errors") or 0) for r in runs)
    manually_dismissed_count = len(dismissed_feedback)
    verified_ungrounded_rate = (
        round((manually_dismissed_count / (total_events + manually_dismissed_count)) * 100, 1)
        if (total_events + manually_dismissed_count) > 0 and manually_dismissed_count > 0
        else None
    )

    avg_time = round(sum(float(r.get("total_duration") or 0) for r in runs) / len(runs), 2) if runs else None
    avg_cost = round(sum(float(r.get("estimated_cost") or 0) for r in runs) / len(runs), 5) if runs else None
    avg_tokens = (
        round(sum(int(r.get("tokens_input") or 0) + int(r.get("tokens_output") or 0) for r in runs) / len(runs), 0)
        if runs
        else None
    )

    baseline_comparison: Dict[str, Any] = {"status": "N/A (No stored run dataset available yet)"}
    if runs:
        latest_run = runs[0]
        latest_run_id = latest_run["run_id"]
        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM source_documents WHERE run_id = ?", (latest_run_id,))
            stored_docs = [dict(r) for r in cur.fetchall()]

        if stored_docs:
            t0 = time.time()
            baseline_error = None

            try:

                base_report = generate_keyword_baseline_report(
                    latest_run.get("query", "Aerospace"),
                    stored_docs,
                    latest_run.get("analysis_scope", "7d"),
                    latest_run_id,
                )

            except Exception as exc:

                logger.exception('[EVALUATION] Keyword baseline failed: %s', exc)

                baseline_error = type(exc).__name__

                from types import SimpleNamespace

                base_report = SimpleNamespace(threats=[])
            base_time = round(time.time() - t0, 4)
            base_events = [t.model_dump() for t in base_report.threats]

            q_low = (latest_run.get("query") or "").lower()
            scoped_refs_for_latest = [
                                         rc for rc in relevant_refs
                                         if any(
                    tok in q_low for tok in re.findall(r"\b[a-z0-9]{3,}\b", (rc.get("kit_topic") or "").lower()))
                                     ] or relevant_refs[:10]

            b_tp, b_diffs, b_scm_corr, b_grounded = _match_event_to_reference_1to1(base_events, scoped_refs_for_latest)
            b_prec = round((b_tp / len(base_events)) * 100, 1) if base_events else None
            b_rec = round((b_tp / len(scoped_refs_for_latest)) * 100, 1) if scoped_refs_for_latest else None
            b_f1 = round(2 * (b_prec * b_rec) / (b_prec + b_rec), 1) if (
                    b_prec and b_rec and (b_prec + b_rec) > 0) else None
            b_scm_acc = round((b_scm_corr / max(1, len(base_events))) * 100, 1) if base_events else None
            b_ground_rate = round((b_grounded / len(base_events)) * 100, 1) if base_events else None
            latest_events = [event for event in events if event.get("run_id") == latest_run_id]
            latest_tp, _, latest_scm, latest_grounded = _match_event_to_reference_1to1(
                latest_events, scoped_refs_for_latest
            )
            latest_prec = round(100 * latest_tp / len(latest_events), 1) if latest_events else None
            latest_rec = round(100 * latest_tp / len(scoped_refs_for_latest), 1) if scoped_refs_for_latest else None
            latest_f1 = (
                round(2 * latest_prec * latest_rec / (latest_prec + latest_rec), 1)
                if latest_prec is not None and latest_rec is not None and latest_prec + latest_rec else None
            )

            baseline_comparison = {
                "status": (
                    "N/A (Keyword baseline failed)"
                    if baseline_error
                    else "EXPERIMENTAL_REFERENCE_MATCHING"
                ),
                "measurement_note": "Event matching is heuristic; reference cases may be seeded. Not independent Precision/Recall/F1.",
                "dataset_run_id": latest_run_id,
                "input_documents_count": len(stored_docs),
                "Keyword_Baseline": {
                    "events_generated": len(base_events),
                    "precision_pct": None, "recall_pct": None, "f1_score_pct": None,
                    "processing_time_sec": base_time,
                    "tokens_used": 0,
                    "cost_usd": 0.0,
                },
                "aviation_ci_app_MultiAgent": {
                    "events_generated": len(latest_events),
                    "precision_pct": None, "recall_pct": None, "f1_score_pct": None,
                    "processing_time_sec": latest_run.get("total_duration"),
                    "tokens_used": int(latest_run.get("tokens_input") or 0) + int(latest_run.get("tokens_output") or 0),
                    "cost_usd": latest_run.get("estimated_cost"),
                },
                "internal_experimental_reference_matching": {
                    "keyword_baseline": {
                        "estimated_precision_pct": b_prec, "estimated_recall_pct": b_rec,
                        "estimated_f1_pct": b_f1, "estimated_scm_accuracy_pct": b_scm_acc,
                        "estimated_grounding_rate_pct": b_ground_rate,
                    },
                    "multi_agent": {
                        "estimated_precision_pct": latest_prec, "estimated_recall_pct": latest_rec,
                        "estimated_f1_pct": latest_f1,
                        "estimated_scm_accuracy_pct": round(100 * latest_scm / latest_tp, 1) if latest_tp else None,
                        "estimated_grounding_rate_pct": round(100 * latest_grounded / len(latest_events),
                                                              1) if latest_events else None,
                    },
                },
            }

    independent_precision = filter_eval["filter_precision_pct"]
    independent_recall = filter_eval["filter_recall_pct"]
    independent_f1 = filter_eval["filter_f1_pct"]
    return {
        "data_sufficiency_status": (
            "ANNOTATED_SAMPLE_AVAILABLE"
            if filter_eval["annotated_document_count"] else "INSUFFICIENT_INDEPENDENT_LABELS"
        ),
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
            "positive": sum(_reference_label(rc) is True for rc in independently_labeled_refs),
            "negative": sum(_reference_label(rc) is False for rc in independently_labeled_refs),
            "ambiguous": sum(_reference_label(rc) == "AMBIGUOUS" for rc in independently_labeled_refs),
        },
        "semantic_filter_evaluation": filter_eval,
        "internal_experimental_filter_evaluation": internal_filter_eval,
        "analytical_output_evaluation": {
            "status": "NOT_INDEPENDENTLY_ANNOTATED",
            "precision_pct": None, "recall_pct": None, "f1_score_pct": None,
            "scm_classification_accuracy_pct": None,
            "citation_traceability_rate_pct": citation_traceability_rate if citation_traceability_rate is not None else "N/A (Insufficient Data)",
            "reference_content_grounding_rate_pct": None,
            "internal_qa_support_rate_pct": internal_qa_support_rate if internal_qa_support_rate is not None else "N/A (Insufficient Data)",
            "fact_vs_hypothesis_separation_rate_pct": fact_hypothesis_sep_rate if fact_hypothesis_sep_rate is not None else "N/A (Insufficient Data)",
            "threat_score_mae": None,
        },
        "internal_experimental_event_matching": {
            "estimated_precision_pct": precision, "estimated_recall_pct": recall,
            "estimated_f1_pct": f1, "estimated_scm_accuracy_pct": scm_accuracy_pct,
            "estimated_reference_grounding_rate_pct": ref_content_grounding_rate,
            "estimated_threat_score_mae": mae,
        },
        "error_and_hallucination_breakdown": {
            "automated_validation_errors_count": total_val_errors,
            "manually_verified_ungrounded_claims_count": manually_dismissed_count,
            "verified_ungrounded_claim_rate_pct": (
                verified_ungrounded_rate
                if verified_ungrounded_rate is not None
                else "N/A (Requires Manual Analyst Verification)"
            ),
            "note": "Automated validation errors reflect harness rejections (e.g. snippet/quote mismatches), not necessarily LLM hallucinations.",
        },
        "baseline_comparison": baseline_comparison,
        "grounding_rate_pct": internal_qa_support_rate,
        "grounding_metric_scope": "INTERNAL_QA_VALIDATION_STATUS",
        "hallucination_rate_pct": (
            verified_ungrounded_rate
            if verified_ungrounded_rate is not None
            else f"{total_val_errors} auto-val errors (N/A manual)"
        ),
        "avg_processing_time_sec": avg_time if avg_time is not None else "N/A",
        "avg_cost_per_run_usd": avg_cost if avg_cost is not None else 0.0,
        "precision_pct": independent_precision,
        "recall_pct": independent_recall,
        "f1_score_pct": independent_f1,
        "precision_metric_scope": "INDEPENDENTLY_ANNOTATED_DOCUMENT_FILTER_LOG",
        "threat_score_mae": None,
    }