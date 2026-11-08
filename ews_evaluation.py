# =============================================================================
# aviation_ci_app | Research evaluation and reference-case matching
#
# Responsibility: Compare extracted intelligence against manually specified reference cases and calculate
#   experimental quality metrics.
# Design boundary: Reference matching and evidence provenance are assessed separately from the model’s
#   self-reported confidence.
# =============================================================================


"""Evaluation metrics and comparisons against reference intelligence cases."""

from ews_agent_support import (
    generate_keyword_baseline_report,
)
from ews_filtering import (
    OBVIOUS_NOISE_REGEX,
)
from ews_state import (
    Any,
    DB_LOCK,
    Dict,
    List,
    SQLITE_DB,
    Tuple,
    app,
    json,
    re,
    sqlite3,
    time,
    logger,
)
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
                observed = _detect_specific_variants(
                    ev.get("affected_program", "")
                )

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


# Compute experimental detection, grounding, and scoring metrics against reference cases.
# Metrics are meaningful only against independently curated and relevant reference labels.
# Report evaluation against labelled fixtures, not estimated performance on unseen live data.
@app.get("/api/evaluation")
def compute_evaluation_metrics():
    # Calculate coverage and quality measurements against the selected independent cases.
    """Calculate experimental quality metrics against stored reference cases.
    
    Evaluate semantic filtering, one-to-one event matching, source traceability,
    reference grounding, and independent scoring. Compare with a keyword-only
    baseline on the same source documents. Report unavailable metrics explicitly
    when there is insufficient labeled evidence.
    """
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
    relevant_refs = [c for c in ref_cases if int(c.get("is_relevant") or 0) == 1]
    irrelevant_refs = [c for c in ref_cases if int(c.get("is_relevant") or 0) == 0]

    
    filter_eval: Dict[str, Any] = {
        "status": "OK" if filter_logs else "N/A (Insufficient Data - Run analysis first)",
        "total_documents_evaluated": len(filter_logs),
        "correctly_rejected_irrelevant_tn": None,
        "mistakenly_rejected_relevant_fn": None,
        "filter_precision_pct": None,
        "filter_recall_pct": None,
        "filter_f1_pct": None,
    }
    if filter_logs and ref_cases:
        f_tp, f_fp, f_tn, f_fn = 0, 0, 0, 0
        for fl in filter_logs:
            fl_accepted = int(fl.get("is_accepted") or 0) == 1
            fl_url = (fl.get("url") or "").strip()
            fl_title_low = (fl.get("title") or "").lower()


            matched_ref = next(
                (rc for rc in ref_cases if (rc.get("source_url") and rc["source_url"] == fl_url) or (
                            rc.get("headline_or_topic") and rc["headline_or_topic"][:35].lower() in fl_title_low)),
                None,
            )
            if matched_ref is not None:
                actually_relevant = int(matched_ref.get("is_relevant") or 0) == 1
            else:
                actually_relevant = not bool(OBVIOUS_NOISE_REGEX.search(fl_title_low)) and fl.get(
                    "signal_type") not in {"MODEL_MISMATCH", "OUT_OF_SCOPE", "DUPLICATE", "EMPTY_OR_INJECTION"}

            if fl_accepted and actually_relevant:
                f_tp += 1
            elif fl_accepted and not actually_relevant:
                f_fp += 1
            elif not fl_accepted and not actually_relevant:
                f_tn += 1
            else:
                f_fn += 1

        f_prec = round((f_tp / (f_tp + f_fp)) * 100, 1) if (f_tp + f_fp) > 0 else None
        f_rec = round((f_tp / (f_tp + f_fn)) * 100, 1) if (f_tp + f_fn) > 0 else None
        f_f1 = round(2 * (f_prec * f_rec) / (f_prec + f_rec), 1) if (
                    f_prec and f_rec and (f_prec + f_rec) > 0) else None
        filter_eval.update({
            "true_positives_kept": f_tp,
            "false_positives_kept": f_fp,
            "correctly_rejected_irrelevant_tn": f_tn,
            "mistakenly_rejected_relevant_fn": f_fn,
            "filter_precision_pct": f_prec,
            "filter_recall_pct": f_rec,
            "filter_f1_pct": f_f1,
        })

    
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

        qa_supported_count = sum(
            1 for e in events if e.get("validation_status") == "SUPPORTED"
        )
        internal_qa_support_rate = round((qa_supported_count / total_events) * 100, 1)

        clean_fact_sep_count = sum(
            1
            for e in events
            if e.get("confirmed_facts")
            and not HYPOTHETICAL_IN_FACTS_REGEX.search(e.get("confirmed_facts") or "")
            and e.get("hypothetical_scenario")
        )
        fact_hypothesis_sep_rate = round((clean_fact_sep_count / total_events) * 100, 1)

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

                logger.exception(
                    "[EVALUATION] Keyword baseline failed: %s",
                    exc,
                )

                baseline_error = type(exc).__name__

                from types import SimpleNamespace

                base_report = SimpleNamespace(
                    threats=[]
                )
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

            baseline_comparison = {
                "status": (
                    "N/A (Keyword baseline failed)"
                    if baseline_error
                    else "COMPARED_ON_IDENTICAL_DATASET"
                ),
                "dataset_run_id": latest_run_id,
                "input_documents_count": len(stored_docs),
                "Keyword_Baseline": {
                    "events_generated": len(base_events),
                    "precision_pct": b_prec,
                    "recall_pct": b_rec,
                    "f1_score_pct": b_f1,
                    "scm_accuracy_pct": b_scm_acc,
                    "content_grounding_rate_pct": b_ground_rate,
                    "processing_time_sec": base_time,
                    "tokens_used": 0,
                    "cost_usd": 0.0,
                },
                "aviation_ci_app_MultiAgent": {
                    "events_generated": total_events,
                    "precision_pct": precision,
                    "recall_pct": recall,
                    "f1_score_pct": f1,
                    "scm_accuracy_pct": scm_accuracy_pct,
                    "content_grounding_rate_pct": ref_content_grounding_rate if ref_content_grounding_rate is not None else internal_qa_support_rate,
                    "processing_time_sec": avg_time,
                    "tokens_used": avg_tokens,
                    "cost_usd": avg_cost,
                },
            }

    return {
        "data_sufficiency_status": (
            "SUFFICIENT"
            if total_events > 0
            else "N/A (Insufficient Data - 0 events processed)"
        ),

        "measurement_note": (
            "Reference cases include seeded/illustrative examples; "
            "unmatched filter documents are heuristically labeled. "
            "Precision/recall are diagnostic estimates, not "
            "independently verified research metrics."
        ),
        "total_runs_evaluated": len(runs),
        "total_unique_events": total_events,
        "reference_dataset_count": len(ref_cases),
        "reference_positive_cases": len(relevant_refs),
        "reference_negative_cases": len(irrelevant_refs),
        "semantic_filter_evaluation": filter_eval,
        "analytical_output_evaluation": {
            "precision_pct": precision if precision is not None else "N/A (Insufficient Data)",
            "recall_pct": recall if recall is not None else "N/A (Insufficient Data)",
            "f1_score_pct": f1 if f1 is not None else "N/A (Insufficient Data)",
            "scm_classification_accuracy_pct": scm_accuracy_pct if scm_accuracy_pct is not None else "N/A (Insufficient Data)",
            "citation_traceability_rate_pct": citation_traceability_rate if citation_traceability_rate is not None else "N/A (Insufficient Data)",
            "reference_content_grounding_rate_pct": ref_content_grounding_rate if ref_content_grounding_rate is not None else "N/A (Insufficient Data)",
            "internal_qa_support_rate_pct": internal_qa_support_rate if internal_qa_support_rate is not None else "N/A (Insufficient Data)",
            "fact_vs_hypothesis_separation_rate_pct": fact_hypothesis_sep_rate if fact_hypothesis_sep_rate is not None else "N/A (Insufficient Data)",
            "threat_score_mae": mae if mae is not None else "N/A (Insufficient Data)",
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

        "grounding_rate_pct": (
            ref_content_grounding_rate
            if ref_content_grounding_rate is not None
            else (internal_qa_support_rate if internal_qa_support_rate is not None else "N/A")
        ),
        "hallucination_rate_pct": (
            verified_ungrounded_rate
            if verified_ungrounded_rate is not None
            else f"{total_val_errors} auto-val errors (N/A manual)"
        ),
        "avg_processing_time_sec": avg_time if avg_time is not None else "N/A",
        "avg_cost_per_run_usd": avg_cost if avg_cost is not None else 0.0,
        "precision_pct": precision,
        "recall_pct": recall,
        "f1_score_pct": f1,
        "threat_score_mae": mae,
    }
