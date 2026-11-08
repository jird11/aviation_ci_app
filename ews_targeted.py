# =============================================================================
# aviation_ci_app | Targeted follow-up investigations for evidence gaps
#
# Responsibility: Build narrow queries for unresolved events, check newly collected documents against
#   existing evidence, and update review status.
# Design boundary: A targeted scan can add evidence but must not silently convert weak or unrelated
#   sources into verified confirmation.
# =============================================================================

"""Targeted follow-up scans for unresolved intelligence evidence gaps."""

from ews_filtering import OBVIOUS_NOISE_REGEX
from ews_models import TargetedScanRequest
from ews_reporting import refresh_threat_reports_dict
from ews_state import (
    Any, CONTRADICTION_MARKERS, ConfidenceLevel, DB_LOCK, Dict, EventStatus,
    FINAL_FILE, HTTPException, List, Optional, PENDING_FILE, SQLITE_DB,
    SequenceMatcher, Tuple, ValidationStatus, app, datetime,
    get_collected_documents, is_date_within_scope, json, logger,
    normalize_scope_value, os, re, scrape_manufacturer_pr_news,
    scrape_regulatory_agencies, search_aerospace_news, sqlite3, timezone, uuid,
)
from ews_validation import (
    _count_independent_confirmations, _detect_aircraft_families,
    _detect_engine_models, _detect_specific_variants,
    _normalize_for_quote_match, _split_affected_entities,
    _engine_models_match,
)


# Create a focused evidence-retrieval query for a specific unresolved event.
# Construct search terms from the unresolved event, not from unverified causal assumptions.
def _build_concrete_targeted_query(target_threat: Dict[str, Any], req: TargetedScanRequest) -> str:
    """Build a focused follow-up query from the event entity, aircraft, component, and issue."""
    company_raw = target_threat.get("company_affected") or req.company_affected or ""
    primary_entity = _split_affected_entities(company_raw)[0] if company_raw else ""
    program_raw = target_threat.get("affected_program") or ""
    component_raw = target_threat.get("affected_component") or ""
    facts_and_desc = (
        f"{target_threat.get('confirmed_facts', '')} "
        f"{target_threat.get('threat_description', '')} "
        f"{target_threat.get('fact_check_quote', '')}"
    )

    model_token = program_raw.replace("_FAMILY", "").replace("_", " ") if not program_raw.startswith("Unknown") else ""
    engine_token = component_raw if not component_raw.startswith("Unknown") else ""

    issue_keywords = [
        kw for kw in (
            "fire switch", "powder metal", "shortage", "delay", "grounded", "grounding",
            "defect", "crack", "corrosion", "directive", "shutdown", "inspection", "halt",
        )
        if kw in facts_and_desc.lower()
    ]
    issue_token = " ".join(issue_keywords[:2]) if issue_keywords else "production delay safety"

    query_parts = []
    for part in (primary_entity, model_token, engine_token, issue_token):
        clean_p = part.strip()
        if clean_p and clean_p.lower() not in " ".join(query_parts).lower():
            query_parts.append(clean_p)

    concrete_query = re.sub(
        r"\s+",
        " ",
        " ".join(query_parts),
    ).strip()[:110]

    return (
            concrete_query
            or f"{primary_entity} {issue_token}".strip()[:110]
    )


# Identify genuinely new supporting, contradictory, or duplicate follow-up evidence.
# Keep original and newly collected evidence distinguishable in the audit.
# Do not confuse syndication duplicates or unrelated commentary with independent corroboration.
def _classify_targeted_scan_document(
    doc: Dict[str, Any],
    target_threat: Dict[str, Any],
    existing_urls: set[str],
    existing_fps: set[str],
    existing_titles_norm: List[str],
) -> Tuple[str, str]:
    """Classify new evidence relative to the original event claim."""
    doc_url = (doc.get("url") or "").strip()
    doc_fp = (doc.get("syndication_fingerprint") or "").strip()
    doc_title = (doc.get("title") or "").strip()
    doc_text = (doc.get("text") or "").strip()
    doc_pub = doc.get("published_at") or "DATE_UNKNOWN"
    doc_full = f"{doc_title} {doc_text}"
    doc_norm = _normalize_for_quote_match(doc_full)
    doc_title_norm = _normalize_for_quote_match(doc_title)

    if not is_date_within_scope(doc_pub) or OBVIOUS_NOISE_REGEX.search(doc_full):
        return "IRRELEVANT", f"Out of time scope ({doc_pub}) or non-industrial noise."

    if (
        (doc_url and doc_url in existing_urls)
        or (doc_fp and doc_fp in existing_fps)
        or any(doc_title_norm and SequenceMatcher(None, doc_title_norm, et).ratio() >= 0.65 for et in existing_titles_norm)
    ):
        return "RELATED", "Syndicated repetition or duplicate of an already recorded report (not independent confirmation)."

    claim_text = (
        f"{target_threat.get('company_affected', '')} "
        f"{target_threat.get('affected_program', '')} "
        f"{target_threat.get('affected_component', '')} "
        f"{target_threat.get('confirmed_facts', '')} "
        f"{target_threat.get('threat_description', '')}"
    )

    entities = _split_affected_entities(target_threat.get("company_affected", ""))
    entity_tokens = [
        tok for ent in entities for tok in re.findall(r"\b[a-z0-9]{3,}\b", ent.lower())
        if tok not in {"the", "company", "airlines", "airways", "holdings", "international"}
    ]
    if entity_tokens and not any(tok in doc_norm for tok in entity_tokens):
        return "IRRELEVANT", "Does not mention the affected manufacturer or operator."

    claim_variants, doc_variants = _detect_specific_variants(claim_text), _detect_specific_variants(doc_full)
    if claim_variants and doc_variants and not claim_variants.intersection(doc_variants):
        return "RELATED", f"Discusses sibling/different variant {sorted(doc_variants)} rather than target variant {sorted(claim_variants)}."
    if claim_variants and not doc_variants:
        return "RELATED", f"Mentions company generally but does not specify target variant {sorted(claim_variants)}."

    claim_families, doc_families = _detect_aircraft_families(claim_text), _detect_aircraft_families(doc_full)
    if claim_families and doc_families and not claim_families.intersection(doc_families):
        return "IRRELEVANT", f"Concerns unrelated aircraft family {sorted(doc_families)}."

    claim_engines, doc_engines = _detect_engine_models(claim_text), _detect_engine_models(doc_full)
    if (
            claim_engines
            and doc_engines
            and not _engine_models_match(claim_text, doc_full)
    ):
        return "IRRELEVANT", f"Concerns different engine model {sorted(doc_engines)}."

    event_terms = [
        w for w in re.findall(
            r"\b[a-z0-9]{4,}\b",
            _normalize_for_quote_match(f"{target_threat.get('confirmed_facts', '')} {target_threat.get('fact_check_quote', '')}"),
        )
        if w not in set(entity_tokens) | {"airbus", "boeing", "source", "states", "confirmed", "aircraft", "program"}
    ]
    matched_event_terms = sum(1 for w in event_terms if w in doc_norm)
    overlap_ratio = (matched_event_terms / len(event_terms)) if event_terms else 0.0

    if CONTRADICTION_MARKERS.search(doc_full.lower()) and overlap_ratio >= 0.25:
        return "CONTRADICTING", "Contains explicit refutation or denial of the claimed event."

    if len(doc_text) < 160 and overlap_ratio < 0.55:
        return "INCONCLUSIVE", "Short snippet without sufficient detail to confirm the specific event."

    if overlap_ratio >= 0.45 and matched_event_terms >= 2:
        return (
            "CORROBORATING",
            f"Independently confirms entity, variant, and event details ({matched_event_terms} core claim terms matched).",
        )
    if overlap_ratio >= 0.20:
        return "RELATED", "Discusses the same company/program theme but does not confirm the specific event."

    return "INCONCLUSIVE", "Insufficient overlap with the specific defect or event."


# Execute a targeted verification scan without silently publishing unverified claims.
# Collecting a new document is not the same as establishing independent corroboration.
# Retain source lineage so a second document is not mistaken for independent confirmation.
@app.post("/api/targeted-kiq-scan")
# A targeted scan should add reviewable evidence while leaving source and event histories intact.
def run_targeted_kiq_scan(req: TargetedScanRequest):
    # Locate the unresolved event and construct a narrow follow-up search context.
    """Collect and classify follow-up evidence for an unresolved intelligence gap."""
    target_file = PENDING_FILE if os.path.exists(PENDING_FILE) else (FINAL_FILE if os.path.exists(FINAL_FILE) else None)
    if not target_file:
        raise HTTPException(status_code=404, detail="No active EWS report found.")

    with open(target_file, "r", encoding="utf-8") as f:
        rep = json.load(f)

    target_threat: Optional[Dict[str, Any]] = next(
        (t for t in rep.get("threats", []) if t.get("event_id") == req.event_id), None
    )
    if target_threat is None:
        raise HTTPException(status_code=404, detail=f"Event {req.event_id} not found in active report.")

    orig_validation_status = target_threat.get("validation_status", "UNSUPPORTED")
    orig_confidence_level = target_threat.get("confidence_level", "LOW")
    orig_event_status = target_threat.get("event_status", "UNDER_REVIEW")
    orig_threat_score = int(target_threat.get("threat_score", 5))
    orig_gap = target_threat.get("intelligence_gap") or {
        "gap_id": f"GAP_{uuid.uuid4().hex[:6].upper()}",
        "what_is_missing": req.what_is_missing,
        "why_important": "Required to verify event impact.",
        "affected_kiq_id": req.affected_kiq_id,
        "recommended_source": "FAA / EASA / Official OEM Pressroom",
        "can_auto_scan": True,
        "status": "OPEN",
    }

    focused_query = _build_concrete_targeted_query(target_threat, req)
    primary_entity = _split_affected_entities(target_threat.get("company_affected") or req.company_affected)[0]
    logger.info(
        f"[TARGETED KIQ SCAN P0-1] Event {req.event_id} | Concrete Query: '{focused_query}' (Entity: '{primary_entity}')"
    )

    os.environ["EWS_DYNAMIC_SCOPE"] = normalize_scope_value(req.scope).value
    os.environ["EWS_DYNAMIC_LIMIT"] = "3"

    existing_docs_before = get_collected_documents()
    before_count = len(existing_docs_before)

    existing_urls = set(target_threat.get("source_urls") or [])
    if target_threat.get("evidence_citation"):
        existing_urls.add(target_threat["evidence_citation"])

    existing_eids = set(target_threat.get("evidence_ids") or [])
    linked_prior_docs = [
        d for d in existing_docs_before
        if d.get("url") in existing_urls or d.get("doc_id") in existing_eids
    ]
    # Deduplicate newly collected sources against existing URLs, fingerprints, and titles.
    existing_fps = {d.get("syndication_fingerprint", "") for d in linked_prior_docs}
    existing_titles_norm = [_normalize_for_quote_match(d.get("title", "")) for d in linked_prior_docs]

    scrape_regulatory_agencies.run(f"{primary_entity} {target_threat.get('affected_program', '')}".strip())
    scrape_manufacturer_pr_news.run(focused_query)
    search_aerospace_news.run(focused_query)

    all_docs_after = get_collected_documents()
    raw_new_docs = all_docs_after[before_count:]

    categorized: Dict[str, List[Dict[str, Any]]] = {
        "CORROBORATING": [],
        "RELATED": [],
        "CONTRADICTING": [],
        "IRRELEVANT": [],
        "INCONCLUSIVE": [],
    }
    scan_evaluations: List[Dict[str, Any]] = []

    for d in raw_new_docs:
        cat, reason = _classify_targeted_scan_document(
            d, target_threat, existing_urls, existing_fps, existing_titles_norm
        )
        categorized[cat].append(d)
        scan_evaluations.append({
            "doc_id": d.get("doc_id"),
            "url": d.get("url"),
            "title": d.get("title"),
            "category": cat,
            "rationale": reason,
        })
        if cat == "CORROBORATING":
            if d.get("url"):
                existing_urls.add(d["url"])
            if d.get("syndication_fingerprint"):
                existing_fps.add(d["syndication_fingerprint"])
            existing_titles_norm.append(_normalize_for_quote_match(d.get("title", "")))

    corroborating_docs = categorized["CORROBORATING"]
    contradicting_docs = categorized["CONTRADICTING"]
    related_docs = categorized["RELATED"]
    inconclusive_docs = categorized["INCONCLUSIVE"]

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    new_validation_status = orig_validation_status
    new_confidence_level = orig_confidence_level
    new_event_status = orig_event_status
    new_gap_status = orig_gap.get("status", "OPEN")
    new_missing_data = target_threat.get("missing_data")
    new_verification_status = target_threat.get("verification_status", "")

    if contradicting_docs:
        new_validation_status = ValidationStatus.CONTRADICTED.value
        new_confidence_level = ConfidenceLevel.LOW.value
        new_event_status = EventStatus.UNDER_REVIEW.value
        new_gap_status = "OPEN"
        new_missing_data = (
            f"Contradicting evidence detected in {len(contradicting_docs)} source(s); manual analyst verification required."
        )
        new_verification_status = (
            f"CONFLICTING EVIDENCE (Manual HITL Review Required): {len(contradicting_docs)} contradicting vs "
            f"{len(corroborating_docs)} corroborating doc(s)."
        )
    elif corroborating_docs:
        corrob_urls = [d["url"] for d in corroborating_docs if d.get("url")]
        corrob_ids = [d["doc_id"] for d in corroborating_docs if d.get("doc_id")]
        target_threat["source_urls"] = list(dict.fromkeys((target_threat.get("source_urls") or []) + corrob_urls))
        target_threat["evidence_ids"] = list(dict.fromkeys((target_threat.get("evidence_ids") or []) + corrob_ids))

        all_confirming_docs = [
            d for d in all_docs_after
            if d.get("doc_id") in target_threat["evidence_ids"] or d.get("url") in target_threat["source_urls"]
        ]
        indep_count, has_prim_reg, has_prim_oem = _count_independent_confirmations(all_confirming_docs)

        if has_prim_reg or has_prim_oem or indep_count >= 2:

            new_validation_status = (
                ValidationStatus.PARTIALLY_SUPPORTED.value
            )

            new_confidence_level = (
                ConfidenceLevel.MEDIUM.value
            )

            new_event_status = (
                EventStatus.UNDER_REVIEW.value
            )

            new_gap_status = "OPEN"

            new_missing_data = (
                "New corroborating evidence was located, "
                "but full event-level Harness validation "
                "is still required before confirmation."
            )

            new_verification_status = (
                f"Targeted evidence retrieved "
                f"({len(corroborating_docs)} corroborating candidates; "
                f"{indep_count} independent source(s)); "
                "AWAITING_FULL_QA"
            )
        else:
            # Classify incremental evidence and reconcile the current pending or final report.
            new_validation_status = ValidationStatus.PARTIALLY_SUPPORTED.value
            if orig_confidence_level == ConfidenceLevel.LOW.value:
                new_confidence_level = ConfidenceLevel.MEDIUM.value
            new_gap_status = "OPEN"
            new_missing_data = (
                "Partial secondary corroboration found; primary OEM/regulator or second independent source still required."
            )
            new_verification_status = (
                f"Partially Corroborated via Targeted KIQ Scan (+{len(corroborating_docs)} secondary doc; primary confirmation pending)"
            )
    else:
        new_gap_status = "OPEN"
        summary_counts = (
            f"{len(related_docs)} related, {len(inconclusive_docs)} inconclusive, "
            f"{len(categorized['IRRELEVANT'])} irrelevant"
        )
        new_missing_data = (
            target_threat.get("missing_data")
            or f"Targeted scan found no corroborating evidence ({summary_counts}); gap remains OPEN."
        )

    orig_gap["status"] = new_gap_status
    if new_missing_data:
        orig_gap["what_is_missing"] = new_missing_data

    target_threat.update({
        "validation_status": new_validation_status,
        "confidence_level": new_confidence_level,
        "event_status": new_event_status,
        "threat_score": orig_threat_score,
        "missing_data": new_missing_data,
        "verification_status": new_verification_status,
        "updated_at": now_iso,
        "intelligence_gap": orig_gap,
    })
    target_threat.setdefault("corroboration_summary", {})["Targeted KIQ Scan Audit"] = (
        f"Corroborating: {len(corroborating_docs)} | Related: {len(related_docs)} | "
        f"Contradicting: {len(contradicting_docs)} | Inconclusive: {len(inconclusive_docs)} | "
        f"Irrelevant: {len(categorized['IRRELEVANT'])}"
    )

    for ka in rep.get("kiq_answers", []):
        if req.event_id in (ka.get("related_event_ids") or []):
            ka["evidence_ids"] = list(
                dict.fromkeys((ka.get("evidence_ids") or []) + (target_threat.get("evidence_ids") or []))
            )
            if new_gap_status == "RESOLVED" and new_confidence_level == "HIGH":
                ka.update({
                    "answer_status": "ANSWERED",
                    "uncertainty_level": "HIGH",
                    "missing_information": None,
                    "verification_status": "Corroborated via Targeted KIQ Scan",
                })
            else:
                ka["answer_status"] = "PARTIALLY_ANSWERED"
                ka["missing_information"] = new_missing_data

    rep = refresh_threat_reports_dict(rep)
    rep["version"] = int(rep.get("version", 1)) + 1
    with open(target_file, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2, ensure_ascii=False)

    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE events
            SET confidence_level = ?, event_status = ?, validation_status = ?,
                verification_status = ?, updated_at = ?, source_urls_json = ?,
                evidence_ids_json = ?, corroboration_json = ?, missing_data = ?
            WHERE event_id = ?
            """,
            (
                new_confidence_level, new_event_status, new_validation_status,
                new_verification_status, now_iso,
                json.dumps(target_threat.get("source_urls", [])),
                json.dumps(target_threat.get("evidence_ids", [])),
                json.dumps(target_threat.get("corroboration_summary", {})),
                new_missing_data, req.event_id,
            ),
        )
        cur.execute(
            "UPDATE reports SET version = ?, updated_at = ?, report_json = ? WHERE report_id = ?",
            (rep["version"], now_iso, json.dumps(rep, indent=2, ensure_ascii=False), rep.get("report_id", "")),
        )
        cur.execute(
            """
            INSERT INTO event_history (
                event_id, run_id, recorded_at, threat_score, confidence_level, event_status, change_type, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req.event_id, "TARGETED_SCAN", now_iso, orig_threat_score,
                new_confidence_level, new_event_status, "TARGETED_KIQ_SCAN_VALIDATED",
                (
                    f"Query: '{focused_query}' | Corroborating: {len(corroborating_docs)}, "
                    f"Related: {len(related_docs)}, Contradicting: {len(contradicting_docs)}, "
                    f"Inconclusive: {len(inconclusive_docs)}, Irrelevant: {len(categorized['IRRELEVANT'])} | "
                    f"Gap Status: {new_gap_status}"
                ),
            ),
        )
        conn.commit()

    return {
        "status": "completed",
        "event_id": req.event_id,
        "query_executed": focused_query,
        "new_documents_found": len(raw_new_docs),
        "corroborating_count": len(corroborating_docs),
        "related_count": len(related_docs),
        "contradicting_count": len(contradicting_docs),
        "inconclusive_count": len(inconclusive_docs),
        "irrelevant_count": len(categorized["IRRELEVANT"]),
        "confidence_level": new_confidence_level,
        "validation_status": new_validation_status,
        "gap_status": new_gap_status,
        "evaluated_documents": scan_evaluations,
    }