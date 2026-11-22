# =============================================================================
# aviation_ci_app | Targeted follow-up investigations for evidence gaps
#
# Responsibility: Build narrow queries for unresolved events, check newly collected documents against
#   existing evidence, and update review status.
# Design boundary: A targeted scan can add evidence but must not silently convert weak or unrelated
#   sources into verified confirmation.
# =============================================================================

"""Targeted follow-up scans for unresolved intelligence evidence gaps."""

import hmac
import hashlib
import threading
from contextlib import contextmanager, closing
from urllib.parse import urlparse

from fastapi import Request

from ews_filtering import OBVIOUS_NOISE_REGEX
from ews_models import TargetedScanRequest
from ews_state import (
    Any, CONTRADICTION_MARKERS, DB_LOCK, Dict,
    FINAL_FILE, HTTPException, List, Optional, PENDING_FILE, PIPELINE_STATE, SQLITE_DB,
    SequenceMatcher, Tuple, app, datetime,
    get_collected_documents, is_date_within_scope, json, logger,
    normalize_scope_value, os, re, scrape_manufacturer_pr_news,
    scrape_regulatory_agencies, search_aerospace_news, sqlite3, timezone, uuid,
)
from ews_validation import (
    _detect_aircraft_families, _detect_engine_models, _detect_specific_variants,
    _normalize_for_quote_match, _split_affected_entities,
    _engine_models_match,
)

_TARGETED_LOCK = threading.RLock()
_COMPLETE_CONTENT = {"FULL_TEXT", "STRUCTURED_DATA", "TRANSCRIPT_AS_RECEIVED"}
_GAP_SEARCH_FOCUS = (
    (r"\b(?:caus\w*|mechanism|root\s+cause|příčin\w*|proč|selhán\w*)\b", "root cause technical investigation failure mechanism"),
    (r"\b(?:extent|scale|how\s+many|affected\s+(?:units|engines|aircraft)|rozsah|počet|kolik)\b", "number of affected engines aircraft units"),
    (r"\b(?:component\w*|part\s+number|assembly|součást\w*|komponent\w*|díl\w*)\b", "affected component part number inspection findings"),
    (r"\b(?:impact\w*|production|deliver\w*|capacity|dopad\w*|výrob\w*|předáv\w*)\b", "production capacity delivery schedule documented impact"),
    (r"\b(?:regulat\w*|directive\w*|docket|effective|compliance|předpis\w*|účinnost\w*)\b", "FAA docket final rule effective date compliance deadline"),
)


@contextmanager
def _isolated_targeted_scope(scope: str):
    """Serialize targeted collectors and restore process settings after every scan."""
    keys = (
        "EWS_DYNAMIC_SCOPE", "EWS_DYNAMIC_LIMIT", "EWS_DATE_FROM", "EWS_DATE_TO",
        "EWS_AS_OF_DATE", "EWS_EFFECTIVE_FROM", "EWS_EFFECTIVE_TO",
    )
    with _TARGETED_LOCK:
        previous = {key: os.environ.get(key) for key in keys}
        try:
            os.environ.update({key: "" for key in keys})
            os.environ.update({"EWS_DYNAMIC_SCOPE": normalize_scope_value(scope).value,
                               "EWS_DYNAMIC_LIMIT": "3"})
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

# Create a focused evidence-retrieval query for a specific unresolved event.
# Construct search terms from the unresolved event, not from unverified causal assumptions.
def _build_concrete_targeted_query(target_threat: Dict[str, Any], req: TargetedScanRequest) -> str:
    """Prioritize the exact missing fact while retaining established entity identity."""
    company_raw = target_threat.get("company_affected") or req.company_affected or ""
    entities = _split_affected_entities(company_raw) if company_raw else []
    primary_entity = entities[0] if entities else ""
    program_raw = target_threat.get("affected_program") or ""
    component_raw = target_threat.get("affected_component") or ""
    gap = target_threat.get("intelligence_gap") or {}
    missing = str(gap.get("what_is_missing") or req.what_is_missing or "")
    focus = [hint for pattern, hint in _GAP_SEARCH_FOCUS if re.search(pattern, missing, re.I)]
    identifiers = re.findall(r"\bFAA-\d{4}-\d+\b|\b20\d{2}-\d{5}\b", missing)
    if not focus:
        focus = [" ".join(re.findall(r"[\w-]{3,}", missing)[:8])]
    parts = []
    for token in (primary_entity, program_raw.replace("_FAMILY", "").replace("_", " "),
                  component_raw, *identifiers, *focus[:2]):
        clean = re.sub(r"[\x00-\x1f<>]", " ", str(token or "")).strip()
        if clean and not clean.lower().startswith("unknown") and clean.lower() not in " ".join(parts).lower():
            if len(" ".join([*parts, clean])) > 210:
                break
            parts.append(clean)
    return " ".join(parts) or missing[:140].strip()

# Identify genuinely new supporting, contradictory, or duplicate follow-up evidence.
# Keep original and newly collected evidence distinguishable in the audit.
# Do not confuse syndication duplicates or unrelated commentary with independent corroboration.
def _classify_targeted_scan_document(
    doc: Dict[str, Any],
    target_threat: Dict[str, Any],
    existing_urls: set[str],
    existing_fps: set[str],
    existing_titles_norm: List[str],
    existing_domains: Optional[set[str]] = None,
) -> Tuple[str, str]:
    """Prioritize review candidates; lexical agreement is never verification."""
    doc_url = (doc.get("url") or "").strip()
    doc_fp = (doc.get("syndication_fingerprint") or "").strip()
    doc_title = (doc.get("title") or "").strip()
    doc_text = (doc.get("text") or "").strip()
    doc_pub = doc.get("published_at") or "DATE_UNKNOWN"
    doc_full = f"{doc_title} {doc_text}"
    doc_norm = _normalize_for_quote_match(doc_full)
    doc_title_norm = _normalize_for_quote_match(doc_title)

    try:
        datetime.fromisoformat(str(doc_pub).replace("Z", "+00:00"))
    except ValueError:
        return "INCONCLUSIVE", "Publication date could not be verified; time relevance is unknown."
    if not is_date_within_scope(doc_pub):
        return "IRRELEVANT", f"Document date {doc_pub} is outside the requested scope."
    if OBVIOUS_NOISE_REGEX.search(doc_full):
        return "IRRELEVANT", "Non-industrial content is unrelated to the monitored issue."
    if not doc.get("doc_id") or not doc_url:
        return "INCONCLUSIVE", "Document ID or source URL is missing; provenance cannot be verified."

    if (
        (doc_url and doc_url in existing_urls)
        or (doc_fp and doc_fp in existing_fps)
        or any(doc_title_norm and SequenceMatcher(None, doc_title_norm, et).ratio() >= 0.65 for et in existing_titles_norm)
    ):
        return "RELATED", "Syndicated repetition or duplicate of an already recorded report (not independent confirmation)."

    publisher = str(doc.get("publisher_domain") or urlparse(doc_url).hostname or "").lower().removeprefix("www.")
    same_publisher = bool(publisher and publisher in (existing_domains or set()))
    if doc.get("content_truncated") or doc.get("content_status") not in _COMPLETE_CONTENT or len(doc_text) < 240:
        return "INCONCLUSIVE", "Content is truncated, metadata-only, or too short for claim-level verification."

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
    if claim_engines and doc_engines and (not _engine_models_match(claim_text, doc_full)):
        return "IRRELEVANT", f"Concerns different engine model {sorted(doc_engines)}."

    claim = str(target_threat.get("fact_check_quote") or target_threat.get("confirmed_facts") or "")
    terms = set(re.findall(r"\b[a-z0-9]{4,}\b", _normalize_for_quote_match(claim))) - (
        set(entity_tokens) | {"airbus", "boeing", "source", "states", "confirmed", "aircraft", "program"}
    )
    if len(terms) < 3:
        return "INCONCLUSIVE", "Original event lacks a sufficiently specific source claim for comparison."
    # Demand a coherent passage; words scattered across a long article are not a claim match.
    passages = [doc_text[i:i + 500] for i in range(0, len(doc_text), 300)]
    best = max((len(terms & set(re.findall(r"\b[a-z0-9]{4,}\b", _normalize_for_quote_match(p))))
                for p in passages), default=0)
    if best < 3 or best / len(terms) < 0.50:
        return "RELATED", "Topic overlap without a passage supporting the specific original claim."
    missing = str((target_threat.get("intelligence_gap") or {}).get("what_is_missing") or "")
    focus = [pattern for pattern, _ in _GAP_SEARCH_FOCUS if re.search(pattern, missing, re.I)]
    if focus and not any(re.search(pattern, doc_text, re.I) for pattern in focus):
        return "INCONCLUSIVE", "No passage addresses the particular outstanding intelligence gap."
    if CONTRADICTION_MARKERS.search(doc_text.lower()):
        result, reason = "CONTRADICTION_CANDIDATE", "Possible claim refutation; QA must verify context and negation."
    else:
        result, reason = "CORROBORATION_CANDIDATE", "Passage overlaps the claim; factual support requires QA."
    if same_publisher:
        reason += " Same publisher as prior evidence; independence is not established."
    return result, reason


def _authorize_targeted_request(req: TargetedScanRequest, request: Request) -> Tuple[str, str, int]:
    """Fail closed on missing analyst credentials, report identity, or version."""
    headers = request.headers
    secret = os.getenv("EWS_REVIEW_KEY", "")
    if len(secret) < 16 or secret.startswith("REPLACE"):
        raise HTTPException(status_code=503, detail="Analyst authorization is not configured.")
    token = headers.get("x-review-key") or headers.get("x-ews-review-key") or ""
    role = headers.get("x-review-role", "").upper()
    if not hmac.compare_digest(token, secret) or role != os.getenv("EWS_REVIEW_ROLE", "ANALYST").upper():
        raise HTTPException(status_code=403, detail="Analyst authorization required.")
    analyst = headers.get("x-analyst-id", "")
    report_id = str(getattr(req, "report_id", None) or headers.get("x-report-id") or "")
    version_raw = getattr(req, "report_version", None) or headers.get("x-report-version")
    if not re.fullmatch(r"[A-Za-z0-9._@-]{3,96}", analyst):
        raise HTTPException(status_code=422, detail="A valid analyst identity is required.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,100}", report_id):
        raise HTTPException(status_code=422, detail="A valid report_id is required.")
    try:
        version = int(version_raw)
        if version < 1:
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="A positive report version is required.")
    return analyst, report_id, version


def _require_scan_approval(request: Request, gap: Dict[str, Any], analyst: str) -> Optional[str]:
    required = (os.getenv("EWS_TARGETED_SCAN_REQUIRE_APPROVAL", "0").lower() in {"1", "true", "yes", "on"}
                or gap.get("can_auto_scan") is not True)
    if not required:
        return None
    secret = os.getenv("EWS_TARGETED_SCAN_APPROVAL_KEY", "")
    if len(secret) < 16 or hmac.compare_digest(secret, os.getenv("EWS_REVIEW_KEY", "")):
        raise HTTPException(status_code=503, detail="HITL targeted-scan approval is not configured.")
    approver = request.headers.get("x-approver-id", "")
    token = request.headers.get("x-targeted-approval-key", "")
    if (not hmac.compare_digest(token, secret)
            or not re.fullmatch(r"[A-Za-z0-9._@-]{3,96}", approver)
            or approver.casefold() == analyst.casefold()):
        raise HTTPException(status_code=403, detail="Independent HITL approval is required.")
    return approver


def _load_target_report(report_id: str, version: int) -> Dict[str, Any]:
    for path in (PENDING_FILE, FINAL_FILE):
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
        if report.get("report_id") != report_id:
            continue
        if int(report.get("version") or 1) != version:
            raise HTTPException(status_code=409, detail="Report version changed; reload before scanning.")
        return report
    raise HTTPException(status_code=404, detail="Requested report_id is not active.")

# Execute a targeted verification scan without silently publishing unverified claims.
# Collecting a new document is not the same as establishing independent corroboration.
# Retain source lineage so a second document is not mistaken for independent confirmation.
@app.post("/api/targeted-kiq-scan")
def run_targeted_kiq_scan(req: TargetedScanRequest, request: Request):
    """Stage traceable follow-up evidence for QA, never silently modify a report."""
    analyst, report_id, expected_version = _authorize_targeted_request(req, request)
    report = _load_target_report(report_id, expected_version)
    threat = next((item for item in report.get("threats", [])
                   if item.get("event_id") == req.event_id), None)
    if threat is None:
        raise HTTPException(status_code=404, detail="Event not found in the requested report.")
    gap = threat.get("intelligence_gap") or {}
    if str(gap.get("status") or "OPEN").upper() in {"RESOLVED", "CLOSED"}:
        raise HTTPException(status_code=409, detail="The intelligence gap is already closed.")
    approver = _require_scan_approval(request, gap, analyst)

    if PIPELINE_STATE.get("running"):
        raise HTTPException(status_code=409, detail="Another EWS collection is running; retry later.")

    query = _build_concrete_targeted_query(threat, req)
    if not query:
        raise HTTPException(status_code=422, detail="No identifiable entity or evidence gap to search.")

    prior_urls = set(threat.get("source_urls") or [])
    if threat.get("evidence_citation"):
        prior_urls.add(threat["evidence_citation"])
    prior_ids = set(threat.get("evidence_ids") or [])
    prior_docs = [doc for doc in get_collected_documents() if doc.get("url") in prior_urls]

    # Historical source lineage is run-scoped; DOC_IDs can be reused across runs.
    if prior_ids and report.get("run_id"):
        placeholders = ",".join("?" for _ in prior_ids)
        try:
            with DB_LOCK, closing(sqlite3.connect(SQLITE_DB)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    f"SELECT doc_id, url, publisher_domain, syndication_fingerprint, title "
                    f"FROM source_documents WHERE run_id = ? AND doc_id IN ({placeholders})",
                    (report["run_id"], *sorted(prior_ids)),
                ).fetchall()
            prior_docs.extend(dict(row) for row in rows)
        except sqlite3.Error as exc:
            logger.warning("[TARGETED SCAN] Historical document lineage unavailable: %s", exc)

    prior_urls.update(d.get("url") for d in prior_docs if d.get("url"))
    prior_fps = {d.get("syndication_fingerprint") for d in prior_docs if d.get("syndication_fingerprint")}
    prior_titles = [_normalize_for_quote_match(d.get("title") or "") for d in prior_docs]
    prior_domains = {
        str(d.get("publisher_domain") or urlparse(str(d.get("url") or "")).hostname or "")
        .lower().removeprefix("www.")
        for d in prior_docs
    } | {
        (urlparse(url).hostname or "").lower().removeprefix("www.")
        for url in prior_urls
    }
    prior_domains.discard("")

    categories = {name: [] for name in (
        "CORROBORATION_CANDIDATE", "CONTRADICTION_CANDIDATE",
        "RELATED", "IRRELEVANT", "INCONCLUSIVE",
    )}
    evaluations, collection_errors = [], []
    missing_fact = str(gap.get("what_is_missing") or req.what_is_missing or "")
    regulatory_gap = bool(re.search(r"\b(?:regulat\w*|directive\w*|docket|effective|FAA|EASA|předpis\w*|účinnost)\b", missing_fact, re.I))
    operational_gap = bool(re.search(r"\b(?:production|deliver\w*|capacity|impact\w*|výrob\w*|předáv\w*|dopad\w*)\b", missing_fact, re.I))
    connectors = (
        (scrape_regulatory_agencies, scrape_manufacturer_pr_news)
        if regulatory_gap and not operational_gap else
        (scrape_manufacturer_pr_news, search_aerospace_news)
        if operational_gap and not regulatory_gap else
        (scrape_regulatory_agencies, scrape_manufacturer_pr_news, search_aerospace_news)
    )

    with _isolated_targeted_scope(req.scope):
        if PIPELINE_STATE.get("running"):
            raise HTTPException(status_code=409, detail="Another EWS collection started.")
        known_ids = {id(doc) for doc in get_collected_documents()}
        for connector in connectors:
            try:
                outcome = connector.run(query)
                if isinstance(outcome, str) and re.match(r"^\s*(?:error|failed|unavailable|access denied)\b", outcome, re.I):
                    collection_errors.append({"connector": str(getattr(connector, "name", "unknown")),
                                              "error_type": "CONNECTOR_REPORTED_ERROR"})
            except Exception as exc:
                collection_errors.append({"connector": str(getattr(connector, "name", "unknown")),
                                          "error_type": type(exc).__name__})
                logger.warning("[TARGETED SCAN] Connector failed: %s", type(exc).__name__)
        new_docs = [doc for doc in get_collected_documents() if id(doc) not in known_ids]
        seen_doc_ids = set()
        for doc in new_docs:
            doc_id = str(doc.get("doc_id") or "")
            if doc_id and doc_id in seen_doc_ids:
                category, reason = "RELATED", "Repeated DOC_ID in this scan; not independent evidence."
            else:
                category, reason = _classify_targeted_scan_document(
                    doc, threat, prior_urls, prior_fps, prior_titles, prior_domains
                )
            if doc_id:
                seen_doc_ids.add(doc_id)
            categories[category].append(doc)
            publisher = str(doc.get("publisher_domain") or urlparse(str(doc.get("url") or "")).hostname or "")
            publisher = publisher.lower().removeprefix("www.")
            evaluations.append({
                "doc_id": doc.get("doc_id"), "url": doc.get("url"),
                "title": doc.get("title"), "category": category, "rationale": reason,
                "source_id": doc.get("source_id"), "publisher_domain": publisher or None,
                "source_independence": "NOT_ESTABLISHED",
                "same_publisher_as_existing": bool(publisher and publisher in prior_domains),
                "published_at": doc.get("published_at"),
                "source_content_sha256": doc.get("source_content_sha256") or doc.get("content_sha256"),
                "content_status": doc.get("content_status", "UNKNOWN"),
                "qa_required": category in {"CORROBORATION_CANDIDATE", "CONTRADICTION_CANDIDATE"},
            })
            if category == "CORROBORATION_CANDIDATE":
                domain = str(doc.get("publisher_domain") or urlparse(str(doc.get("url") or "")).hostname or "")
                prior_domains.add(domain.lower().removeprefix("www."))
                if doc.get("syndication_fingerprint"):
                    prior_fps.add(doc["syndication_fingerprint"])
                prior_titles.append(_normalize_for_quote_match(doc.get("title") or ""))

    scan_id = f"TS_{uuid.uuid4().hex[:16].upper()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    baseline_digest = hashlib.sha256(json.dumps(report, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    candidate_ids = [item["doc_id"] for item in evaluations
                     if item["qa_required"] and item.get("doc_id")]
    evidence_rows, storage_ids = [], set()
    for index, (doc, evaluation) in enumerate(zip(new_docs, evaluations), 1):
        storage_id = str(doc.get("doc_id") or f"UNIDENTIFIED_{index}")
        if storage_id in storage_ids:
            storage_id = f"{storage_id}__DUPLICATE_{index}"
        storage_ids.add(storage_id)
        evaluation["storage_key"] = storage_id
        evidence_rows.append((scan_id, storage_id, json.dumps(doc, ensure_ascii=False, default=str)))
    proposal = {
        "scan_id": scan_id, "report_id": report_id, "report_version": expected_version,
        "baseline_report_sha256": baseline_digest,
        "run_id": report.get("run_id"), "event_id": req.event_id,
        "intelligence_gap_id": gap.get("gap_id"), "missing_fact": gap.get("what_is_missing") or req.what_is_missing,
        "query": query, "scope": normalize_scope_value(req.scope).value,
        "requested_by": analyst, "preapproved_by": approver,
        "actor_identity_assurance": "DECLARED_ID_WITH_REVIEW_SECRET",
        "approver_identity_assurance": "DECLARED_ID_WITH_SEPARATE_HITL_SECRET" if approver else None,
        "created_at": timestamp, "review_status": "PENDING_QA",
        "claim_verification": "NOT_PERFORMED", "evidence_promoted": False,
        "retrieval_completeness": "UNKNOWN_DUE_TO_SOURCE_ERRORS" if collection_errors else "NOT_ESTABLISHED",
        "proposed_update": {
            "event_id": req.event_id, "candidate_doc_ids": candidate_ids,
            "required_validation": "STANDARD_REPORT_VALIDATION_AND_HITL",
            "validation_completed": False, "report_changes": None,
        },
        "original_validation_status": threat.get("validation_status", "UNSUPPORTED"),
        "original_confidence_level": threat.get("confidence_level", "LOW"),
        "evaluations": evaluations, "collector_errors": collection_errors,
    }

    # A version-checked transaction persists only the review proposal and its audit trail.
    # No events, KIQ answers, published files, or report versions are changed.
    if _load_target_report(report_id, expected_version) != report:
        raise HTTPException(status_code=409, detail="Report content changed during scan.")
    with DB_LOCK, closing(sqlite3.connect(SQLITE_DB)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT version, report_json FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
        if (row is None or int(row[0] or 1) != expected_version or json.loads(row[1]) != report):
            raise HTTPException(status_code=409, detail="Report changed during scan; results were not applied.")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targeted_scan_proposals (
                scan_id TEXT PRIMARY KEY, report_id TEXT NOT NULL, report_version INTEGER NOT NULL,
                event_id TEXT NOT NULL, review_status TEXT NOT NULL,
                created_at TEXT NOT NULL, proposal_json TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targeted_scan_evidence (
                scan_id TEXT NOT NULL, doc_id TEXT NOT NULL, source_json TEXT NOT NULL,
                PRIMARY KEY (scan_id, doc_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS targeted_scan_history (
                scan_id TEXT NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL,
                recorded_at TEXT NOT NULL, details_json TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO targeted_scan_proposals VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, report_id, expected_version, req.event_id, "PENDING_QA",
             timestamp, json.dumps(proposal, ensure_ascii=False)),
        )
        conn.executemany("INSERT INTO targeted_scan_evidence VALUES (?, ?, ?)", evidence_rows)
        for action, actor in (("SCAN_PROPOSED", analyst), ("PRE_SCAN_APPROVED", approver)):
            if actor:
                conn.execute(
                    "INSERT INTO targeted_scan_history VALUES (?, ?, ?, ?, ?)",
                    (scan_id, action, actor, timestamp,
                     json.dumps({"report_id": report_id, "report_version": expected_version,
                                 "event_id": req.event_id}, ensure_ascii=False)),
                )

    return {
        "status": "pending_qa", "scan_id": scan_id, "report_id": report_id,
        "report_version": expected_version, "event_id": req.event_id,
        "query_executed": query, "new_documents_found": len(new_docs),
        "corroborating_count": len(categories["CORROBORATION_CANDIDATE"]),
        "corroboration_candidate_count": len(categories["CORROBORATION_CANDIDATE"]),
        "contradicting_count": len(categories["CONTRADICTION_CANDIDATE"]),
        "related_count": len(categories["RELATED"]),
        "inconclusive_count": len(categories["INCONCLUSIVE"]),
        "irrelevant_count": len(categories["IRRELEVANT"]),
        "validation_status": threat.get("validation_status", "UNSUPPORTED"),
        "confidence_level": threat.get("confidence_level", "LOW"),
        "gap_status": gap.get("status", "OPEN"),
        "evaluated_documents": evaluations, "collector_errors": collection_errors,
        "retrieval_completeness": proposal["retrieval_completeness"],
        "claim_verification": "NOT_PERFORMED", "evidence_promoted": False,
        "review_status": "PENDING_QA", "report_mutated": False,
    }
