# =============================================================================
# aviation_ci_app | FastAPI interface, report review, and diagnostics
#
# Responsibility: Expose dashboard/report endpoints, submit KIT scans, manage HITL decisions, record
#   feedback, and inspect audit logs.
# Design boundary: Delegates orchestration, persistence, and evidence validation to dedicated backend
#   modules.
# =============================================================================

"""FastAPI routes for intelligence monitoring, review, and operational diagnostics."""

import os
import re
import sqlite3
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Body, Header, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from ews_database import append_to_historical_archive, get_active_kiq_catalog
from ews_models import AnalystFeedbackRequest, EWSRequest
from ews_pipeline import _execute_ews_background
from ews_reporting import refresh_threat_reports_dict, synchronize_report_consistency
from ews_state import (
    AEROSPACE_SUPPLIER_REGISTRY,
    DB_LOCK,
    FINAL_FILE,
    LOG_FILE,
    PENDING_FILE,
    PIPELINE_LOCK,
    PIPELINE_STATE,
    SOURCE_REGISTRY,
    SQLITE_DB,
    app,
    compare_digest,
    json,
    logger,
)

# Static dashboard assets and FastAPI route handlers.
app.mount("/static", StaticFiles(directory="static"), name="static")

# Choose the pending HITL report before the published dashboard snapshot.
def _get_active_report_file() -> Optional[str]:
    return PENDING_FILE if os.path.exists(PENDING_FILE) else (FINAL_FILE if os.path.exists(FINAL_FILE) else None)

# Load an existing report without changing its stored fields.
def _load_report_json(filepath: str) -> Dict[str, Any]:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

# Serialize the supplied report snapshot as UTF-8 JSON; versioning is handled by callers.
def _save_report_json(filepath: str, data: Dict[str, Any]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=os.path.dirname(os.path.abspath(filepath)),
            prefix=".ews-report-", suffix=".tmp", delete=False,
        ) as output:
            temporary = output.name
            json.dump(data, output, indent=2, ensure_ascii=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, filepath)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _authorize_review(key: str, role: Optional[str] = None, analyst_id: Optional[str] = None) -> str:
    """Fail closed on missing/placeholder credentials for all review mutations."""
    expected = (os.getenv("EWS_REVIEW_KEY") or "").strip()
    if len(expected) < 16 or expected.upper().startswith(
        ("REPLACE_", "YOUR_", "CHANGEME", "CHANGE_ME", "PLACEHOLDER")
    ):
        raise HTTPException(status_code=503, detail="Review authorization is not configured")
    if not compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Unauthorized")
    configured_role = os.getenv("EWS_REVIEW_ROLE", "ANALYST").strip().upper()
    if configured_role not in {"ANALYST", "APPROVER", "ADMIN"}:
        raise HTTPException(status_code=503, detail="Review role is not configured")
    if role is not None and role.strip().upper() != configured_role:
        raise HTTPException(status_code=403, detail="Insufficient review permissions")
    if analyst_id is not None and not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.@-]{2,79}", analyst_id.strip()
    ):
        raise HTTPException(status_code=422, detail="X-Analyst-ID is required")
    return configured_role


def _qa_complete(metadata: Dict[str, Any]) -> bool:
    try:
        return (float(metadata.get("qa_duration_sec") or 0) > 0
                and not metadata.get("qa_failed")
                and not metadata.get("human_feedback_pending_review"))
    except (TypeError, ValueError):
        return False


def _run_state(report: Dict[str, Any]) -> Dict[str, Any]:
    """Never equate the active worker state with the last published analysis."""
    active_id, report_id = PIPELINE_STATE.get("current_run_id"), report.get("run_id")
    return {
        "active_run_id": active_id,
        "report_run_id": report_id,
        "pipeline_running": bool(PIPELINE_STATE.get("running")),
        "pipeline_state": PIPELINE_STATE.get("state", "IDLE"),
        "report_processing_status": (report.get("run_metadata") or {}).get("processing_status", "UNKNOWN"),
        "analytical_outcome": report.get("outcome_status", "UNKNOWN"),
        "report_is_active_run": report_id == active_id if report_id and active_id else None,
    }


def _review_disposition(report: Dict[str, Any]) -> Dict[str, Any]:
    """Classify review work without changing the persisted HITL workflow."""
    meta = report.get("run_metadata") or {}
    outcome = str(report.get("outcome_status") or "UNKNOWN")
    hitl = str(report.get("hitl_status") or "")
    threats = report.get("threats") or []
    supported = [t for t in threats if t.get("validation_status") == "SUPPORTED"
                 and t.get("program_relevance") == "DIRECT_KIT_MATCH"]

    if (meta.get("experiment") or {}).get("replay_run_id"):
        status, reason = "EXPERIMENT_ONLY", "REPLAY_CANNOT_BE_PUBLISHED"
    elif hitl == "REJECTED":
        status, reason = "REJECTED", "HUMAN_REJECTION"
    elif hitl.startswith("APPROVED"):
        limited = (
                outcome != "COMPLETED"
                or not supported
                or len(supported) != len(threats)
                or meta.get("processing_status") in {"FAILED", "PARTIAL"}
                or not _qa_complete(meta)
                or meta.get("source_coverage_limited")
        )
        status = "APPROVED"
        reason = "HUMAN_APPROVAL_WITH_LIMITATIONS" if limited else "HUMAN_APPROVAL"
    elif outcome in {"SOURCE_UNAVAILABLE", "ANALYSIS_FAILED", "VALIDATION_FAILED"} or meta.get(
            "processing_status") == "FAILED":
        status, reason = "TECHNICAL_PROBLEM", "PROCESSING_OR_SOURCE_FAILURE"
    elif outcome == "INSUFFICIENT_DATA":
        status, reason = "INSUFFICIENT_EVIDENCE", "INSUFFICIENT_DATA"
    elif not threats and not report.get("related_program_watchlist"):
        if (outcome == "PARTIAL_SUCCESS" or meta.get("source_coverage_limited")
                or meta.get("processing_status") == "PARTIAL" or meta.get("documents_failed")):
            status, reason = "INSUFFICIENT_EVIDENCE", "INCOMPLETE_COVERAGE"
        else:
            status, reason = "NO_FINDINGS", "NO_VERIFIED_EVENTS"
    elif outcome not in {"COMPLETED", "PARTIAL_SUCCESS", "NO_RELEVANT_EVENTS"}:
        status, reason = "ANALYST_REVIEW", "OUTCOME_NOT_VERIFIED"
    elif outcome == "NO_RELEVANT_EVENTS":
        status, reason = "ANALYST_REVIEW", "INCONSISTENT_EVENT_CLASSIFICATION"
    elif (outcome == "PARTIAL_SUCCESS" or not supported or len(supported) != len(threats)
          or meta.get("processing_status") == "PARTIAL"
          or not _qa_complete(meta)
          or meta.get("source_coverage_limited")):
        status, reason = "ANALYST_REVIEW", "UNVERIFIED_OR_PARTIAL_EVIDENCE"
    else:
        status, reason = "AWAITING_THREAT_APPROVAL", "VERIFIED_DIRECT_FINDINGS"

    queue = ("THREAT_APPROVAL" if status == "AWAITING_THREAT_APPROVAL"
             else "ANALYST_REVIEW" if status == "ANALYST_REVIEW" else "NONE")
    return {
        "review_status": status, "review_reason": reason, "approval_queue": queue,
        "requires_threat_approval": queue == "THREAT_APPROVAL",
        "requires_analyst_review": queue == "ANALYST_REVIEW",
        "verified_direct_findings": len(supported),
    }


def _source_operational_statuses(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Expose observed connector health separately from search relevance."""
    statuses = {
        sid: {"source_id": sid, "name": cfg.get("name", sid),
              "operational_status": "NOT_OBSERVED", "search_outcome": "NOT_RUN"}
        for sid, cfg in SOURCE_REGISTRY.items()
    }
    for name, record in (report.get("connector_status") or {}).items():
        if not isinstance(record, dict):
            continue
        sid = record.get("source_id") or name
        statuses[sid] = {
            "source_id": sid, "name": name,
            "operational_status": record.get("operational_status") or "UNKNOWN",
            "search_outcome": record.get("last_search_outcome") or "UNKNOWN",
            "http_requests": record.get("http_requests", 0),
            "http_status_counts": record.get("http_status_counts") or {},
            "found_count": record.get("found_count", 0),
            "accepted_count": record.get("accepted_count", 0),
            "errors": record.get("errors") or [],
        }
    return statuses

# Serve the local analyst dashboard HTML.
@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

# Expose the maintained architecture diagram source.
@app.get("/api/architecture.puml", response_class=PlainTextResponse)
def serve_architecture_model():
    """Expose the versioned PlantUML architecture model."""
    with open("architecture.puml", "r", encoding="utf-8") as file:
        return file.read()

# Return the current report together with staleness metadata.
@app.get("/dashboard_data.json")
def serve_data():
    target_file = _get_active_report_file()
    if target_file:
        data = refresh_threat_reports_dict(_load_report_json(target_file))
        data.update(_review_disposition(data))
        data["run_state"] = _run_state(data)
        data["source_operational_statuses"] = _source_operational_statuses(data)
        meta = data.get("run_metadata") or {}
        comp_at = meta.get("completed_at")
        if comp_at:
            try:
                dt = datetime.fromisoformat(comp_at.replace("Z", "+00:00"))
                age_hours = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600.0, 1)
                meta.update({"data_age_hours": age_hours, "is_stale": age_hours > 24.0})
                data["run_metadata"] = meta
            except Exception:
                pass
        return JSONResponse(content=data)

    return {
        "report_id": "NONE", "run_id": "NONE", "version": 1, "outcome_status": "IDLE",
        "executive_summary": "No intelligence data generated yet.",
        "qa_audit_summary": "No quality assurance audit has been executed yet.",
        "hitl_status": "IDLE", "threats": [], "action_plan": [], "kiq_answers": [],
        "run_metadata": None, "comparison_summary": None, "connector_status": {},
        "review_status": "IDLE", "review_reason": "NO_RUN", "approval_queue": "NONE",
        "requires_threat_approval": False, "requires_analyst_review": False,
        "source_operational_statuses": _source_operational_statuses({}),
        "run_state": _run_state({}),
    }


@app.get("/api/review-queue")
def get_review_queue():
    """Keep actionable HITL work separate from operational exceptions."""
    target = _get_active_report_file()
    if not target:
        return {"threat_approvals": [], "analyst_reviews": [], "operational_notices": []}
    report = _load_report_json(target)
    disposition = _review_disposition(report)
    item = {"report_id": report.get("report_id"), "run_id": report.get("run_id"),
            "version": report.get("version"), "outcome_status": report.get("outcome_status"), **disposition}
    queue = disposition["approval_queue"]
    return {
        "threat_approvals": [item] if queue == "THREAT_APPROVAL" else [],
        "analyst_reviews": [item] if queue == "ANALYST_REVIEW" else [],
        "operational_notices": [item] if disposition["review_status"] in {
            "TECHNICAL_PROBLEM", "INSUFFICIENT_EVIDENCE", "NO_FINDINGS", "EXPERIMENT_ONLY"
        } else [],
    }


@app.get("/api/source-status")
def get_source_status():
    target = _get_active_report_file()
    report = _load_report_json(target) if target else {}
    return {"report_id": report.get("report_id"), "run_id": report.get("run_id"),
            "outcome_status": report.get("outcome_status", "UNKNOWN"),
            "sources": _source_operational_statuses(report)}

# Validate the requested scan and hand it to the background pipeline worker.
@app.post("/run-ews")
def run_ews_pipeline(request: EWSRequest):
    # Serialize scan submission and return the active run instead of starting two concurrent pipelines.
    with PIPELINE_LOCK:
        if PIPELINE_STATE["running"]:
            return {"status": "already_running", "run_id": PIPELINE_STATE.get("current_run_id")}

        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:12].upper()}"
        PIPELINE_STATE.update({"running": True, "state": "QUEUED", "current_run_id": run_id,
                               "cancel_requested": False})

    try:
        threading.Thread(target=_execute_ews_background, args=(request, run_id), daemon=True).start()
    except Exception as exc:
        with PIPELINE_LOCK:
            if PIPELINE_STATE.get("current_run_id") == run_id:
                PIPELINE_STATE.update({"running": False, "state": "FAILED",
                                       "last_status": "PIPELINE_START_FAILED"})
        logger.error("[PIPELINE] Worker failed to start: %s", exc)
        raise HTTPException(status_code=503, detail="Pipeline worker could not start") from exc
    return {"status": "started", "run_id": run_id}

# Request cancellation through the shared pipeline state.
@app.post("/cancel-ews")
def cancel_ews_pipeline():
    with PIPELINE_LOCK:
        if PIPELINE_STATE["running"]:
            PIPELINE_STATE["cancel_requested"] = True
            return {"status": "cancelling", "run_id": PIPELINE_STATE.get("current_run_id")}
    return {"status": "not_running"}

# Apply an authorized HITL approval/rejection decision to the pending report.
# Persist human decisions separately from automatic model assessments.
# Authorization and version checks must precede any change to the review record.
@app.post("/approve-ews")
def approve_ews_report(
        payload: Dict[str, Any] = Body(...),
        x_analyst_role: str = Header(default="", alias="X-Review-Role"),
        x_analyst_id: str = Header(default="", alias="X-Analyst-ID"),
        x_review_key: str = Header(default="", alias="X-Review-Key"),
):
    # Verify authorization and report version before applying a human-review transition.
    """Apply an authenticated analyst decision to a versioned EWS report."""
    role = _authorize_review(x_review_key, x_analyst_role, x_analyst_id)

    report_id = str(payload.get("report_id") or "").strip()
    if not report_id or report_id == "NONE":
        raise HTTPException(status_code=422, detail="A report_id is required")
    try:
        client_version = int(payload["version"])
        if client_version < 1 or isinstance(payload["version"], bool):
            raise ValueError("Invalid version")
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="A valid report version is required")

    try:
        if PIPELINE_STATE.get("running"):
            raise HTTPException(status_code=409, detail="A pipeline run is in progress; retry review afterward")
        raw_decision = payload.get("decision") or "APPROVE"
        if not isinstance(raw_decision, str):
            raise HTTPException(status_code=422, detail="Invalid review decision")
        decision = raw_decision.upper()
        if decision not in {"APPROVE", "REJECT"}:
            return JSONResponse(status_code=422, content={
                "status": "invalid_decision", "message": "Decision must be APPROVE or REJECT."
            })
        reviewer_name = x_analyst_id.strip()
        rationale = payload.get("rationale") or "Reviewed via HITL Gate."
        rejected_ids = payload.get("rejected_event_ids") or []
        if not isinstance(rejected_ids, list) or any(not isinstance(i, str) for i in rejected_ids):
            raise HTTPException(status_code=422, detail="Invalid rejected event IDs")
        stored_report = None
        db_run_id = None
        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,)).fetchone()
            if row:
                if int(row["version"]) != client_version:
                    raise HTTPException(status_code=409, detail="Report version changed; reload before review")
                stored_report = json.loads(row["report_json"])
                db_run_id = row["run_id"] if "run_id" in row.keys() else None

        if stored_report is None:
            raise HTTPException(status_code=404, detail="Report not found")
        if stored_report.get("hitl_status") != "WAITING_FOR_HITL":
            raise HTTPException(status_code=409, detail="Report is not awaiting review")
        if (stored_report.get("report_id") != report_id
                or int(stored_report.get("version", 0)) != client_version):
            raise HTTPException(status_code=409, detail="Report identity or version mismatch")
        run_id = stored_report.get("run_id")
        if (not run_id or (db_run_id is not None and db_run_id != run_id)
                or (payload.get("run_id") and payload["run_id"] != run_id)):
            raise HTTPException(status_code=409, detail="Report run identity mismatch")
        if not os.path.isfile(PENDING_FILE):
            raise HTTPException(status_code=409, detail="No active pending review")
        pending = _load_report_json(PENDING_FILE)
        if (pending.get("report_id") != report_id
                or int(pending.get("version", 0)) != client_version
                or pending.get("run_id") != run_id):
            raise HTTPException(status_code=409, detail="Active review changed; reload before review")
        event_ids = {t.get("event_id") for t in stored_report.get("threats") or []}
        if not set(rejected_ids) <= event_ids:
            raise HTTPException(status_code=422, detail="Rejected event does not belong to this report")

        experiment = (stored_report.get("run_metadata") or {}).get("experiment") or {}
        if experiment.get("replay_run_id"):
            return JSONResponse(
                status_code=409,
                content={"message": "Replay is an experiment; publication is disabled."}
            )

        if rejected_ids:
            stored_report = synchronize_report_consistency(stored_report, rejected_ids)

        stored_report = refresh_threat_reports_dict(stored_report)
        metadata = stored_report.setdefault("run_metadata", {})
        disposition = _review_disposition(stored_report)
        has_limited_evidence = (
                stored_report.get("outcome_status") != "COMPLETED"
                or not _qa_complete(metadata)
                or disposition["approval_queue"] != "THREAT_APPROVAL"
        )

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_version = client_version + 1
        stored_report["version"] = new_version

        if decision == "REJECT":
            stored_report["hitl_status"] = "REJECTED"
            metadata["hitl_approval_note"] = "REJECTED_BY_HITL"
        else:
            qa_ran = float(metadata.get("qa_duration_sec") or 0) > 0 and not metadata.get("qa_failed")
            stored_report["hitl_status"] = "APPROVED_BY_HITL_AND_QA" if qa_ran else "APPROVED_BY_HITL"
            metadata["human_feedback_pending_review"] = False
            metadata["hitl_approval_note"] = (
                f"APPROVED_WITH_LIMITED_EVIDENCE ({disposition['review_status']}: {disposition['review_reason']})"
                if has_limited_evidence
                else "APPROVED_STANDARD"
            )
            metadata["hitl_approved_by"] = reviewer_name
            metadata["hitl_approved_at"] = now_iso

        governance = (stored_report.get('run_metadata') or {}).get('ai_governance')
        if isinstance(governance, dict):
            governance["human_review_status"] = stored_report["hitl_status"]

        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            changed = conn.execute(
                "UPDATE reports SET version = ?, hitl_status = ?, updated_at = ?, report_json = ? "
                "WHERE report_id = ? AND version = ? AND hitl_status = 'WAITING_FOR_HITL'",
                (new_version, stored_report["hitl_status"], now_iso,
                 json.dumps(stored_report, indent=2, ensure_ascii=False), report_id, client_version),
            )
            if changed.rowcount != 1:
                raise HTTPException(status_code=409, detail="Report was changed during review")
            conn.execute(
                "INSERT INTO review_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"DEC_{uuid.uuid4().hex[:8].upper()}", stored_report.get("report_id", "MANUAL"),
                    stored_report.get("run_id", "MANUAL"), new_version, reviewer_name, role,
                    decision, json.dumps(rejected_ids), rationale, now_iso,
                ),
            )
            conn.commit()

        if decision == "REJECT":
            _save_report_json(PENDING_FILE, stored_report)
        else:
            _save_report_json(FINAL_FILE, stored_report)
            append_to_historical_archive(stored_report.get("threats", []))
            if os.path.exists(PENDING_FILE):
                current = _load_report_json(PENDING_FILE)
                if (current.get("report_id") == report_id and current.get("run_id") == run_id
                        and int(current.get("version") or 0) == client_version):
                    os.remove(PENDING_FILE)
                else:
                    logger.warning("[HITL] A newer pending report was preserved")

        if decision == "APPROVE":
            try:
                from ews_alerts import send_verified_critical_alerts

                alerts_sent = send_verified_critical_alerts(stored_report)
                logger.info('[CRITICAL ALERTS] Emails sent: %s', alerts_sent)
            except Exception as alert_error:
                logger.error('[CRITICAL ALERTS] Notification failed: %s', alert_error)

        logger.info(
            f"[HITL GATE {decision}] {reviewer_name} ({role}) processed report {stored_report.get('report_id')} (v{new_version}).")
        return {
            "status": "approved" if decision == "APPROVE" else "rejected",
            "report_id": stored_report.get("report_id"),
            "run_id": run_id,
            "version": new_version,
            "threats_count": len(stored_report.get("threats", [])),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[HITL ERROR] Report approval failed: %s", e)
        return JSONResponse(status_code=500, content={
            "status": "error", "message": "Review could not be completed; reload report status."
        })

# Persist analyst corrections and invalidate approval where re-review is required.
# Previously issued approval may no longer apply after an analyst edit.
# Feedback may reopen review; it does not independently validate the amended claims.
@app.post("/api/analyst-feedback")
def submit_analyst_feedback(
    req: AnalystFeedbackRequest,
    x_review_key: str = Header(default="", alias="X-Review-Key"),
    x_review_role: str = Header(default="", alias="X-Review-Role"),
    x_run_id: str = Header(default="", alias="X-Run-ID"),
):
    # Treat analyst feedback as a new reviewable version rather than modifying approved facts silently.
    """Record authorized analyst feedback and require renewed report approval."""
    from tasks import RiskType

    _authorize_review(x_review_key, x_review_role or None)
    if PIPELINE_STATE.get("running"):
        raise HTTPException(status_code=409, detail="A pipeline run is in progress; retry feedback afterward")

    allowed_feedback = {
        "CONFIRM_RELEVANT",
        "DISMISS",
        "CORRECT_RISK_AND_SCORE",
        "FLAG_SOURCE",
        "ADD_MISSING_INFO",
        "PROPOSE_KIQ",
    }

    if req.feedback_type not in allowed_feedback:
        raise HTTPException(status_code=400, detail="Invalid feedback type")

    if req.corrected_risk_type and req.corrected_risk_type not in {
        item.value for item in RiskType
    }:
        raise HTTPException(status_code=400, detail="Invalid risk type")

    if req.corrected_score is not None and (not 1 <= req.corrected_score <= 10):
        raise HTTPException(status_code=400, detail="Score must be 1–10")

    target_file = _get_active_report_file()
    if not target_file:
        raise HTTPException(status_code=404, detail="No active report")

    rep = _load_report_json(target_file)
    report_id, run_id = rep.get("report_id"), rep.get("run_id")
    if not report_id or not run_id or (x_run_id and x_run_id != run_id):
        raise HTTPException(status_code=409, detail="Report run identity is not verified")
    old_version = int(rep.get("version") or 0)
    if old_version < 1:
        raise HTTPException(status_code=409, detail="Report version is invalid")

    if (not req.report_id or req.report_id == 'ACTIVE') and not x_run_id:
        raise HTTPException(status_code=409, detail="A report ID or X-Run-ID is required")
    if req.report_id and req.report_id not in {'ACTIVE', report_id}:
        raise HTTPException(status_code=409, detail="Report ID mismatch")

    event = next((t for t in rep.get('threats', []) if t.get('event_id') == req.event_id), None)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fb_id = f"FB_{uuid.uuid4().hex[:8].upper()}"

    if req.feedback_type == "DISMISS":
        rep = synchronize_report_consistency(rep, [req.event_id])
    else:
        if req.corrected_risk_type:
            event["risk_type"] = req.corrected_risk_type

        if req.corrected_score is not None:
            event["threat_score"] = req.corrected_score
            event["is_critical"] = False
            event["escalation_level"] = "PRIORITY_VERIFICATION_REQUIRED"
            event["score_rationale"] = (
                f"Analyst-proposed severity: {req.corrected_score}/10. "
                "This correction is pending independent review and "
                "does not establish evidentiary support."
            )

        if req.added_missing_info:
            event["missing_data"] = req.added_missing_info

        event["updated_at"] = now_iso

    rep["version"] = old_version + 1

    rep["hitl_status"] = "WAITING_FOR_HITL"
    meta = rep.setdefault("run_metadata", {})
    meta["human_feedback_pending_review"] = True
    meta["last_feedback_id"] = fb_id

    rep = refresh_threat_reports_dict(rep)

    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        cur = conn.cursor()

        row = cur.execute(
            "SELECT version, report_json FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not in database")
        db_report = json.loads(row[1])
        if (int(row[0]) != old_version or db_report.get("report_id") != report_id
                or db_report.get("run_id") != run_id):
            raise HTTPException(status_code=409, detail="Report changed during feedback; reload")

        # Update persisted report projections while retaining feedback and review history.
        cur.execute(
            "INSERT INTO analyst_feedback VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fb_id,
                req.event_id,
                rep["report_id"],
                req.analyst_name,
                req.feedback_type,
                req.corrected_risk_type,
                req.corrected_score,
                req.flagged_source_url,
                req.added_missing_info,
                req.proposed_kiq,
                req.rationale,
                now_iso,
            )
        )

        if req.proposed_kiq:
            cur.execute(
                "INSERT INTO kiq_catalog VALUES "
                "(?, 'KIT_USER', 'Analyst Proposed Intelligence Need', "
                "?, '[]', '[]', '7d', '[]', "
                "'Targeted verification', 'Analyst review', "
                "'HIGH', ?, 0)",
                (f'KIQ_USR_{uuid.uuid4().hex[:4].upper()}', req.proposed_kiq, req.analyst_name),
            )

        cur.execute(
            "UPDATE reports SET version = ?, hitl_status = ?, "
            "updated_at = ?, report_json = ? WHERE report_id = ? AND version = ?",
            (
                rep["version"],
                rep["hitl_status"],
                now_iso,
                json.dumps(rep, ensure_ascii=False),
                report_id, old_version,
            )
        )
        if cur.rowcount != 1:
            raise HTTPException(status_code=409, detail="Report was changed during feedback")
        conn.commit()

    _save_report_json(PENDING_FILE, rep)

    logger.info('[ANALYST FEEDBACK] %s applied to %s; approval required', req.feedback_type, req.event_id)

    return {
        "status": "pending_review",
        "feedback_id": fb_id,
        "report_id": report_id,
        "run_id": run_id,
        "report_version": rep["version"],
        "hitl_status": rep["hitl_status"],
    }

# Expose currently configured strategic questions for UI planning.
@app.get("/api/kiq-catalog")
def get_kiq_catalog_endpoint():
    return {"catalog": get_active_kiq_catalog(), "suppliers": AEROSPACE_SUPPLIER_REGISTRY,
            "sources": list(SOURCE_REGISTRY.values())}

# Return bounded operational diagnostics for the dashboard.
@app.get("/logs")
def get_live_logs():
    lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    return JSONResponse(content={
        "logs": lines[-22:],
        "running": PIPELINE_STATE["running"],
        "last_status": PIPELINE_STATE["last_status"],
        "state": PIPELINE_STATE.get("state", "IDLE"),
        "current_run_id": PIPELINE_STATE.get("current_run_id"),
    })

# Retrieve source-collection exclusions for an individual analysis run.
# Keep source-collection exclusions distinct from semantic-filter decisions.
def _collection_exclusions_for_run(run_id: Optional[str]) -> list[dict]:
    # Explain collection exclusions separately from semantic filter rejections.
    if not run_id or not os.path.isfile(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as stream:
            lines = stream.readlines()
    except (OSError, UnicodeError):
        return []

    marker = f"API REQUEST RECEIVED [{run_id}]"
    starts = [i for i, line in enumerate(lines) if marker in line]
    if not starts:
        return []

    records = []
    seen = set()
    for line in lines[starts[-1] + 1:]:
        if "API REQUEST RECEIVED [" in line:
            break
        line = line.strip()
        title, url, reason, kind = "", "", "", ""
        if "[COMPLIANCE] Skipping " in line:
            payload = line.split("[COMPLIANCE] Skipping ", 1)[1]
            url, _, detail = payload.partition(": ")
            reason, kind = detail or "Collection blocked by compliance rules", "COLLECTION_COMPLIANCE"
        elif "[TDM COMPLIANCE] Respecting HTML meta TDM opt-out on " in line:
            url = line.split("[TDM COMPLIANCE] Respecting HTML meta TDM opt-out on ", 1)[1].strip()
            reason, kind = "Publisher TDM opt-out: document was not extracted", "TDM_OPT_OUT"
        elif "[NEWS API REJECT]" in line:
            payload = line.split("[NEWS API REJECT]", 1)[1].strip()
            match = re.match(r"(.+?),\s*title=['\"](.+)['\"]$", payload)
            reason, title = (match.group(1), match.group(2)) if match else (payload, "")
            kind = "NEWS_API_PRE_FILTER"
        elif "[OSINT DEBUG] Article " in line and " skipped " in line:
            payload = line.split("[OSINT DEBUG] Article ", 1)[1]
            url = payload.split(" ", 1)[0].strip()
            reason, kind = payload[len(url):].strip(), "COLLECTION_SCOPE"
        else:
            continue

        if not url.startswith(("https://", "http://")):
            url = ""
        signature = (kind, url, title, reason)
        if signature in seen:
            continue
        seen.add(signature)
        records.append(
            {"source_url": url, "title": title, "reason": reason, "exclusion_type": kind, "source_stage": "COLLECTION"})
        if len(records) >= 100:
            break
    return records

# Return accepted and excluded source records with filter-stage rationales.
@app.get("/api/filter-audit")
# Expose filter decisions separately from source-collection exclusions for diagnostic analysis.
def get_semantic_filter_audit(run_id: Optional[str] = Query(default=None)):
    """Return accepted and rejected documents from the two-stage semantic filter for Recall evaluation."""
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if run_id:
            rows = [dict(r) for r in cur.execute("SELECT * FROM document_filter_log WHERE run_id = ? ORDER BY doc_id",
                                                 (run_id,)).fetchall()]
        else:
            rows = [dict(r) for r in cur.execute(
                "SELECT * FROM document_filter_log WHERE run_id = (SELECT run_id FROM analytical_runs ORDER BY completed_at DESC LIMIT 1) ORDER BY doc_id").fetchall()]
    return {
        "total_logged": len(rows),
        "accepted_count": sum(1 for r in rows if r.get("is_accepted") == 1),
        "rejected_count": sum(1 for r in rows if r.get("is_accepted") == 0),
        "documents": rows,
        "collection_exclusions": _collection_exclusions_for_run(run_id),
    }

_VALID_FEEDBACK_TARGETS = {"ALL", "PLANNER", "ANALYST", "QA", "EDITOR", "SCORING"}


def _ensure_agent_feedback_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_agent_feedback ("
        "feedback_id TEXT PRIMARY KEY, "
        "target_agent TEXT NOT NULL DEFAULT 'ALL', "
        "instruction TEXT NOT NULL, "
        "active INTEGER NOT NULL DEFAULT 1, "
        "created_at TEXT NOT NULL)"
    )


@app.get("/api/agent-feedback")
def list_agent_feedback():
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        _ensure_agent_feedback_table(conn)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT feedback_id, target_agent, instruction, created_at "
            "FROM user_agent_feedback WHERE active = 1 ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.post("/api/agent-feedback")
def save_agent_feedback(payload: Dict[str, Any] = Body(...)):
    instruction = " ".join(str(payload.get("instruction") or "").split()).strip()
    if len(instruction) < 3:
        raise HTTPException(status_code=422, detail="Feedback text is too short.")
    if len(instruction) > 500:
        instruction = instruction[:500]

    target = str(payload.get("target_agent") or "ALL").strip().upper()
    if target not in _VALID_FEEDBACK_TARGETS:
        target = "ALL"

    fb_id = f"AFB_{uuid.uuid4().hex[:8].upper()}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        _ensure_agent_feedback_table(conn)
        conn.execute(
            "INSERT INTO user_agent_feedback (feedback_id, target_agent, instruction, active, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (fb_id, target, instruction, now_iso),
        )
        conn.commit()
    logger.info("[AGENT FEEDBACK] Saved %s for %s", fb_id, target)
    return {
        "status": "saved",
        "item": {
            "feedback_id": fb_id,
            "target_agent": target,
            "instruction": instruction,
            "created_at": now_iso,
        },
    }


@app.delete("/api/agent-feedback/{feedback_id}")
def delete_agent_feedback(feedback_id: str):
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        _ensure_agent_feedback_table(conn)
        cur = conn.execute(
            "UPDATE user_agent_feedback SET active = 0 WHERE feedback_id = ? AND active = 1",
            (feedback_id.strip(),),
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Feedback item not found.")
    logger.info("[AGENT FEEDBACK] Deactivated %s", feedback_id)
    return {"status": "deleted", "feedback_id": feedback_id}


import ews_evaluation  # noqa: F401
import ews_targeted  # noqa: F401

