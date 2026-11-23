# =============================================================================
# aviation_ci_app | FastAPI interface, report review, and diagnostics
#
# Responsibility: Expose dashboard/report endpoints, submit KIT scans, manage
#   HITL decisions, record feedback, and inspect audit logs.
# Design boundary: Delegates orchestration, persistence, and evidence validation
#   to dedicated backend modules.
# =============================================================================

"""FastAPI routes for intelligence monitoring, review, and operational diagnostics."""

import os
import re
import sqlite3
import tempfile
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Body, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ews_database import append_to_historical_archive, get_active_kiq_catalog
from ews_models import AnalystFeedbackRequest, EWSRequest
from ews_pipeline import _execute_ews_background
from ews_reporting import refresh_threat_reports_dict, synchronize_report_consistency
from ews_state import (
    AEROSPACE_SUPPLIER_REGISTRY, DB_LOCK, FINAL_FILE, LOG_FILE, PENDING_FILE,
    PIPELINE_LOCK, PIPELINE_STATE, SOURCE_REGISTRY, SQLITE_DB, app,
    compare_digest, json, logger,
)

# Static dashboard assets and controlled review/feedback vocabularies.
app.mount("/static", StaticFiles(directory="static"), name="static")

_PLACEHOLDER_PREFIXES = ("REPLACE_", "YOUR_", "CHANGEME", "CHANGE_ME", "PLACEHOLDER")
_VALID_REVIEW_ROLES = {"ANALYST", "APPROVER", "ADMIN"}
_ALLOWED_FEEDBACK_TYPES = {
    "CONFIRM_RELEVANT", "DISMISS", "CORRECT_RISK_AND_SCORE",
    "FLAG_SOURCE", "ADD_MISSING_INFO", "PROPOSE_KIQ",
}
_VALID_FEEDBACK_TARGETS = {"ALL", "PLANNER", "ANALYST", "QA", "EDITOR", "SCORING"}
_OPERATIONAL_NOTICE_STATUSES = {"TECHNICAL_PROBLEM", "INSUFFICIENT_EVIDENCE", "NO_FINDINGS", "EXPERIMENT_ONLY"}


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 Z format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def _db_conn(row_factory: bool = False):
    """Acquire DB_LOCK and open a SQLite connection, optionally returning sqlite3.Row."""
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        if row_factory:
            conn.row_factory = sqlite3.Row
        yield conn


def _require(condition: bool, status_code: int, detail: str) -> None:
    """Raise HTTPException when a precondition fails."""
    if not condition:
        raise HTTPException(status_code=status_code, detail=detail)


def _get_active_report_file() -> Optional[str]:
    """Choose the pending HITL report before the published dashboard snapshot."""
    return PENDING_FILE if os.path.exists(PENDING_FILE) else (FINAL_FILE if os.path.exists(FINAL_FILE) else None)


def _load_report_json(filepath: str) -> Dict[str, Any]:
    """Load an existing JSON report snapshot without mutating its stored fields."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_report_json(filepath: str, data: Dict[str, Any]) -> None:
    """Atomically persist a report snapshot as UTF-8 JSON with fsync."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=os.path.dirname(os.path.abspath(filepath)),
            prefix=".ews-report-", suffix=".tmp", delete=False,
        ) as out:
            temporary = out.name
            json.dump(data, out, indent=2, ensure_ascii=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, filepath)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _authorize_review(key: str, role: Optional[str] = None, analyst_id: Optional[str] = None) -> str:
    """Fail closed on missing/placeholder credentials for all review mutations."""
    expected = (os.getenv("EWS_REVIEW_KEY") or "").strip()
    _require(len(expected) >= 16 and not expected.upper().startswith(_PLACEHOLDER_PREFIXES), 503, "Review authorization is not configured")
    _require(compare_digest(key, expected), 403, "Unauthorized")
    cfg_role = os.getenv("EWS_REVIEW_ROLE", "ANALYST").strip().upper()
    _require(cfg_role in _VALID_REVIEW_ROLES, 503, "Review role is not configured")
    _require(role is None or role.strip().upper() == cfg_role, 403, "Insufficient review permissions")
    _require(analyst_id is None or bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{2,79}", analyst_id.strip())), 422, "X-Analyst-ID is required")
    return cfg_role


def _qa_complete(metadata: Dict[str, Any]) -> bool:
    """Return True only when QA completed cleanly and no analyst feedback awaits review."""
    try:
        return float(metadata.get("qa_duration_sec") or 0) > 0 and not metadata.get("qa_failed") and not metadata.get("human_feedback_pending_review")
    except (TypeError, ValueError):
        return False


def _run_state(report: Dict[str, Any]) -> Dict[str, Any]:
    """Never equate the active worker state with the last published analysis."""
    active_id, report_id = PIPELINE_STATE.get("current_run_id"), report.get("run_id")
    return {
        "active_run_id": active_id, "report_run_id": report_id,
        "pipeline_running": bool(PIPELINE_STATE.get("running")),
        "pipeline_state": PIPELINE_STATE.get("state", "IDLE"),
        "report_processing_status": (report.get("run_metadata") or {}).get("processing_status", "UNKNOWN"),
        "analytical_outcome": report.get("outcome_status", "UNKNOWN"),
        "report_is_active_run": report_id == active_id if report_id and active_id else None,
    }


def _review_disposition(report: Dict[str, Any]) -> Dict[str, Any]:
    """Classify review work without changing the persisted HITL workflow."""
    meta = report.get("run_metadata") or {}
    outcome, hitl = str(report.get("outcome_status") or "UNKNOWN"), str(report.get("hitl_status") or "")
    threats = report.get("threats") or []
    supported = [t for t in threats if t.get("validation_status") == "SUPPORTED" and t.get("program_relevance") == "DIRECT_KIT_MATCH"]
    proc = meta.get("processing_status")
    has_gaps = not supported or len(supported) != len(threats) or not _qa_complete(meta) or bool(meta.get("source_coverage_limited"))

    if (meta.get("experiment") or {}).get("replay_run_id"):
        status, reason = "EXPERIMENT_ONLY", "REPLAY_CANNOT_BE_PUBLISHED"
    elif hitl == "REJECTED":
        status, reason = "REJECTED", "HUMAN_REJECTION"
    elif hitl.startswith("APPROVED"):
        limited = outcome != "COMPLETED" or has_gaps or proc in {"FAILED", "PARTIAL"}
        status, reason = "APPROVED", ("HUMAN_APPROVAL_WITH_LIMITATIONS" if limited else "HUMAN_APPROVAL")
    elif outcome in {"SOURCE_UNAVAILABLE", "ANALYSIS_FAILED", "VALIDATION_FAILED"} or proc == "FAILED":
        status, reason = "TECHNICAL_PROBLEM", "PROCESSING_OR_SOURCE_FAILURE"
    elif outcome == "INSUFFICIENT_DATA":
        status, reason = "INSUFFICIENT_EVIDENCE", "INSUFFICIENT_DATA"
    elif not threats and not report.get("related_program_watchlist"):
        incomplete = outcome == "PARTIAL_SUCCESS" or meta.get("source_coverage_limited") or proc == "PARTIAL" or meta.get("documents_failed")
        status, reason = ("INSUFFICIENT_EVIDENCE", "INCOMPLETE_COVERAGE") if incomplete else ("NO_FINDINGS", "NO_VERIFIED_EVENTS")
    elif outcome not in {"COMPLETED", "PARTIAL_SUCCESS", "NO_RELEVANT_EVENTS"}:
        status, reason = "ANALYST_REVIEW", "OUTCOME_NOT_VERIFIED"
    elif outcome == "NO_RELEVANT_EVENTS":
        status, reason = "ANALYST_REVIEW", "INCONSISTENT_EVENT_CLASSIFICATION"
    elif outcome == "PARTIAL_SUCCESS" or proc == "PARTIAL" or has_gaps:
        status, reason = "ANALYST_REVIEW", "UNVERIFIED_OR_PARTIAL_EVIDENCE"
    else:
        status, reason = "AWAITING_THREAT_APPROVAL", "VERIFIED_DIRECT_FINDINGS"

    queue = "THREAT_APPROVAL" if status == "AWAITING_THREAT_APPROVAL" else ("ANALYST_REVIEW" if status == "ANALYST_REVIEW" else "NONE")
    return {
        "review_status": status, "review_reason": reason, "approval_queue": queue,
        "requires_threat_approval": queue == "THREAT_APPROVAL",
        "requires_analyst_review": queue == "ANALYST_REVIEW",
        "verified_direct_findings": len(supported),
    }


def _source_operational_statuses(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Expose observed connector health separately from search relevance."""
    statuses = {
        sid: {"source_id": sid, "name": cfg.get("name", sid), "operational_status": "NOT_OBSERVED", "search_outcome": "NOT_RUN"}
        for sid, cfg in SOURCE_REGISTRY.items()
    }
    for name, rec in (report.get("connector_status") or {}).items():
        if isinstance(rec, dict):
            sid = rec.get("source_id") or name
            statuses[sid] = {
                "source_id": sid, "name": name,
                "operational_status": rec.get("operational_status") or "UNKNOWN",
                "search_outcome": rec.get("last_search_outcome") or "UNKNOWN",
                "http_requests": rec.get("http_requests", 0),
                "http_status_counts": rec.get("http_status_counts") or {},
                "found_count": rec.get("found_count", 0),
                "accepted_count": rec.get("accepted_count", 0),
                "errors": rec.get("errors") or [],
            }
    return statuses


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the local analyst dashboard HTML."""
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/architecture.puml", response_class=PlainTextResponse)
def serve_architecture_model():
    """Expose the versioned PlantUML architecture model."""
    with open("architecture.puml", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/dashboard_data.json")
def serve_data():
    """Return the active report enriched with review disposition, run state, and staleness."""
    if target := _get_active_report_file():
        data = refresh_threat_reports_dict(_load_report_json(target))
        data.update(_review_disposition(data))
        data["run_state"] = _run_state(data)
        data["source_operational_statuses"] = _source_operational_statuses(data)
        meta = data.get("run_metadata") or {}
        if comp_at := meta.get("completed_at"):
            try:
                age_h = round((datetime.now(timezone.utc) - datetime.fromisoformat(comp_at.replace("Z", "+00:00"))).total_seconds() / 3600.0, 1)
                meta.update({"data_age_hours": age_h, "is_stale": age_h > 24.0})
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
        "source_operational_statuses": _source_operational_statuses({}), "run_state": _run_state({}),
    }


@app.get("/api/review-queue")
def get_review_queue():
    """Keep actionable HITL work separate from operational exceptions."""
    if not (target := _get_active_report_file()):
        return {"threat_approvals": [], "analyst_reviews": [], "operational_notices": []}
    report = _load_report_json(target)
    disp = _review_disposition(report)
    item = {"report_id": report.get("report_id"), "run_id": report.get("run_id"), "version": report.get("version"), "outcome_status": report.get("outcome_status"), **disp}
    q = disp["approval_queue"]
    return {
        "threat_approvals": [item] if q == "THREAT_APPROVAL" else [],
        "analyst_reviews": [item] if q == "ANALYST_REVIEW" else [],
        "operational_notices": [item] if disp["review_status"] in _OPERATIONAL_NOTICE_STATUSES else [],
    }


@app.get("/api/source-status")
def get_source_status():
    """Return observed operational health for all registered connectors."""
    target = _get_active_report_file()
    report = _load_report_json(target) if target else {}
    return {"report_id": report.get("report_id"), "run_id": report.get("run_id"), "outcome_status": report.get("outcome_status", "UNKNOWN"), "sources": _source_operational_statuses(report)}


@app.post("/run-ews")
def run_ews_pipeline(request: EWSRequest):
    """Validate scan submission and start one background pipeline worker at a time."""
    with PIPELINE_LOCK:
        if PIPELINE_STATE["running"]:
            return {"status": "already_running", "run_id": PIPELINE_STATE.get("current_run_id")}
        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:12].upper()}"
        PIPELINE_STATE.update({"running": True, "state": "QUEUED", "current_run_id": run_id, "cancel_requested": False})

    try:
        threading.Thread(target=_execute_ews_background, args=(request, run_id), daemon=True).start()
    except Exception as exc:
        with PIPELINE_LOCK:
            if PIPELINE_STATE.get("current_run_id") == run_id:
                PIPELINE_STATE.update({"running": False, "state": "FAILED", "last_status": "PIPELINE_START_FAILED"})
        logger.error("[PIPELINE] Worker failed to start: %s", exc)
        raise HTTPException(status_code=503, detail="Pipeline worker could not start") from exc
    return {"status": "started", "run_id": run_id}


@app.post("/cancel-ews")
def cancel_ews_pipeline():
    """Signal graceful cancellation through the shared pipeline state."""
    with PIPELINE_LOCK:
        if PIPELINE_STATE["running"]:
            PIPELINE_STATE["cancel_requested"] = True
            return {"status": "cancelling", "run_id": PIPELINE_STATE.get("current_run_id")}
    return {"status": "not_running"}


@app.post("/approve-ews")
def approve_ews_report(
    payload: Dict[str, Any] = Body(...),
    x_analyst_role: str = Header(default="", alias="X-Review-Role"),
    x_analyst_id: str = Header(default="", alias="X-Analyst-ID"),
    x_review_key: str = Header(default="", alias="X-Review-Key"),
):
    """Apply an authenticated analyst approval or rejection to a versioned pending report."""
    role = _authorize_review(x_review_key, x_analyst_role, x_analyst_id)
    report_id = str(payload.get("report_id") or "").strip()
    _require(bool(report_id) and report_id != "NONE", 422, "A report_id is required")
    try:
        raw_ver = payload["version"]
        client_version = int(raw_ver)
        if client_version < 1 or isinstance(raw_ver, bool):
            raise ValueError("Invalid version")
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="A valid report version is required")

    try:
        _require(not PIPELINE_STATE.get("running"), 409, "A pipeline run is in progress; retry review afterward")
        raw_decision = payload.get("decision") or "APPROVE"
        _require(isinstance(raw_decision, str), 422, "Invalid review decision")
        decision = raw_decision.upper()
        if decision not in {"APPROVE", "REJECT"}:
            return JSONResponse(status_code=422, content={"status": "invalid_decision", "message": "Decision must be APPROVE or REJECT."})

        reviewer_name = x_analyst_id.strip()
        rationale = payload.get("rationale") or "Reviewed via HITL Gate."
        rejected_ids = payload.get("rejected_event_ids") or []
        _require(isinstance(rejected_ids, list) and all(isinstance(i, str) for i in rejected_ids), 422, "Invalid rejected event IDs")

        stored_report, db_run_id = None, None
        with _db_conn(row_factory=True) as conn:
            if row := conn.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,)).fetchone():
                _require(int(row["version"]) == client_version, 409, "Report version changed; reload before review")
                stored_report = json.loads(row["report_json"])
                db_run_id = row["run_id"] if "run_id" in row.keys() else None

        _require(stored_report is not None, 404, "Report not found")
        _require(stored_report.get("hitl_status") == "WAITING_FOR_HITL", 409, "Report is not awaiting review")
        _require(stored_report.get("report_id") == report_id and int(stored_report.get("version", 0)) == client_version, 409, "Report identity or version mismatch")
        run_id = stored_report.get("run_id")
        _require(bool(run_id) and (db_run_id is None or db_run_id == run_id) and (not payload.get("run_id") or payload["run_id"] == run_id), 409, "Report run identity mismatch")
        _require(os.path.isfile(PENDING_FILE), 409, "No active pending review")
        pending = _load_report_json(PENDING_FILE)
        _require(pending.get("report_id") == report_id and int(pending.get("version", 0)) == client_version and pending.get("run_id") == run_id, 409, "Active review changed; reload before review")
        _require(set(rejected_ids) <= {t.get("event_id") for t in stored_report.get("threats") or []}, 422, "Rejected event does not belong to this report")
        if ((stored_report.get("run_metadata") or {}).get("experiment") or {}).get("replay_run_id"):
            return JSONResponse(status_code=409, content={"message": "Replay is an experiment; publication is disabled."})

        if rejected_ids:
            stored_report = synchronize_report_consistency(stored_report, rejected_ids)
        stored_report = refresh_threat_reports_dict(stored_report)
        meta = stored_report.setdefault("run_metadata", {})
        disp = _review_disposition(stored_report)
        limited = stored_report.get("outcome_status") != "COMPLETED" or not _qa_complete(meta) or disp["approval_queue"] != "THREAT_APPROVAL"

        now_iso, new_version = _now_iso(), client_version + 1
        stored_report["version"] = new_version
        if decision == "REJECT":
            stored_report["hitl_status"], meta["hitl_approval_note"] = "REJECTED", "REJECTED_BY_HITL"
        else:
            qa_ran = float(meta.get("qa_duration_sec") or 0) > 0 and not meta.get("qa_failed")
            stored_report["hitl_status"] = "APPROVED_BY_HITL_AND_QA" if qa_ran else "APPROVED_BY_HITL"
            meta.update({
                "human_feedback_pending_review": False,
                "hitl_approval_note": f"APPROVED_WITH_LIMITED_EVIDENCE ({disp['review_status']}: {disp['review_reason']})" if limited else "APPROVED_STANDARD",
                "hitl_approved_by": reviewer_name, "hitl_approved_at": now_iso,
            })
        if isinstance(gov := meta.get("ai_governance"), dict):
            gov["human_review_status"] = stored_report["hitl_status"]

        with _db_conn() as conn:
            changed = conn.execute(
                "UPDATE reports SET version = ?, hitl_status = ?, updated_at = ?, report_json = ? "
                "WHERE report_id = ? AND version = ? AND hitl_status = 'WAITING_FOR_HITL'",
                (new_version, stored_report["hitl_status"], now_iso, json.dumps(stored_report, indent=2, ensure_ascii=False), report_id, client_version),
            )
            _require(changed.rowcount == 1, 409, "Report was changed during review")
            conn.execute(
                "INSERT INTO review_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"DEC_{uuid.uuid4().hex[:8].upper()}", stored_report.get("report_id", "MANUAL"),
                 stored_report.get("run_id", "MANUAL"), new_version, reviewer_name, role,
                 decision, json.dumps(rejected_ids), rationale, now_iso),
            )
            conn.commit()

        if decision == "REJECT":
            _save_report_json(PENDING_FILE, stored_report)
        else:
            _save_report_json(FINAL_FILE, stored_report)
            append_to_historical_archive(stored_report.get("threats", []))
            if os.path.exists(PENDING_FILE):
                cur_pend = _load_report_json(PENDING_FILE)
                if cur_pend.get("report_id") == report_id and cur_pend.get("run_id") == run_id and int(cur_pend.get("version") or 0) == client_version:
                    os.remove(PENDING_FILE)
                else:
                    logger.warning("[HITL] A newer pending report was preserved")
            try:
                from ews_alerts import send_verified_critical_alerts
                logger.info("[CRITICAL ALERTS] Emails sent: %s", send_verified_critical_alerts(stored_report))
            except Exception as alert_err:
                logger.error("[CRITICAL ALERTS] Notification failed: %s", alert_err)

        logger.info("[HITL GATE %s] %s (%s) processed report %s (v%s).", decision, reviewer_name, role, stored_report.get("report_id"), new_version)
        return {
            "status": "approved" if decision == "APPROVE" else "rejected",
            "report_id": stored_report.get("report_id"), "run_id": run_id,
            "version": new_version, "threats_count": len(stored_report.get("threats", [])),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("[HITL ERROR] Report approval failed: %s", exc)
        return JSONResponse(status_code=500, content={"status": "error", "message": "Review could not be completed; reload report status."})


@app.post("/api/analyst-feedback")
def submit_analyst_feedback(
    req: AnalystFeedbackRequest,
    x_review_key: str = Header(default="", alias="X-Review-Key"),
    x_review_role: str = Header(default="", alias="X-Review-Role"),
    x_run_id: str = Header(default="", alias="X-Run-ID"),
):
    """Record authorized analyst feedback, bump report version, and require renewed HITL approval."""
    from tasks import RiskType

    _authorize_review(x_review_key, x_review_role or None)
    _require(not PIPELINE_STATE.get("running"), 409, "A pipeline run is in progress; retry feedback afterward")
    _require(req.feedback_type in _ALLOWED_FEEDBACK_TYPES, 400, "Invalid feedback type")
    _require(not req.corrected_risk_type or req.corrected_risk_type in {i.value for i in RiskType}, 400, "Invalid risk type")
    _require(req.corrected_score is None or 1 <= req.corrected_score <= 10, 400, "Score must be 1–10")
    _require(bool(target := _get_active_report_file()), 404, "No active report")

    rep = _load_report_json(target)
    report_id, run_id, old_version = rep.get("report_id"), rep.get("run_id"), int(rep.get("version") or 0)
    _require(bool(report_id and run_id) and (not x_run_id or x_run_id == run_id), 409, "Report run identity is not verified")
    _require(old_version >= 1, 409, "Report version is invalid")
    _require(not ((not req.report_id or req.report_id == "ACTIVE") and not x_run_id), 409, "A report ID or X-Run-ID is required")
    _require(not req.report_id or req.report_id in {"ACTIVE", report_id}, 409, "Report ID mismatch")
    event = next((t for t in rep.get("threats", []) if t.get("event_id") == req.event_id), None)
    _require(event is not None, 404, "Event not found")

    now_iso, fb_id = _now_iso(), f"FB_{uuid.uuid4().hex[:8].upper()}"
    if req.feedback_type == "DISMISS":
        rep = synchronize_report_consistency(rep, [req.event_id])
    else:
        if req.corrected_risk_type:
            event["risk_type"] = req.corrected_risk_type
        if req.corrected_score is not None:
            event.update({
                "threat_score": req.corrected_score, "is_critical": False, "escalation_level": "PRIORITY_VERIFICATION_REQUIRED",
                "score_rationale": f"Analyst-proposed severity: {req.corrected_score}/10. This correction is pending independent review and does not establish evidentiary support.",
            })
        if req.added_missing_info:
            event["missing_data"] = req.added_missing_info
        event["updated_at"] = now_iso

    rep["version"], rep["hitl_status"] = old_version + 1, "WAITING_FOR_HITL"
    rep.setdefault("run_metadata", {}).update({"human_feedback_pending_review": True, "last_feedback_id": fb_id})
    rep = refresh_threat_reports_dict(rep)

    with _db_conn() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT version, report_json FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        _require(row is not None, 404, "Report not in database")
        db_rep = json.loads(row[1])
        _require(int(row[0]) == old_version and db_rep.get("report_id") == report_id and db_rep.get("run_id") == run_id, 409, "Report changed during feedback; reload")
        cur.execute(
            "INSERT INTO analyst_feedback VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (fb_id, req.event_id, rep["report_id"], req.analyst_name, req.feedback_type, req.corrected_risk_type,
             req.corrected_score, req.flagged_source_url, req.added_missing_info, req.proposed_kiq, req.rationale, now_iso),
        )
        if req.proposed_kiq:
            cur.execute(
                "INSERT INTO kiq_catalog VALUES (?, 'KIT_USER', 'Analyst Proposed Intelligence Need', ?, "
                "'[]', '[]', '7d', '[]', 'Targeted verification', 'Analyst review', 'HIGH', ?, 0)",
                (f"KIQ_USR_{uuid.uuid4().hex[:4].upper()}", req.proposed_kiq, req.analyst_name),
            )
        cur.execute(
            "UPDATE reports SET version = ?, hitl_status = ?, updated_at = ?, report_json = ? WHERE report_id = ? AND version = ?",
            (rep["version"], rep["hitl_status"], now_iso, json.dumps(rep, ensure_ascii=False), report_id, old_version),
        )
        _require(cur.rowcount == 1, 409, "Report was changed during feedback")
        conn.commit()

    _save_report_json(PENDING_FILE, rep)
    logger.info("[ANALYST FEEDBACK] %s applied to %s; approval required", req.feedback_type, req.event_id)
    return {"status": "pending_review", "feedback_id": fb_id, "report_id": report_id, "run_id": run_id, "report_version": rep["version"], "hitl_status": rep["hitl_status"]}


@app.get("/api/kiq-catalog")
def get_kiq_catalog_endpoint():
    """Expose active strategic KIQs, supplier registry, and governed sources for UI planning."""
    return {"catalog": get_active_kiq_catalog(), "suppliers": AEROSPACE_SUPPLIER_REGISTRY, "sources": list(SOURCE_REGISTRY.values())}


@app.get("/logs")
def get_live_logs():
    """Return the latest operational log lines and current background worker status."""
    lines = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    return JSONResponse(content={
        "logs": lines[-22:], "running": PIPELINE_STATE["running"],
        "last_status": PIPELINE_STATE["last_status"], "state": PIPELINE_STATE.get("state", "IDLE"),
        "current_run_id": PIPELINE_STATE.get("current_run_id"),
    })


def _collection_exclusions_for_run(run_id: Optional[str]) -> list[dict]:
    """Parse log-based collection exclusions for a run separately from semantic filter rejections."""
    if not run_id or not os.path.isfile(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as stream:
            lines = stream.readlines()
    except (OSError, UnicodeError):
        return []

    starts = [i for i, line in enumerate(lines) if f"API REQUEST RECEIVED [{run_id}]" in line]
    if not starts:
        return []

    records, seen = [], set()
    for raw in lines[starts[-1] + 1:]:
        if "API REQUEST RECEIVED [" in raw:
            break
        line, title, url, reason, kind = raw.strip(), "", "", "", ""
        if "[COMPLIANCE] Skipping " in line:
            url, _, detail = line.split("[COMPLIANCE] Skipping ", 1)[1].partition(": ")
            reason, kind = detail or "Collection blocked by compliance rules", "COLLECTION_COMPLIANCE"
        elif "[TDM COMPLIANCE] Respecting HTML meta TDM opt-out on " in line:
            url = line.split("[TDM COMPLIANCE] Respecting HTML meta TDM opt-out on ", 1)[1].strip()
            reason, kind = "Publisher TDM opt-out: document was not extracted", "TDM_OPT_OUT"
        elif "[NEWS API REJECT]" in line:
            payload = line.split("[NEWS API REJECT]", 1)[1].strip()
            m = re.match(r"(.+?),\s*title=['\"](.+)['\"]$", payload)
            reason, title, kind = (m.group(1), m.group(2), "NEWS_API_PRE_FILTER") if m else (payload, "", "NEWS_API_PRE_FILTER")
        elif "[OSINT DEBUG] Article " in line and " skipped " in line:
            payload = line.split("[OSINT DEBUG] Article ", 1)[1]
            url = payload.split(" ", 1)[0].strip()
            reason, kind = payload[len(url):].strip(), "COLLECTION_SCOPE"
        else:
            continue

        url = url if url.startswith(("https://", "http://")) else ""
        if (sig := (kind, url, title, reason)) not in seen:
            seen.add(sig)
            records.append({"source_url": url, "title": title, "reason": reason, "exclusion_type": kind, "source_stage": "COLLECTION"})
            if len(records) >= 100:
                break
    return records


@app.get("/api/filter-audit")
def get_semantic_filter_audit(run_id: Optional[str] = Query(default=None)):
    """Return accepted and rejected documents from the two-stage semantic filter for Recall evaluation."""
    sql = (
        "SELECT * FROM document_filter_log WHERE run_id = ? ORDER BY doc_id" if run_id
        else "SELECT * FROM document_filter_log WHERE run_id = (SELECT run_id FROM analytical_runs ORDER BY completed_at DESC LIMIT 1) ORDER BY doc_id"
    )
    with _db_conn(row_factory=True) as conn:
        rows = [dict(r) for r in conn.execute(sql, (run_id,) if run_id else ()).fetchall()]
    return {
        "total_logged": len(rows),
        "accepted_count": sum(1 for r in rows if r.get("is_accepted") == 1),
        "rejected_count": sum(1 for r in rows if r.get("is_accepted") == 0),
        "documents": rows, "collection_exclusions": _collection_exclusions_for_run(run_id),
    }


def _ensure_agent_feedback_table(conn: sqlite3.Connection) -> None:
    """Create the user_agent_feedback table on demand if it does not exist."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_agent_feedback ("
        "feedback_id TEXT PRIMARY KEY, target_agent TEXT NOT NULL DEFAULT 'ALL', "
        "instruction TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)"
    )


@app.get("/api/agent-feedback")
def list_agent_feedback():
    """List up to 20 active persistent user instructions for agent stages."""
    with _db_conn(row_factory=True) as conn:
        _ensure_agent_feedback_table(conn)
        rows = conn.execute("SELECT feedback_id, target_agent, instruction, created_at FROM user_agent_feedback WHERE active = 1 ORDER BY created_at DESC LIMIT 20").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.post("/api/agent-feedback")
def save_agent_feedback(payload: Dict[str, Any] = Body(...)):
    """Validate and store a persistent user guidance instruction for an agent stage."""
    instruction = " ".join(str(payload.get("instruction") or "").split()).strip()
    _require(len(instruction) >= 3, 422, "Feedback text is too short.")
    instruction = instruction[:500]
    target = str(payload.get("target_agent") or "ALL").strip().upper()
    target = target if target in _VALID_FEEDBACK_TARGETS else "ALL"
    fb_id, now_iso = f"AFB_{uuid.uuid4().hex[:8].upper()}", _now_iso()

    with _db_conn() as conn:
        _ensure_agent_feedback_table(conn)
        conn.execute("INSERT INTO user_agent_feedback (feedback_id, target_agent, instruction, active, created_at) VALUES (?, ?, ?, 1, ?)", (fb_id, target, instruction, now_iso))
        conn.commit()
    logger.info("[AGENT FEEDBACK] Saved %s for %s", fb_id, target)
    return {"status": "saved", "item": {"feedback_id": fb_id, "target_agent": target, "instruction": instruction, "created_at": now_iso}}


@app.delete("/api/agent-feedback/{feedback_id}")
def delete_agent_feedback(feedback_id: str):
    """Soft-delete an active persistent user instruction by feedback_id."""
    with _db_conn() as conn:
        _ensure_agent_feedback_table(conn)
        cur = conn.execute("UPDATE user_agent_feedback SET active = 0 WHERE feedback_id = ? AND active = 1", (feedback_id.strip(),))
        conn.commit()
        _require(cur.rowcount > 0, 404, "Feedback item not found.")
    logger.info("[AGENT FEEDBACK] Deactivated %s", feedback_id)
    return {"status": "deleted", "feedback_id": feedback_id}


import ews_evaluation  # noqa: F401
import ews_targeted  # noqa: F401