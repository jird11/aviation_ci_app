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
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Body, Header, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
)

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
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


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
    }


# Validate the requested scan and hand it to the background pipeline worker.
@app.post("/run-ews")
def run_ews_pipeline(request: EWSRequest):
    # Serialize scan submission and return the active run instead of starting two concurrent pipelines.
    with PIPELINE_LOCK:
        if PIPELINE_STATE["running"]:
            return {"status": "already_running", "run_id": PIPELINE_STATE.get("current_run_id")}

        run_id = f"RUN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        PIPELINE_STATE.update({"running": True, "state": "QUEUED", "current_run_id": run_id})

    threading.Thread(target=_execute_ews_background, args=(request, run_id), daemon=True).start()
    return {"status": "started", "run_id": run_id}


# Request cancellation through the shared pipeline state.
@app.post("/cancel-ews")
def cancel_ews_pipeline():
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
        x_analyst_role: str = Header(default="ANALYST"),
        x_review_key: str = Header(default="", alias="X-Review-Key"),
):
    # Verify authorization and report version before applying a human-review transition.
    """Apply an authenticated analyst decision to a versioned EWS report."""
    expected_key = os.getenv("EWS_REVIEW_KEY", "")
    if not expected_key or not compare_digest(x_review_key, expected_key):
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        role = os.getenv("EWS_REVIEW_ROLE", "ANALYST").upper()
        if role not in {"ANALYST", "APPROVER", "ADMIN"}:
            return JSONResponse(
                status_code=403,
                content={"status": "error",
                         "message": "Insufficient role permissions to approve or reject EWS reports."},
            )

        report_id = payload.get("report_id")
        decision = (payload.get("decision") or "APPROVE").upper()
        if decision not in {"APPROVE", "REJECT"}:
            return JSONResponse(status_code=422, content={
                "status": "invalid_decision", "message": "Decision must be APPROVE or REJECT."
            })
        reviewer_name = payload.get("reviewer_name") or "Senior CI Analyst"
        rationale = payload.get("rationale") or "Reviewed via HITL Gate."
        rejected_ids = payload.get("rejected_event_ids") or []
        client_version = payload.get("version")

        stored_report = None
        if report_id and report_id != "NONE":
            with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,)).fetchone()
                if row:
                    if client_version is not None and int(row["version"]) > int(client_version):
                        return JSONResponse(
                            status_code=409,
                            content={
                                "status": "conflict",
                                "message": f"Version conflict: report was modified (server v{row['version']} vs client v{client_version}). Reload dashboard.",
                            },
                        )
                    stored_report = json.loads(row["report_json"])

        if stored_report is None:
            raise HTTPException(status_code=404, detail="Report not found")

        experiment = (stored_report.get("run_metadata") or {}).get("experiment") or {}
        if experiment.get("replay_run_id"):
            return JSONResponse(
                status_code=409,
                content={"message": "Replay is an experiment; publication is disabled."}
            )

        if rejected_ids:
            stored_report = synchronize_report_consistency(stored_report, rejected_ids)

        stored_report = refresh_threat_reports_dict(stored_report)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_version = int(stored_report.get("version", 1)) + 1
        stored_report["version"] = new_version

        if decision == "APPROVE" and stored_report.get("outcome_status") in {
            "SOURCE_UNAVAILABLE", "ANALYSIS_FAILED", "VALIDATION_FAILED", "INSUFFICIENT_DATA"
        }:
            return JSONResponse(status_code=409, content={
                "status": "review_only",
                "message": "Insufficient evidence or failed analysis cannot be approved as an intelligence report.",
            })

        if decision == "REJECT":
            stored_report["hitl_status"] = "REJECTED"
            governance = (
                (stored_report.get("run_metadata") or {})
                .get("ai_governance")
            )

            # Update the pending review snapshot; direct file writes here are not atomic.
            if isinstance(governance, dict):
                governance["human_review_status"] = stored_report["hitl_status"]
            _save_report_json(PENDING_FILE, stored_report)
        else:
            metadata = stored_report.get("run_metadata") or {}
            qa_performed = (
                    float(metadata.get("qa_duration_sec") or 0) > 0
                    and not metadata.get("qa_failed", False)
                    and not metadata.get("human_feedback_pending_review", False)
            )
            stored_report["hitl_status"] = "APPROVED_BY_HITL_AND_QA" if qa_performed else "APPROVED_BY_HITL_ONLY"

            governance = (
                (stored_report.get("run_metadata") or {})
                .get("ai_governance")
            )

            if isinstance(governance, dict):
                governance["human_review_status"] = stored_report["hitl_status"]

            _save_report_json(FINAL_FILE, stored_report)
            
            append_to_historical_archive(stored_report.get("threats", []))

            if os.path.exists(PENDING_FILE):
                os.remove(PENDING_FILE)

        governance = (
            (stored_report.get("run_metadata") or {})
            .get("ai_governance")
        )
        if governance is not None:
            governance["human_review_status"] = stored_report["hitl_status"]

        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            conn.execute(
                "UPDATE reports SET version = ?, hitl_status = ?, updated_at = ?, report_json = ? WHERE report_id = ?",
                (new_version, stored_report["hitl_status"], now_iso,
                 json.dumps(stored_report, indent=2, ensure_ascii=False), stored_report.get("report_id", "MANUAL")),
            )
            conn.execute(
                "INSERT INTO review_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"DEC_{uuid.uuid4().hex[:8].upper()}", stored_report.get("report_id", "MANUAL"),
                    stored_report.get("run_id", "MANUAL"), new_version, reviewer_name, role,
                    decision, json.dumps(rejected_ids), rationale, now_iso,
                ),
            )
            conn.commit()

        if decision == "APPROVE":
            try:
                from ews_alerts import send_verified_critical_alerts

                alerts_sent = send_verified_critical_alerts(
                    stored_report
                )
                logger.info(
                    "[CRITICAL ALERTS] Emails sent: %s",
                    alerts_sent,
                )
            except Exception as alert_error:
                logger.error(
                    "[CRITICAL ALERTS] Notification failed: %s",
                    alert_error,
                )

        logger.info(
            f"[HITL GATE {decision}] {reviewer_name} ({role}) processed report {stored_report.get('report_id')} (v{new_version}).")
        return {
            "status": decision.lower() + "d",
            "report_id": stored_report.get("report_id"),
            "version": new_version,
            "threats_count": len(stored_report.get("threats", [])),
        }
    except Exception as e:
        logger.error(f"[HITL ERROR] Report approval failed: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


# Persist analyst corrections and invalidate approval where re-review is required.
# Previously issued approval may no longer apply after an analyst edit.
# Feedback may reopen review; it does not independently validate the amended claims.
@app.post("/api/analyst-feedback")
def submit_analyst_feedback(
    req: AnalystFeedbackRequest,
    x_review_key: str = Header(default="", alias="X-Review-Key"),
):
    # Treat analyst feedback as a new reviewable version rather than modifying approved facts silently.
    """Record authorized analyst feedback and require renewed report approval."""
    from tasks import RiskType

    expected_key = os.getenv("EWS_REVIEW_KEY", "")
    if not expected_key or not compare_digest(x_review_key, expected_key):
        raise HTTPException(status_code=403, detail="Unauthorized")

    if os.getenv("EWS_REVIEW_ROLE", "ANALYST").upper() not in {
        "ANALYST", "APPROVER", "ADMIN"
    }:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

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

    if req.corrected_score is not None and not (
        1 <= req.corrected_score <= 10
    ):
        raise HTTPException(status_code=400, detail="Score must be 1–10")

    target_file = _get_active_report_file()
    if not target_file:
        raise HTTPException(status_code=404, detail="No active report")

    rep = _load_report_json(target_file)

    if req.report_id and req.report_id not in {
        "ACTIVE", rep.get("report_id")
    }:
        raise HTTPException(status_code=409, detail="Report ID mismatch")

    event = next(
        (
            t for t in rep.get("threats", [])
            if t.get("event_id") == req.event_id
        ),
        None
    )
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
        rep["version"] = int(rep.get("version", 1)) + 1

    rep["hitl_status"] = "WAITING_FOR_HITL"
    meta = rep.setdefault("run_metadata", {})
    meta["human_feedback_pending_review"] = True
    meta["last_feedback_id"] = fb_id

    rep = refresh_threat_reports_dict(rep)

    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        cur = conn.cursor()

        row = cur.execute(
            "SELECT report_id FROM reports WHERE report_id = ?",
            (rep["report_id"],)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not in database")

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
                (
                    f"KIQ_USR_{uuid.uuid4().hex[:4].upper()}",
                    req.proposed_kiq,
                    req.analyst_name,
                ),
            )

        cur.execute(
            "UPDATE reports SET version = ?, hitl_status = ?, "
            "updated_at = ?, report_json = ? WHERE report_id = ?",
            (
                rep["version"],
                rep["hitl_status"],
                now_iso,
                json.dumps(rep, ensure_ascii=False),
                rep["report_id"],
            )
        )
        conn.commit()

    _save_report_json(PENDING_FILE, rep)

    logger.info(
        "[ANALYST FEEDBACK] %s applied to %s; approval required",
        req.feedback_type,
        req.event_id,
    )

    return {
        "status": "pending_review",
        "feedback_id": fb_id,
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


import ews_evaluation  # noqa: F401
import ews_targeted  # noqa: F401
