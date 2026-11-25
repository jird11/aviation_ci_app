#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aero_EWS 2.0 — Final Thesis Evaluation & Verification Suite (5 Scenarios x 5 Queries = 25).

Aligned with Chapter 8 of the Master's Thesis:
  - 8.3 Functional & API Contract Testing       (--phase contract)
  - 8.4-8.6, 8.8, 8.10, 8.11 Main 25-Query Run  (--phase main)
  - 8.7 Stability & Repeatability (3x Replay)   (--phase stability)
  - 8.9 Keyword Baseline Comparison (Replay)    (--phase baseline)
  - Export Thesis Tables & Annotation Templates (--phase export)
  - Compute Final Precision/Recall/F1/MAE       (--phase score)

Uses Python standard library only (urllib, sqlite3, csv, json).
Run from the Aero_EWS project root while `python main.py` is running on http://127.0.0.1:8000.

Examples:
  python run_final_thesis_suite-v2.py --list
  python run_final_thesis_suite-v2.py --phase contract
  python run_final_thesis_suite-v2.py --phase main --scenarios S1 --limit 6
  python run_final_thesis_suite-v2.py --phase main --resume --limit 6
  python run_final_thesis_suite-v2.py --phase stability
  python run_final_thesis_suite-v2.py --phase baseline
  python run_final_thesis_suite-v2.py --phase export
  python run_final_thesis_suite-v2.py --phase score
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SQLITE_DB = Path("ews_intelligence.db")
OUT_DIR = Path("thesis_eval_results")
STATE_FILE = OUT_DIR / "suite_state.json"


@dataclass(frozen=True)
class TestQuery:
    query_id: str
    scenario_id: str
    scenario_name: str
    kit_ref: str
    kiq_ref: str
    query: str
    scope: str
    platforms: tuple[str, ...]
    expected_risk_type: str
    expected_behavior: str
    test_role: str  # POSITIVE | IMPROVEMENT | NEGATIVE_CONTROL | CROSS_VARIANT | UNVERIFIED_SOCIAL | RETROSPECTIVE
    as_of_date: str = ""
    date_from: str = ""
    date_to: str = ""


# 5 Scenarios x 5 Queries = 25 Thesis Evaluation Queries (100% English)
THESIS_QUERIES: List[TestQuery] = [
    # --- SCENARIO 1: Supply Chain, Production & Critical Components (KIT 1 / KIQ 1.1 & 1.2) ---
    TestQuery(
        "S1-Q1", "S1", "Supply Chain, Production & Critical Components", "KIT_1", "KIQ_1_1",
        "Airbus A320neo production rate ramp-up and engine delivery delays",
        "365d", ("news", "regulatory", "pr"), "SUPPLY_CHAIN",
        "Capture A320neo production rate status and engine delivery bottlenecks without conflating unrelated programs.",
        "POSITIVE",
    ),
    TestQuery(
        "S1-Q2", "S1", "Supply Chain, Production & Critical Components", "KIT_1", "KIQ_1_1 / KIQ_1_2",
        "Spirit AeroSystems Boeing 737 and Airbus A220 aerostructures production transition",
        "365d", ("news", "regulatory", "pr"), "SUPPLY_CHAIN",
        "Track operational impacts of the Spirit AeroSystems acquisition/transition (Dec 2025) across Boeing and Airbus lines.",
        "POSITIVE",
    ),
    TestQuery(
        "S1-Q3", "S1", "Supply Chain, Production & Critical Components", "KIT_1", "KIQ_1_2",
        "Safran CFM LEAP engine casting and forging supply constraints",
        "365d", ("news", "regulatory", "pr"), "SUPPLY_CHAIN",
        "Identify Tier 1/2 casting and forging bottlenecks at Safran/CFM while separating confirmed facts from hypothetical impact.",
        "POSITIVE",
    ),
    TestQuery(
        "S1-Q4", "S1", "Supply Chain, Production & Critical Components", "KIT_1", "KIQ_1_1 / KIQ_1_2",
        "Airbus A350 cabin interior and landing gear supplier bottlenecks",
        "365d", ("news", "pr"), "SUPPLY_CHAIN",
        "Verify detection of Airbus widebody cabin/landing-gear supplier constraints and accurate SCM tier assignment.",
        "POSITIVE",
    ),
    TestQuery(
        "S1-Q5", "S1", "Supply Chain, Production & Critical Components", "KIT_1", "KIQ_1_2",
        "Aerospace titanium and specialty alloy raw material supply risks",
        "365d", ("news", "pr"), "GEOPOLITICAL",
        "Capture Tier 3 raw material and titanium supply risks without extrapolating unverified OEM assembly line halts.",
        "POSITIVE",
    ),

    # --- SCENARIO 2: Aircraft Certification, Regulation & Airworthiness (KIT 3 / KIQ 3.1) ---
    TestQuery(
        "S2-Q1", "S2", "Aircraft Certification, Regulation & Airworthiness", "KIT_3", "KIQ_3_1",
        "Boeing 777X FAA certification and GE9X engine status",
        "365d", ("news", "regulatory", "pr"), "REGULATORY",
        "Cover dual tracks—airframe (FAA TIA/ETOPS) and engine (GE9X mid-seal)—keeping issuer filings distinct from FAA rulings.",
        "POSITIVE",
    ),
    TestQuery(
        "S2-Q2", "S2", "Aircraft Certification, Regulation & Airworthiness", "KIT_3", "KIQ_3_1",
        "Boeing 737 MAX 7 and MAX 10 FAA certification status",
        "365d", ("news", "regulatory", "pr"), "REGULATORY",
        "Preserve exact 737-7 and 737-10 variant scope and accurately reflect current certification status.",
        "POSITIVE",
    ),
    TestQuery(
        "S2-Q3", "S2", "Aircraft Certification, Regulation & Airworthiness", "KIT_3", "KIQ_3_1",
        "CFM LEAP-1A high pressure turbine blade FAA EASA airworthiness directives",
        "365d", ("regulatory", "news", "pr"), "REGULATORY",
        "Distinguish NPRM proposals, final issued ADs, and effective dates strictly for the LEAP-1A variant.",
        "POSITIVE",
    ),
    TestQuery(
        "S2-Q4", "S2", "Aircraft Certification, Regulation & Airworthiness", "KIT_3", "KIQ_3_1",
        "COMAC C919 EASA type certification progress in Europe",
        "365d", ("regulatory", "news", "pr"), "REGULATORY",
        "Track European EASA validation progress for C919 without conflating Chinese CAAC approval with EASA certification.",
        "POSITIVE",
    ),
    TestQuery(
        "S2-Q5", "S2", "Aircraft Certification, Regulation & Airworthiness", "KIT_3", "KIQ_3_1",
        "Airbus A321XLR EASA and FAA certification and operational conditions",
        "365d", ("regulatory", "news", "pr"), "REGULATORY",
        "Recognize completed certification milestones and operating conditions for A321XLR without false crisis escalation.",
        "IMPROVEMENT",
    ),

    # --- SCENARIO 3: Engine Technical Defects, Durability & MRO (KIT 1 & KIT 3) ---
    TestQuery(
        "S3-Q1", "S3", "Engine Technical Defects, Durability & MRO", "KIT_1 / KIT_3", "KIQ_1_2 / KIQ_3_1",
        "Pratt & Whitney PW1100G powdered metal inspection and Airbus A320neo AOG impact",
        "365d", ("regulatory", "news", "pr"), "TECHNICAL_QUALITY",
        "Capture root cause (powdered metal), mandatory inspection scope, and evidenced A320neo fleet AOG impact.",
        "POSITIVE",
    ),
    TestQuery(
        "S3-Q2", "S3", "Engine Technical Defects, Durability & MRO", "KIT_1 / KIT_3", "KIQ_1_2 / KIQ_3_1",
        "Rolls-Royce Trent XWB durability and Airbus A350 maintenance inspections",
        "365d", ("regulatory", "news", "pr"), "TECHNICAL_QUALITY",
        "Identify Trent XWB durability and MRO inspection findings (including harsh/dusty operating environments) on A350.",
        "POSITIVE",
    ),
    TestQuery(
        "S3-Q3", "S3", "Engine Technical Defects, Durability & MRO", "KIT_1 / KIT_3", "KIQ_1_2 / KIQ_3_1",
        "Airbus A220 Pratt & Whitney PW1500G engine durability and grounding",
        "365d", ("regulatory", "news", "pr"), "TECHNICAL_QUALITY",
        "Capture A220/PW1500G fleet impacts and verify strict separation from PW1100G (A320neo) evidence.",
        "POSITIVE",
    ),
    TestQuery(
        "S3-Q4", "S3", "Engine Technical Defects, Durability & MRO", "KIT_1 / KIT_3", "KIQ_1_2 / KIQ_3_1",
        "GE Aerospace GE9X mid-seal durability issue and ETOPS testing impact",
        "365d", ("regulatory", "news", "pr"), "TECHNICAL_QUALITY",
        "Verify component-level extraction (mid-seal), ETOPS schedule link, and SEC 10-Q disclosure vs. FAA approval.",
        "POSITIVE",
    ),
    TestQuery(
        "S3-Q5", "S3", "Engine Technical Defects, Durability & MRO", "KIT_1 / KIT_3", "KIQ_3_1",
        "Rolls-Royce Trent 1000 durability upgrade package Boeing 787",
        "365d", ("regulatory", "news", "pr"), "TECHNICAL_QUALITY",
        "Recognize corrective upgrade/durability improvement milestone without misclassifying it as a new grounding crisis.",
        "IMPROVEMENT",
    ),

    # --- SCENARIO 4: Competitive Environment, Orders, Airshows & Tech/SAF Trends (KIT 2 & KIT 3) ---
    TestQuery(
        "S4-Q1", "S4", "Competitive Environment, Orders, Airshows & Tech/SAF Trends", "KIT_2", "KIQ_2_2",
        "Airbus aircraft orders and major fleet contracts announcements",
        "90d", ("airshow", "news", "pr"), "COMPETITIVE",
        "Classify major Airbus fleet contracts as COMPETITIVE (not SUPPLY_CHAIN) and distinguish firm orders from MoUs.",
        "POSITIVE",
    ),
    TestQuery(
        "S4-Q2", "S4", "Competitive Environment, Orders, Airshows & Tech/SAF Trends", "KIT_2", "KIQ_2_2",
        "Boeing widebody aircraft orders and customer delivery reshuffling",
        "90d", ("airshow", "news", "pr"), "COMPETITIVE",
        "Capture Boeing widebody order activity and any customer delivery slot reshuffling or deferrals.",
        "POSITIVE",
    ),
    TestQuery(
        "S4-Q3", "S4", "Competitive Environment, Orders, Airshows & Tech/SAF Trends", "KIT_2", "KIQ_2_1 / KIQ_2_2",
        "Embraer E2 and COMAC C919 commercial orders and market expansion",
        "365d", ("airshow", "news", "pr"), "COMPETITIVE",
        "Track commercial expansion and orderbook momentum of non-duopoly challengers (Embraer, COMAC).",
        "POSITIVE",
    ),
    TestQuery(
        "S4-Q4", "S4", "Competitive Environment, Orders, Airshows & Tech/SAF Trends", "KIT_2 / KIT_3", "KIQ_2_1 / KIQ_3_2",
        "Airbus ZEROe hydrogen aircraft program development timeline and delays",
        "365d", ("news", "pr", "regulatory"), "ENVIRONMENTAL_TECHNOLOGICAL",
        "Assess strategic technology roadmap updates and schedule shifts for the Airbus ZEROe hydrogen program.",
        "POSITIVE",
    ),
    TestQuery(
        "S4-Q5", "S4", "Competitive Environment, Orders, Airshows & Tech/SAF Trends", "KIT_3", "KIQ_3_2",
        "Sustainable Aviation Fuel SAF availability and ReFuelEU Aviation compliance impact",
        "365d", ("regulatory", "news", "pr"), "ENVIRONMENTAL_TECHNOLOGICAL",
        "Cover SAF supply constraints, pricing dynamics, and ReFuelEU Aviation regulatory compliance impacts.",
        "POSITIVE",
    ),

    # --- SCENARIO 5: Boundary Tests, Negative Controls, Unverified Signals & Retrospective ---
    TestQuery(
        "S5-Q1", "S5", "Boundary Tests, Negative Controls, Unverified Signals & Retrospective", "CONTROL", "NFR02",
        "Airbus A380 new commercial production line launch",
        "90d", ("news", "pr", "regulatory"), "NONE",
        "Negative control #1: A380 production ended; expect 0 confirmed critical alerts and zero fabricated events.",
        "NEGATIVE_CONTROL",
    ),
    TestQuery(
        "S5-Q2", "S5", "Boundary Tests, Negative Controls, Unverified Signals & Retrospective", "CONTROL", "NFR02",
        "Boeing 747-8 passenger variant FAA new type certification 2026",
        "90d", ("regulatory", "news", "pr"), "NONE",
        "Negative control #2: discontinued passenger variant; must not hallucinate a new 2026 certification event.",
        "NEGATIVE_CONTROL",
    ),
    TestQuery(
        "S5-Q3", "S5", "Boundary Tests, Negative Controls, Unverified Signals & Retrospective", "CONTROL", "NFR01",
        "Airbus A320neo CFM LEAP-1B engine defect",
        "365d", ("regulatory", "news", "pr"), "NONE",
        "Cross-variant guard test: LEAP-1B powers 737 MAX, not A320neo (LEAP-1A); FR03/Harness must block direct KIT match.",
        "CROSS_VARIANT",
    ),
    TestQuery(
        "S5-Q4", "S5", "Boundary Tests, Negative Controls, Unverified Signals & Retrospective", "CONTROL", "FR11 / NFR02",
        "Boeing 777X production rumors and unverified airline cancellation speculation",
        "30d", ("bluesky", "youtube", "news"), "REGULATORY",
        "Unverified community source test: social/video rumors must never trigger CRITICAL_CONFIRMED_ALERT.",
        "UNVERIFIED_SOCIAL",
    ),
    TestQuery(
        "S5-Q5", "S5", "Boundary Tests, Negative Controls, Unverified Signals & Retrospective", "KIT_3", "Ch. 8.11 (Timeliness)",
        "Boeing 777X FAA certification and GE9X engine status",
        "365d", ("news", "regulatory", "pr"), "REGULATORY",
        "Retrospective point-in-time test as of 2026-06-30: zero documents published after 2026-06-30 may leak into analysis.",
        "RETROSPECTIVE",
        as_of_date="2026-06-30",
    ),
]

STABILITY_ANCHORS = ("S1-Q1", "S2-Q1", "S3-Q1")
BASELINE_ANCHORS = ("S1-Q1", "S2-Q1", "S3-Q1", "S4-Q1", "S5-Q1")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _http_json(base_url: str, method: str, path: str, payload: Optional[dict] = None,
               headers: Optional[dict] = None, timeout: float = 30.0) -> tuple[int, Any]:
    url = base_url.rstrip("/") + path
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req_headers = {"Accept": "application/json"}
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    req = Request(url, data=body, headers=req_headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except HTTPError as err:
        raw = err.read().decode("utf-8", errors="replace")
        try:
            return err.code, json.loads(raw)
        except json.JSONDecodeError:
            return err.code, raw
    except URLError as err:
        return 0, f"URLError: {err.reason}"


def _load_state() -> Dict[str, Any]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"contract_tests": [], "main_runs": {}, "stability_runs": {}, "baseline_runs": {}}


def _save_state(state: Dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def _wait_for_run(base_url: str, run_id: str, timeout_sec: int = 600) -> str:
    deadline = time.monotonic() + timeout_sec
    last_state = "QUEUED"
    while time.monotonic() < deadline:
        code, data = _http_json(base_url, "GET", "/logs", timeout=10.0)
        if code == 200 and isinstance(data, dict):
            running = bool(data.get("running"))
            cur_id = str(data.get("current_run_id") or "")
            last_state = str(data.get("state") or last_state)
            if not running and (cur_id == run_id or cur_id == "" or last_state in {"COMPLETED", "FAILED", "CANCELLED", "IDLE"}):
                return last_state
        time.sleep(3.0)
    raise TimeoutError(f"Run {run_id} did not finish within {timeout_sec}s (last_state={last_state})")


def _wait_until_idle(base_url: str, timeout_sec: int = 120) -> None:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        code, data = _http_json(base_url, "GET", "/logs", timeout=10.0)
        if code == 200 and isinstance(data, dict) and not data.get("running"):
            return
        time.sleep(2.0)
    raise TimeoutError("Server pipeline remained busy.")


def _fetch_report_from_db(run_id: str) -> Optional[Dict[str, Any]]:
    if not SQLITE_DB.is_file():
        return None
    with sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT report_json FROM reports WHERE run_id = ?", (run_id,)).fetchone()
        if row and row["report_json"]:
            return json.loads(row["report_json"])
    return None


def _run_single_scan(base_url: str, payload: Dict[str, Any], timeout_sec: int = 600) -> tuple[str, str, Optional[Dict[str, Any]]]:
    _wait_until_idle(base_url, timeout_sec=120)
    code, data = _http_json(base_url, "POST", "/run-ews", payload=payload, timeout=25.0)
    if code != 200 or not isinstance(data, dict) or data.get("status") != "started":
        raise RuntimeError(f"POST /run-ews failed (HTTP {code}): {data}")
    run_id = str(data["run_id"])
    final_state = _wait_for_run(base_url, run_id, timeout_sec=timeout_sec)
    time.sleep(1.0)
    report = _fetch_report_from_db(run_id)
    if report:
        run_dir = OUT_DIR / "reports"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{run_id}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return run_id, final_state, report


# =============================================================================
# PHASE 1: Functional & API Contract Tests (Chapter 8.3)
# =============================================================================
def run_contract_phase(base_url: str, state: Dict[str, Any]) -> int:
    results: List[Dict[str, Any]] = []

    def record(tid: str, area: str, expected: str, ok: bool, actual: str) -> None:
        status = "PASS" if ok else "FAIL"
        results.append({
            "test_id": tid, "area": area, "expected": expected,
            "actual": actual, "status": status, "timestamp": _now_iso(),
        })
        print(f"[{status:4}] {tid} ({area}): {actual}")

    reg_script = Path("ews_final_regression.py")
    if reg_script.is_file():
        proc = subprocess.run([sys.executable, str(reg_script), "--smoke-import"], capture_output=True, text=True, timeout=120)
        ok = proc.returncode == 0
        tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-1:] or ["(no output)"]
        record("T01", "Offline smoke-import & contracts", "Zero exit code with no import or schema errors", ok, f"rc={proc.returncode}; {tail[0][:120]}")
    else:
        record("T01", "Offline smoke-import & contracts", "Execute ews_final_regression.py", False, "File ews_final_regression.py not found")

    c_root, _ = _http_json(base_url, "GET", "/")
    c_puml, puml_body = _http_json(base_url, "GET", "/api/architecture.puml")
    record("T02", "Dashboard & UML availability", "HTTP 200 for / and /api/architecture.puml",
           c_root == 200 and c_puml == 200 and "@startuml" in str(puml_body),
           f"GET /={c_root}, GET /api/architecture.puml={c_puml}")

    c_cat, cat_data = _http_json(base_url, "GET", "/api/kiq-catalog")
    c_src, _ = _http_json(base_url, "GET", "/api/source-status")
    kiq_n = len((cat_data or {}).get("kiq_catalog", [])) if isinstance(cat_data, dict) else 0
    record("T03", "KIQ catalog & connector status", "HTTP 200 with active KIQ catalog and connector status",
           c_cat == 200 and c_src == 200 and kiq_n >= 5,
           f"/api/kiq-catalog={c_cat} (KIQ={kiq_n}), /api/source-status={c_src}")

    c_empty, _ = _http_json(base_url, "POST", "/run-ews", payload={"query": "   ", "scope": "30d", "platforms": ["news"], "limit": 5})
    record("T04", "Input validation — blank KIT", "Rejected with HTTP 422", c_empty == 422, f"HTTP {c_empty}")

    c_date, _ = _http_json(base_url, "POST", "/run-ews", payload={
        "query": "Airbus A320neo", "scope": "custom", "date_from": "2026-10-10", "date_to": "2026-09-01",
        "platforms": ["news"], "limit": 5,
    })
    record("T05", "Input validation — inverted dates", "Rejected with HTTP 422", c_date == 422, f"HTTP {c_date}")

    c_plat, _ = _http_json(base_url, "POST", "/run-ews", payload={
        "query": "Airbus A320neo", "scope": "30d", "platforms": ["invalid_platform_xyz"], "limit": 5,
    })
    record("T06", "Input validation — unknown platform", "Rejected with HTTP 422", c_plat == 422, f"HTTP {c_plat}")

    c_auth, _ = _http_json(base_url, "POST", "/approve-ews", payload={"decision": "APPROVED"}, headers={"X-Review-Key": "wrong_key"})
    record("T07", "HITL authorization — unauthorized approval", "Fail-closed rejection (HTTP 401/403/422/503)",
           c_auth in {401, 403, 422, 503}, f"HTTP {c_auth}")

    c_log, log_data = _http_json(base_url, "GET", "/logs")
    c_fa, _ = _http_json(base_url, "GET", "/api/filter-audit")
    record("T08", "Runtime diagnostics & FR03 audit", "HTTP 200 for /logs and /api/filter-audit",
           c_log == 200 and c_fa == 200 and isinstance(log_data, dict) and "state" in log_data,
           f"/logs={c_log} (state={log_data.get('state') if isinstance(log_data, dict) else '?'}), /api/filter-audit={c_fa}")

    state["contract_tests"] = results
    _save_state(state)
    _export_functional_md(results)
    failed = sum(1 for r in results if r["status"] != "PASS")
    print(f"[CONTRACT DONE] {len(results) - failed}/{len(results)} passed.")
    return 0 if failed == 0 else 1


# =============================================================================
# PHASE 2: Main 25-Query Evaluation Run (5 Scenarios x 5 Queries)
# =============================================================================
def run_main_phase(base_url: str, state: Dict[str, Any], selected: List[TestQuery], limit: int, resume: bool, timeout_sec: int) -> int:
    main_runs = state.setdefault("main_runs", {})
    failures = 0
    for idx, tq in enumerate(selected, 1):
        if resume and tq.query_id in main_runs and main_runs[tq.query_id].get("run_id") and main_runs[tq.query_id].get("state") != "FAILED":
            print(f"[SKIP {idx:02d}/{len(selected):02d}] {tq.query_id} already completed: {main_runs[tq.query_id]['run_id']}")
            continue

        payload: Dict[str, Any] = {
            "query": tq.query,
            "scope": tq.scope,
            "platforms": list(tq.platforms),
            "limit": limit,
            "collection_mode": "agentic_exa",
            "auto_approve": False,
            "use_keyword_baseline": False,
        }
        if tq.as_of_date:
            payload["as_of_date"] = tq.as_of_date
        if tq.date_from:
            payload["date_from"] = tq.date_from
        if tq.date_to:
            payload["date_to"] = tq.date_to

        print(f"\n[MAIN {idx:02d}/{len(selected):02d}] {tq.query_id} ({tq.test_role}) | {tq.query} [scope={tq.scope}, as_of={tq.as_of_date or 'LIVE'}]")
        try:
            run_id, final_state, report = _run_single_scan(base_url, payload, timeout_sec=timeout_sec)
            meta = (report or {}).get("run_metadata") or {}
            print(
                f"  -> {run_id} | state={final_state} | outcome={(report or {}).get('outcome_status')} "
                f"| docs={meta.get('documents_collected')}/{meta.get('documents_analyzed')} "
                f"| threats={len((report or {}).get('threats') or [])} "
                f"| crit={meta.get('confirmed_critical_count')} | cost=${meta.get('estimated_cost_usd')}"
            )
            main_runs[tq.query_id] = {
                "run_id": run_id,
                "state": final_state,
                "completed_at": _now_iso(),
                "payload": payload,
            }
            _save_state(state)
        except Exception as exc:
            failures += 1
            print(f"  -> ERROR {tq.query_id}: {exc}", file=sys.stderr)
            main_runs[tq.query_id] = {"run_id": None, "state": "FAILED", "error": str(exc), "completed_at": _now_iso()}
            _save_state(state)
    return 0 if failures == 0 else 1


# =============================================================================
# PHASE 3: Stability & Repeatability via replay_run_id (Chapter 8.7)
# =============================================================================
def run_stability_phase(base_url: str, state: Dict[str, Any], anchors: List[str], repeats: int, limit: int, timeout_sec: int) -> int:
    main_runs = state.get("main_runs") or {}
    stab_runs = state.setdefault("stability_runs", {})
    q_by_id = {q.query_id: q for q in THESIS_QUERIES}

    for qid in anchors:
        base_info = main_runs.get(qid)
        if not base_info or not base_info.get("run_id"):
            print(f"[STABILITY SKIP] {qid} has no completed main run_id yet.")
            continue
        source_run_id = base_info["run_id"]
        tq = q_by_id[qid]
        existing = stab_runs.setdefault(qid, [source_run_id])
        if source_run_id not in existing:
            existing.insert(0, source_run_id)

        while len(existing) < repeats:
            rep_no = len(existing) + 1
            payload = {
                "query": tq.query,
                "scope": tq.scope,
                "platforms": list(tq.platforms),
                "limit": limit,
                "collection_mode": "agentic_exa",
                "replay_run_id": source_run_id,
                "auto_approve": False,
                "use_keyword_baseline": False,
            }
            if tq.as_of_date:
                payload["as_of_date"] = tq.as_of_date
            print(f"[STABILITY] {qid} repeat {rep_no}/{repeats} replaying {source_run_id}...")
            try:
                rid, st, _ = _run_single_scan(base_url, payload, timeout_sec=timeout_sec)
                print(f"  -> {rid} ({st})")
                existing.append(rid)
                _save_state(state)
            except Exception as exc:
                print(f"  -> FAILED stability repeat for {qid}: {exc}", file=sys.stderr)
                break
    return 0


# =============================================================================
# PHASE 4: Keyword Baseline Comparison via replay_run_id (Chapter 8.9)
# =============================================================================
def run_baseline_phase(base_url: str, state: Dict[str, Any], anchors: List[str], limit: int, timeout_sec: int) -> int:
    main_runs = state.get("main_runs") or {}
    base_runs = state.setdefault("baseline_runs", {})
    q_by_id = {q.query_id: q for q in THESIS_QUERIES}

    for qid in anchors:
        base_info = main_runs.get(qid)
        if not base_info or not base_info.get("run_id"):
            print(f"[BASELINE SKIP] {qid} has no completed main run_id yet.")
            continue
        if base_runs.get(qid):
            print(f"[BASELINE SKIP] {qid} already has baseline run {base_runs[qid]}")
            continue
        source_run_id = base_info["run_id"]
        tq = q_by_id[qid]
        payload = {
            "query": tq.query,
            "scope": tq.scope,
            "platforms": list(tq.platforms),
            "limit": limit,
            "collection_mode": "agentic_exa",
            "replay_run_id": source_run_id,
            "auto_approve": False,
            "use_keyword_baseline": True,
        }
        if tq.as_of_date:
            payload["as_of_date"] = tq.as_of_date
        print(f"[BASELINE] {qid} running Keyword Baseline over replay {source_run_id}...")
        try:
            rid, st, _ = _run_single_scan(base_url, payload, timeout_sec=timeout_sec)
            print(f"  -> {rid} ({st})")
            base_runs[qid] = rid
            _save_state(state)
        except Exception as exc:
            print(f"  -> FAILED baseline for {qid}: {exc}", file=sys.stderr)
    return 0


# =============================================================================
# PHASE 5: Export All Thesis Tables & Manual Annotation Templates
# =============================================================================
def _export_functional_md(results: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 8.3 Functional and API Contract Testing — Aero_EWS 2.0",
        "",
        "| Test ID | Area | Expected Result | Actual Result | Status |",
        "| :--- | :--- | :--- | :--- | :---: |",
    ]
    for r in results:
        lines.append(f"| {r['test_id']} | {r['area']} | {r['expected']} | {r['actual']} | **{r['status']}** |")
    (OUT_DIR / "01_functional_tests.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _extract_metrics_for_run(conn: sqlite3.Connection, run_id: str, tq: Optional[TestQuery] = None) -> Optional[Dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    rr = conn.execute("SELECT * FROM analytical_runs WHERE run_id = ?", (run_id,)).fetchone()
    rep = conn.execute("SELECT report_json FROM reports WHERE run_id = ?", (run_id,)).fetchone()
    if not rr or not rep:
        return None
    run = dict(rr)
    report = json.loads(rep["report_json"])
    meta = report.get("run_metadata") or {}
    acq = meta.get("acquisition_trace") or {}
    threats = report.get("threats") or []

    docs_col = int(meta.get("documents_collected") or run.get("documents_collected") or 0)
    docs_ana = int(meta.get("documents_analyzed") or run.get("documents_analyzed") or 0)
    docs_rej = int(meta.get("documents_rejected") or run.get("documents_rejected") or 0)
    acc_pct = round(100.0 * docs_ana / docs_col, 1) if docs_col else 0.0

    future_leak = 0
    if tq and tq.as_of_date:
        doc_dates = conn.execute("SELECT published_at FROM source_documents WHERE run_id = ?", (run_id,)).fetchall()
        future_leak = sum(1 for d in doc_dates if d["published_at"] and str(d["published_at"])[:10] > tq.as_of_date)

    confirmed_crit = int(meta.get("confirmed_critical_count") or 0)
    supported_cnt = sum(1 for t in threats if t.get("validation_status") == "SUPPORTED")
    partial_cnt = sum(1 for t in threats if t.get("validation_status") == "PARTIALLY_SUPPORTED")
    unver_cnt = sum(1 for t in threats if t.get("validation_status") not in {"SUPPORTED", "PARTIALLY_SUPPORTED"})
    direct_cnt = sum(1 for t in threats if t.get("program_relevance") == "DIRECT_KIT_MATCH")
    ground_pass = sum(1 for t in threats if t.get("technical_grounding_status") == "PASS")
    avg_score = round(sum(int(t.get("threat_score") or 0) for t in threats) / len(threats), 2) if threats else 0.0

    return {
        "query_id": tq.query_id if tq else "AD_HOC",
        "scenario_id": tq.scenario_id if tq else "",
        "scenario_name": tq.scenario_name if tq else "",
        "kit_ref": tq.kit_ref if tq else "",
        "kiq_ref": tq.kiq_ref if tq else "",
        "test_role": tq.test_role if tq else "",
        "query": run.get("query") or (tq.query if tq else ""),
        "scope": run.get("analysis_scope") or (tq.scope if tq else ""),
        "as_of_date": run.get("as_of_date") or (tq.as_of_date if tq else ""),
        "run_id": run_id,
        "dataset_sha256": str((meta.get("experiment") or {}).get("dataset_sha256") or "")[:16],
        "outcome_status": report.get("outcome_status") or run.get("outcome_status") or "",
        "planner_status": meta.get("planner_status", ""),
        "docs_collected": docs_col,
        "docs_primary": int(acq.get("primary_documents") or 0),
        "docs_full_text": int((meta.get("document_content_status_counts") or {}).get("FULL_TEXT") or acq.get("full_text_documents") or 0),
        "docs_metadata_only": int((meta.get("document_content_status_counts") or {}).get("METADATA_ONLY") or acq.get("metadata_only_documents") or 0),
        "fr03_accepted": docs_ana,
        "fr03_rejected": docs_rej,
        "fr03_acceptance_pct": acc_pct,
        "events_total": len(threats),
        "events_direct_kit": direct_cnt,
        "events_supported": supported_cnt,
        "events_partial": partial_cnt,
        "events_unverified": unver_cnt,
        "grounding_pass_events": ground_pass,
        "confirmed_critical": confirmed_crit,
        "avg_threat_score": avg_score,
        "rkiq_total": int(meta.get("runtime_kiq_count") or 0),
        "rkiq_answered": int(meta.get("runtime_kiq_answered") or 0),
        "rkiq_partial": int(meta.get("runtime_kiq_partially_answered") or 0),
        "rkiq_unanswered": int(meta.get("runtime_kiq_unanswered") or 0),
        "editor_mode": meta.get("executive_summary_mode", ""),
        "editor_validation": meta.get("editor_validation_status", ""),
        "future_date_leaks": future_leak,
        "plan_sec": round(float(meta.get("planning_duration_sec") or 0.0), 2),
        "collect_sec": round(float(meta.get("collection_duration_sec") or run.get("collection_duration") or 0.0), 2),
        "filter_sec": round(float(meta.get("filter_duration_sec") or 0.0), 2),
        "analyze_sec": round(float(meta.get("analysis_duration_sec") or run.get("analysis_duration") or 0.0), 2),
        "qa_sec": round(float(meta.get("qa_duration_sec") or run.get("qa_duration") or 0.0), 2),
        "edit_sec": round(float(meta.get("editorial_duration_sec") or 0.0), 2),
        "total_sec": round(float(meta.get("total_duration_sec") or run.get("total_duration") or 0.0), 2),
        "llm_calls": int(meta.get("llm_calls") or run.get("llm_calls") or 0),
        "tokens_in": int(meta.get("tokens_input") or run.get("tokens_input") or 0),
        "tokens_out": int(meta.get("tokens_output") or run.get("tokens_output") or 0),
        "cost_usd": round(float(meta.get("estimated_cost_usd") or run.get("estimated_cost") or 0.0), 5),
        "model_id": meta.get("model_id") or run.get("model_id") or "",
        "exa_calls": int(acq.get("exa_calls_executed") or 0),
        "acq_steps": int(acq.get("queries_executed") or len(acq.get("steps") or [])),
        "_report": report,
    }


def run_export_phase(state: Dict[str, Any]) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not SQLITE_DB.is_file():
        print(f"ERROR: {SQLITE_DB} not found.", file=sys.stderr)
        return 1

    q_by_id = {q.query_id: q for q in THESIS_QUERIES}
    main_runs = state.get("main_runs") or {}

    with sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        main_rows: List[Dict[str, Any]] = []
        event_annotation_rows: List[Dict[str, Any]] = []
        fr03_annotation_rows: List[Dict[str, Any]] = []

        for tq in THESIS_QUERIES:
            rid = (main_runs.get(tq.query_id) or {}).get("run_id")
            if not rid:
                continue
            m = _extract_metrics_for_run(conn, rid, tq)
            if not m:
                continue
            report = m.pop("_report")
            main_rows.append(m)

            for t in (report.get("threats") or []):
                event_annotation_rows.append({
                    "query_id": tq.query_id,
                    "scenario_id": tq.scenario_id,
                    "test_role": tq.test_role,
                    "run_id": rid,
                    "event_id": t.get("event_id", ""),
                    "company_affected": t.get("company_affected", ""),
                    "affected_program": t.get("affected_program", ""),
                    "program_relevance": t.get("program_relevance", ""),
                    "system_risk_type": t.get("risk_type", ""),
                    "system_scm_tier": t.get("scm_tier", ""),
                    "system_threat_score": t.get("threat_score", ""),
                    "validation_status": t.get("validation_status", ""),
                    "confidence_level": t.get("confidence_level", ""),
                    "technical_grounding": t.get("technical_grounding_status", ""),
                    "event_freshness": t.get("event_freshness", ""),
                    "threat_description": " ".join(str(t.get("threat_description") or "").split()),
                    "confirmed_facts": " ".join(str(t.get("confirmed_facts") or "").split()),
                    "fact_check_quote": " ".join(str(t.get("fact_check_quote") or "").split()),
                    "evidence_citation": t.get("evidence_citation", ""),
                    # --- MANUAL ANNOTATION COLUMNS (FILL IN EXCEL / CSV) ---
                    "manual_is_relevant_0_1": "",
                    "manual_ref_risk_type": "",
                    "manual_ref_threat_score_1_10": "",
                    "manual_factual_verdict": "",    # CORRECT | PARTIALLY_CORRECT | INCORRECT | UNVERIFIABLE
                    "manual_hallucination_type": "",  # NONE | INTRINSIC | EXTRINSIC | VARIANT_MIXUP
                    "manual_citation_supports_0_1": "",
                    "manual_notes": "",
                })

            f_rows = conn.execute(
                "SELECT doc_id, source_id, url, title, filter_stage, is_accepted, signal_type, decision_rationale "
                "FROM document_filter_log WHERE run_id = ? ORDER BY doc_id",
                (rid,),
            ).fetchall()
            for fr in f_rows:
                fr03_annotation_rows.append({
                    "query_id": tq.query_id,
                    "scenario_id": tq.scenario_id,
                    "query": tq.query,
                    "run_id": rid,
                    "doc_id": fr["doc_id"],
                    "source_id": fr["source_id"],
                    "title": " ".join(str(fr["title"] or "").split()),
                    "url": fr["url"],
                    "filter_stage": fr["filter_stage"],
                    "fr03_accepted_0_1": fr["is_accepted"],
                    "signal_type": fr["signal_type"],
                    "decision_rationale": " ".join(str(fr["decision_rationale"] or "").split())[:220],
                    "manual_doc_relevant_0_1": "",
                    "manual_error_note": "",
                })

        if main_rows:
            csv_path = OUT_DIR / "02_main_25_queries.csv"
            with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(main_rows[0].keys()))
                w.writeheader()
                w.writerows(main_rows)

            md = [
                "# Main Experiment Results — Aero_EWS 2.0 (5 Scenarios x 5 Queries = 25 Queries)",
                "",
                "| ID | Scenario | Role | Outcome | Docs (Acc/Tot) | Events (Supp/Part/Crit) | RKIQ (A/P/U) | Time (s) | Cost (USD) | Run ID |",
                "| :--- | :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |",
            ]
            for r in main_rows:
                md.append(
                    f"| {r['query_id']} | {r['scenario_id']} | {r['test_role']} | {r['outcome_status']} "
                    f"| {r['fr03_accepted']}/{r['docs_collected']} ({r['fr03_acceptance_pct']}%) "
                    f"| {r['events_total']} ({r['events_supported']}/{r['events_partial']}/{r['confirmed_critical']}) "
                    f"| {r['rkiq_answered']}/{r['rkiq_partial']}/{r['rkiq_unanswered']} "
                    f"| {r['total_sec']} | ${r['cost_usd']:.5f} | `{r['run_id']}` |"
                )

            md += ["", "## Summary by Scenario (S1-S5)", "",
                   "| Scenario | Runs | Avg Docs | FR03 Accepted (%) | Avg Events | Avg Supported | Critical | Avg Time (s) | Avg Cost (USD) |",
                   "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"]
            for sid in ("S1", "S2", "S3", "S4", "S5"):
                sub = [r for r in main_rows if r["scenario_id"] == sid]
                if not sub:
                    continue
                n = len(sub)
                md.append(
                    f"| {sid}: {sub[0]['scenario_name'][:38]} | {n} "
                    f"| {sum(r['docs_collected'] for r in sub)/n:.1f} "
                    f"| {sum(r['fr03_acceptance_pct'] for r in sub)/n:.1f}% "
                    f"| {sum(r['events_total'] for r in sub)/n:.1f} "
                    f"| {sum(r['events_supported'] for r in sub)/n:.1f} "
                    f"| {sum(r['confirmed_critical'] for r in sub)} "
                    f"| {sum(r['total_sec'] for r in sub)/n:.1f} "
                    f"| ${sum(r['cost_usd'] for r in sub)/n:.5f} |"
                )
            (OUT_DIR / "02_main_25_queries.md").write_text("\n".join(md) + "\n", encoding="utf-8")

            n = len(main_rows)
            eff = [
                "# 8.8 Efficiency, Per-Stage Latency, and Cost Telemetry",
                "",
                "| Metric | Mean per Run | Total (All Runs) |",
                "| :--- | :---: | :---: |",
                f"| Completed Runs | -- | {n} |",
                f"| Planning (Planner) [s] | {sum(r['plan_sec'] for r in main_rows)/n:.2f} | {sum(r['plan_sec'] for r in main_rows):.2f} |",
                f"| OSINT Collection (Acquisition + Exa) [s] | {sum(r['collect_sec'] for r in main_rows)/n:.2f} | {sum(r['collect_sec'] for r in main_rows):.2f} |",
                f"| FR03 Relevance Filtering [s] | {sum(r['filter_sec'] for r in main_rows)/n:.2f} | {sum(r['filter_sec'] for r in main_rows):.2f} |",
                f"| Analysis (Risk Analyst) [s] | {sum(r['analyze_sec'] for r in main_rows)/n:.2f} | {sum(r['analyze_sec'] for r in main_rows):.2f} |",
                f"| Quality Assurance (QA + Harness) [s] | {sum(r['qa_sec'] for r in main_rows)/n:.2f} | {sum(r['qa_sec'] for r in main_rows):.2f} |",
                f"| Editorial Synthesis (Editor) [s] | {sum(r['edit_sec'] for r in main_rows)/n:.2f} | {sum(r['edit_sec'] for r in main_rows):.2f} |",
                f"| **Total Pipeline Runtime [s]** | **{sum(r['total_sec'] for r in main_rows)/n:.2f}** | **{sum(r['total_sec'] for r in main_rows):.2f}** |",
                f"| LLM Calls | {sum(r['llm_calls'] for r in main_rows)/n:.1f} | {sum(r['llm_calls'] for r in main_rows)} |",
                f"| Input Tokens | {sum(r['tokens_in'] for r in main_rows)/n:.0f} | {sum(r['tokens_in'] for r in main_rows)} |",
                f"| Output Tokens | {sum(r['tokens_out'] for r in main_rows)/n:.0f} | {sum(r['tokens_out'] for r in main_rows)} |",
                f"| **Estimated LLM Cost [USD]** | **${sum(r['cost_usd'] for r in main_rows)/n:.5f}** | **${sum(r['cost_usd'] for r in main_rows):.5f}** |",
            ]
            (OUT_DIR / "08_efficiency_telemetry.md").write_text("\n".join(eff) + "\n", encoding="utf-8")

        if event_annotation_rows:
            ev_csv = OUT_DIR / "03_events_for_manual_annotation.csv"
            with ev_csv.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(event_annotation_rows[0].keys()))
                w.writeheader()
                w.writerows(event_annotation_rows)

        if fr03_annotation_rows:
            fr_csv = OUT_DIR / "04_fr03_docs_for_annotation.csv"
            with fr_csv.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(fr03_annotation_rows[0].keys()))
                w.writeheader()
                w.writerows(fr03_annotation_rows)

        stab_lines = [
            "# 8.7 Stability and Repeatability of Analytical Results (`replay_run_id`)",
            "",
            "| Query | Run # | Run ID | Dataset SHA-256 | Outcome | Events (Tot/Supp) | Avg Threat Score | RKIQ (A/P/U) | Time (s) |",
            "| :--- | :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: |",
        ]
        for qid, rids in (state.get("stability_runs") or {}).items():
            tq = q_by_id.get(qid)
            for idx, rid in enumerate(rids, 1):
                m = _extract_metrics_for_run(conn, rid, tq)
                if m:
                    stab_lines.append(
                        f"| {qid} | Run {idx} | `{rid}` | `{m['dataset_sha256']}` | {m['outcome_status']} "
                        f"| {m['events_total']}/{m['events_supported']} | {m['avg_threat_score']} "
                        f"| {m['rkiq_answered']}/{m['rkiq_partial']}/{m['rkiq_unanswered']} | {m['total_sec']} |"
                    )
        (OUT_DIR / "05_stability_replay.md").write_text("\n".join(stab_lines) + "\n", encoding="utf-8")

        base_lines = [
            "# 8.9 Comparison of Aero_EWS 2.0 vs. Keyword Baseline (Shared `dataset_sha256`)",
            "",
            "| Query | Variant | Run ID | Docs Analyzed | Events (Tot/Supp/Crit) | RKIQ (A/P) | Time (s) | LLM Calls | Cost (USD) |",
            "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for qid, base_rid in (state.get("baseline_runs") or {}).items():
            tq = q_by_id.get(qid)
            main_rid = (main_runs.get(qid) or {}).get("run_id")
            for label, rid in (("Aero_EWS (Multi-Agent)", main_rid), ("Keyword Baseline", base_rid)):
                if not rid:
                    continue
                m = _extract_metrics_for_run(conn, rid, tq)
                if m:
                    base_lines.append(
                        f"| {qid} | {label} | `{rid}` | {m['fr03_accepted']} "
                        f"| {m['events_total']}/{m['events_supported']}/{m['confirmed_critical']} "
                        f"| {m['rkiq_answered']}/{m['rkiq_partial']} | {m['total_sec']} | {m['llm_calls']} | ${m['cost_usd']:.5f} |"
                    )
        (OUT_DIR / "06_baseline_comparison.md").write_text("\n".join(base_lines) + "\n", encoding="utf-8")

        kiq_lines = ["# 8.10 Case Study Summary — KIT / KIQ Answers", ""]
        for tq in THESIS_QUERIES:
            rid = (main_runs.get(tq.query_id) or {}).get("run_id")
            if not rid:
                continue
            rep = _fetch_report_from_db(rid)
            if not rep:
                continue
            kiq_lines.append(f"## {tq.query_id} ({tq.kit_ref} / {tq.kiq_ref}): {tq.query}")
            kiq_lines.append(f"- **Run ID:** `{rid}` | **Outcome:** `{rep.get('outcome_status')}` | **As-Of:** `{tq.as_of_date or 'LIVE'}`")
            kiq_lines.append(f"- **Executive Summary:** {str(rep.get('executive_summary') or '')[:500]}")
            for ka in (rep.get("kiq_answers") or []):
                kiq_lines.append(
                    f"  - **{ka.get('kiq_id')}** (`{ka.get('answer_status')}`, coverage=`{ka.get('evidence_coverage')}`): "
                    f"{ka.get('question')} -- {str(ka.get('answer') or '')[:320]}"
                )
            kiq_lines.append("")
        (OUT_DIR / "07_kiq_case_study_summary.md").write_text("\n".join(kiq_lines) + "\n", encoding="utf-8")

    print(f"[EXPORT DONE] Exported {len(main_rows)} main runs, {len(event_annotation_rows)} events, {len(fr03_annotation_rows)} FR03 docs -> {OUT_DIR}/")
    return 0


# =============================================================================
# PHASE 6: Compute Metrics From Completed Manual Annotations (Chapter 8.4-8.6)
# =============================================================================
def run_score_phase() -> int:
    fr_csv = OUT_DIR / "04_fr03_docs_for_annotation.csv"
    ev_csv = OUT_DIR / "03_events_for_manual_annotation.csv"
    lines = ["# Manual Reference Dataset Evaluation Report (Chapter 8.4-8.6)", ""]

    if fr_csv.is_file():
        tp = fp = tn = fn = 0
        with fr_csv.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                gold = str(row.get("manual_doc_relevant_0_1") or "").strip()
                if gold not in {"0", "1"}:
                    continue
                pred = int(str(row.get("fr03_accepted_0_1") or "0").strip() == "1")
                g = int(gold)
                if pred == 1 and g == 1:
                    tp += 1
                elif pred == 1 and g == 0:
                    fp += 1
                elif pred == 0 and g == 0:
                    tn += 1
                else:
                    fn += 1
        tot = tp + fp + tn + fn
        prec = (100.0 * tp / (tp + fp)) if (tp + fp) else 0.0
        rec = (100.0 * tp / (tp + fn)) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        lines += [
            "## 8.4 FR03 Two-Stage Filter Accuracy (Document Level)",
            f"- Annotated documents: **{tot}** (TP={tp}, FP={fp}, TN={tn}, FN={fn})",
            f"- **Precision:** {prec:.1f}% | **Recall:** {rec:.1f}% | **F1-score:** {f1:.1f}%",
            "",
        ]

    if ev_csv.is_file():
        rel_tp = rel_fp = cat_ok = cat_tot = cit_ok = cit_tot = 0
        score_diffs: List[float] = []
        verdicts: Counter = Counter()
        halluc: Counter = Counter()
        with ev_csv.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                rel = str(row.get("manual_is_relevant_0_1") or "").strip()
                if rel in {"0", "1"}:
                    if rel == "1":
                        rel_tp += 1
                    else:
                        rel_fp += 1
                ref_cat = str(row.get("manual_ref_risk_type") or "").strip().upper()
                if ref_cat:
                    cat_tot += 1
                    if ref_cat == str(row.get("system_risk_type") or "").strip().upper():
                        cat_ok += 1
                ref_sc = str(row.get("manual_ref_threat_score_1_10") or "").strip()
                sys_sc = str(row.get("system_threat_score") or "").strip()
                if ref_sc.isdigit() and sys_sc.isdigit():
                    score_diffs.append(abs(int(ref_sc) - int(sys_sc)))
                v = str(row.get("manual_factual_verdict") or "").strip().upper()
                if v:
                    verdicts[v] += 1
                h = str(row.get("manual_hallucination_type") or "").strip().upper()
                if h:
                    halluc[h] += 1
                c = str(row.get("manual_citation_supports_0_1") or "").strip()
                if c in {"0", "1"}:
                    cit_tot += 1
                    cit_ok += int(c)

        ev_prec = (100.0 * rel_tp / (rel_tp + rel_fp)) if (rel_tp + rel_fp) else 0.0
        cat_acc = (100.0 * cat_ok / cat_tot) if cat_tot else 0.0
        mae = (sum(score_diffs) / len(score_diffs)) if score_diffs else 0.0
        cit_rate = (100.0 * cit_ok / cit_tot) if cit_tot else 0.0
        lines += [
            "## 8.4-8.6 Event Quality, Risk Classification, Threat Score & Hallucinations",
            f"- **Event Detection Precision:** {ev_prec:.1f}% (TP={rel_tp}, FP={rel_fp})",
            f"- **Risk Category Accuracy:** {cat_acc:.1f}% ({cat_ok}/{cat_tot})",
            f"- **Threat Score Mean Absolute Error (MAE):** {mae:.2f} points (n={len(score_diffs)})",
            f"- **Citation Grounding Rate:** {cit_rate:.1f}% ({cit_ok}/{cit_tot})",
            f"- **Factual Verdict Distribution:** {dict(verdicts)}",
            f"- **Hallucination Distribution:** {dict(halluc)}",
            "",
        ]

    out_path = OUT_DIR / "09_annotated_evaluation_report.md"
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[SCORE DONE] Written -> {out_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Aero_EWS 2.0 Final Thesis Test Suite (5 Scenarios x 5 Queries = 25)")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Running Aero_EWS FastAPI base URL")
    parser.add_argument("--list", action="store_true", help="Print all 25 test queries and exit")
    parser.add_argument(
        "--phase",
        choices=("contract", "main", "stability", "baseline", "export", "score", "all"),
        default="export",
        help="Execution phase",
    )
    parser.add_argument("--scenarios", default="ALL", help="Comma-separated scenario IDs (e.g., S1,S2) or ALL")
    parser.add_argument("--ids", default="", help="Comma-separated query IDs (e.g., S1-Q1,S5-Q1)")
    parser.add_argument("--limit", type=int, default=6, help="Records per source (1..10)")
    parser.add_argument("--repeats", type=int, default=3, help="Total runs per anchor query in stability phase")
    parser.add_argument("--timeout", type=int, default=600, help="Per-run timeout in seconds")
    parser.add_argument("--resume", action="store_true", help="Skip already completed main runs stored in suite_state.json")
    args = parser.parse_args()

    if args.list:
        for q in THESIS_QUERIES:
            print(f"{q.query_id} | {q.scenario_id} | {q.test_role:<17} | scope={q.scope:<4} | as_of={q.as_of_date or 'LIVE':<10} | {q.query}")
        print(f"\nTotal: {len(THESIS_QUERIES)} queries across {len({q.scenario_id for q in THESIS_QUERIES})} scenarios.")
        return 0

    state = _load_state()
    if args.ids.strip():
        wanted = {x.strip().upper() for x in args.ids.split(",") if x.strip()}
        selected = [q for q in THESIS_QUERIES if q.query_id.upper() in wanted]
    elif args.scenarios.strip().upper() == "ALL":
        selected = list(THESIS_QUERIES)
    else:
        wanted_sc = {x.strip().upper() for x in args.scenarios.split(",") if x.strip()}
        selected = [q for q in THESIS_QUERIES if q.scenario_id.upper() in wanted_sc]

    rc = 0
    if args.phase in {"contract", "all"}:
        rc |= run_contract_phase(args.base_url, state)
    if args.phase in {"main", "all"}:
        rc |= run_main_phase(args.base_url, state, selected, args.limit, args.resume, args.timeout)
    if args.phase in {"stability", "all"}:
        rc |= run_stability_phase(args.base_url, state, list(STABILITY_ANCHORS), args.repeats, args.limit, args.timeout)
    if args.phase in {"baseline", "all"}:
        rc |= run_baseline_phase(args.base_url, state, list(BASELINE_ANCHORS), args.limit, args.timeout)
    if args.phase in {"export", "all"}:
        rc |= run_export_phase(state)
    if args.phase == "score":
        rc |= run_score_phase()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
