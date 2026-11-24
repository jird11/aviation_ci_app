# =============================================================================
# Aero_EWS 2.0 | Thesis A/B Benchmark Runner (deterministic vs. agentic_exa)
#
# Usage:
#   Export existing SQLite runs only (zero API cost):
#     python run_thesis_benchmark.py --export-only
#
#   Run selected scenarios live against http://127.0.0.1:8000:
#     python run_thesis_benchmark.py --scenarios S01,S02 --limit 5
#
#   Run all 10 thesis scenarios in both modes:
#     python run_thesis_benchmark.py --limit 5
# =============================================================================

"""Automated A/B benchmark harness exporting CSV and Markdown tables for the thesis."""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

SQLITE_DB = Path("ews_intelligence.db")
DEFAULT_PLATFORMS = ["news", "regulatory", "pr", "bluesky"]


@dataclass(frozen=True)
class BenchmarkScenario:
    scenario_id: str
    query: str
    scope: str
    category: str


THESIS_SCENARIOS: List[BenchmarkScenario] = [
    BenchmarkScenario("S01", "Airbus A320neo engine problems", "365d", "Program / Multi-OEM Propulsion"),
    BenchmarkScenario("S02", "Boeing 737 MAX 10 FAA certification delays", "365d", "Regulatory / Certification"),
    BenchmarkScenario("S03", "Pratt & Whitney PW1100G powdered metal inspection requirements", "365d", "Tier 1 / Technical Quality"),
    BenchmarkScenario("S04", "Boeing 777X FAA certification and GE9X engine status", "365d", "Program / Certification"),
    BenchmarkScenario("S05", "CFM LEAP-1A high pressure turbine blade airworthiness directives", "365d", "Regulatory / Exact Engine"),
    BenchmarkScenario("S06", "Spirit AeroSystems Boeing 737 fuselage production quality disruption", "365d", "Tier 1 / Supply Chain"),
    BenchmarkScenario("S07", "Safran aircraft engine casting supply constraints and delivery impact", "365d", "Tier 1-2 / Supply Chain"),
    BenchmarkScenario("S08", "Rolls-Royce Trent XWB durability and A350 maintenance issues", "365d", "Tier 1 / Widebody Propulsion"),
    BenchmarkScenario("S09", "Airbus A220 Pratt & Whitney PW1500G engine grounding", "365d", "Program / Narrowbody GTF"),
    BenchmarkScenario("S10", "Airbus A380 new production line launch", "30d", "Negative Control (Hallucination Test)"),
]

CSV_FIELDS = [
    "scenario_id", "category", "query", "scope", "collection_mode", "run_id", "outcome_status",
    "docs_collected", "docs_primary", "docs_secondary", "docs_full_text", "docs_metadata_only",
    "fr03_accepted", "fr03_rejected", "fr03_acceptance_pct", "fr03_review_candidates",
    "events_total", "events_supported_direct", "events_unverified", "confirmed_critical",
    "rkiq_total", "rkiq_answered", "rkiq_partial", "rkiq_unanswered",
    "acq_steps", "exa_calls", "collection_sec", "total_sec", "llm_calls",
    "tokens_input", "tokens_output", "estimated_cost_usd", "cost_status", "completed_at",
]


def _wait_for_pipeline_idle(base_url: str, run_id: str, timeout_sec: int = 600) -> str:
    """Poll /logs until the background pipeline finishes the given run_id."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            resp = requests.get(f"{base_url}/logs", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                running = bool(data.get("running"))
                cur_id = str(data.get("current_run_id") or "")
                state = str(data.get("state") or "")
                if not running and (cur_id == run_id or state in {"COMPLETED", "FAILED", "CANCELLED"}):
                    return state or "COMPLETED"
        except requests.RequestException:
            pass
        time.sleep(3.0)
    raise TimeoutError(f"Run {run_id} did not finish within {timeout_sec}s")


def _trigger_run(
    base_url: str, scenario: BenchmarkScenario, mode: str, limit: int, platforms: List[str],
) -> str:
    """Submit POST /run-ews and return accepted run_id."""
    payload = {
        "query": scenario.query,
        "scope": scenario.scope,
        "limit": limit,
        "collection_mode": mode,
        "platforms": platforms,
    }
    resp = requests.post(f"{base_url}/run-ews", json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "started" or not data.get("run_id"):
        raise RuntimeError(f"Could not start run for {scenario.scenario_id} ({mode}): {data}")
    return str(data["run_id"])


def _extract_run_row(
    conn: sqlite3.Connection,
    run_id: str,
    scenario: Optional[BenchmarkScenario] = None,
) -> Optional[Dict[str, Any]]:
    """Extract normalized thesis benchmark metrics for one completed run from SQLite."""
    conn.row_factory = sqlite3.Row
    run_row = conn.execute("SELECT * FROM analytical_runs WHERE run_id = ?", (run_id,)).fetchone()
    rep_row = conn.execute("SELECT report_json FROM reports WHERE run_id = ?", (run_id,)).fetchone()
    if not run_row or not rep_row:
        return None

    run = dict(run_row)
    report = json.loads(rep_row["report_json"])
    meta = report.get("run_metadata") or {}
    acq = meta.get("acquisition_trace") or {}
    try:
        cfg = json.loads(run.get("ablation_config_json") or "{}")
    except (TypeError, ValueError):
        cfg = {}

    mode = str(meta.get("collection_mode") or cfg.get("collection_mode") or "deterministic")
    docs_collected = int(run.get("documents_collected") or 0)
    docs_analyzed = int(run.get("documents_analyzed") or 0)
    docs_rejected = int(run.get("documents_rejected") or 0)
    acc_pct = round(100.0 * docs_analyzed / docs_collected, 1) if docs_collected else 0.0

    # Derive primary/full-text counts from source_documents if missing in older acquisition_trace.
    doc_rows = conn.execute(
        "SELECT origin_type, content_status FROM source_documents WHERE run_id = ?", (run_id,)
    ).fetchall()
    primary_docs = int(acq.get("primary_documents") or sum(
        1 for d in doc_rows if str(d["origin_type"] or "").startswith("PRIMARY")
    ))
    full_text_docs = int(acq.get("full_text_documents") or sum(
        1 for d in doc_rows if d["content_status"] == "FULL_TEXT"
    ))
    meta_only_docs = int(acq.get("metadata_only_documents") or sum(
        1 for d in doc_rows if d["content_status"] == "METADATA_ONLY"
    ))

    matched_sc = scenario or next(
        (s for s in THESIS_SCENARIOS if s.query.casefold() == str(run.get("query") or "").strip().casefold()),
        None,
    )
    return {
        "scenario_id": matched_sc.scenario_id if matched_sc else "AD_HOC",
        "category": matched_sc.category if matched_sc else "Custom KIT",
        "query": run.get("query", ""),
        "scope": run.get("analysis_scope", ""),
        "collection_mode": mode,
        "run_id": run_id,
        "outcome_status": run.get("outcome_status", ""),
        "docs_collected": docs_collected,
        "docs_primary": primary_docs,
        "docs_secondary": max(0, docs_collected - primary_docs),
        "docs_full_text": full_text_docs,
        "docs_metadata_only": meta_only_docs,
        "fr03_accepted": docs_analyzed,
        "fr03_rejected": docs_rejected,
        "fr03_acceptance_pct": acc_pct,
        "fr03_review_candidates": int(meta.get("fr03_rejection_review_candidates") or 0),
        "events_total": len(report.get("threats") or []),
        "events_supported_direct": int(meta.get("direct_kit_confirmed_count") or 0),
        "events_unverified": int(meta.get("unverified_signal_count") or 0),
        "confirmed_critical": int(meta.get("confirmed_critical_count") or 0),
        "rkiq_total": int(meta.get("runtime_kiq_count") or 0),
        "rkiq_answered": int(meta.get("runtime_kiq_answered") or 0),
        "rkiq_partial": int(meta.get("runtime_kiq_partially_answered") or 0),
        "rkiq_unanswered": int(meta.get("runtime_kiq_unanswered") or 0),
        "acq_steps": len(acq.get("steps") or []),
        "exa_calls": int(acq.get("exa_calls_executed") or 0),
        "collection_sec": round(float(run.get("collection_duration") or 0.0), 2),
        "total_sec": round(float(run.get("total_duration") or 0.0), 2),
        "llm_calls": int(run.get("llm_calls") or 0),
        "tokens_input": int(run.get("tokens_input") or 0),
        "tokens_output": int(run.get("tokens_output") or 0),
        "estimated_cost_usd": (
            round(float(run["estimated_cost"]), 5) if run.get("estimated_cost") is not None else ""
        ),
        "cost_status": meta.get("estimated_cost_status", ""),
        "completed_at": run.get("completed_at", ""),
    }


def _write_outputs(rows: List[Dict[str, Any]], csv_path: Path, md_path: Path) -> None:
    """Export per-run CSV and thesis-ready Markdown comparison tables."""
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    def _avg(subset: List[Dict[str, Any]], key: str, digits: int = 2) -> str:
        vals = [float(r[key]) for r in subset if r.get(key) not in ("", None)]
        return f"{sum(vals) / len(vals):.{digits}f}" if vals else "—"

    by_mode = {
        mode: [r for r in rows if r["collection_mode"] == mode]
        for mode in ("deterministic", "agentic_exa")
    }

    md_lines = [
        "# Aero_EWS 2.0 — A/B Benchmark Summary (`deterministic` vs. `agentic_exa`)",
        "",
        "## 1. Aggregate Comparison by Collection Mode",
        "",
        "| Metric | `deterministic` (Baseline) | `agentic_exa` (Adaptive + Exa) |",
        "| :--- | :---: | :---: |",
        f"| Completed Runs | {len(by_mode['deterministic'])} | {len(by_mode['agentic_exa'])} |",
        f"| Avg. Documents Collected | {_avg(by_mode['deterministic'], 'docs_collected')} | {_avg(by_mode['agentic_exa'], 'docs_collected')} |",
        f"| Avg. Primary Documents | {_avg(by_mode['deterministic'], 'docs_primary')} | {_avg(by_mode['agentic_exa'], 'docs_primary')} |",
        f"| Avg. Full-Text Documents | {_avg(by_mode['deterministic'], 'docs_full_text')} | {_avg(by_mode['agentic_exa'], 'docs_full_text')} |",
        f"| Avg. Metadata-Only Documents | {_avg(by_mode['deterministic'], 'docs_metadata_only')} | {_avg(by_mode['agentic_exa'], 'docs_metadata_only')} |",
        f"| Avg. FR03 Accepted Documents | {_avg(by_mode['deterministic'], 'fr03_accepted')} | {_avg(by_mode['agentic_exa'], 'fr03_accepted')} |",
        f"| Avg. FR03 Acceptance Rate (%) | {_avg(by_mode['deterministic'], 'fr03_acceptance_pct', 1)}% | {_avg(by_mode['agentic_exa'], 'fr03_acceptance_pct', 1)}% |",
        f"| Avg. Events Identified | {_avg(by_mode['deterministic'], 'events_total')} | {_avg(by_mode['agentic_exa'], 'events_total')} |",
        f"| Avg. Supported Direct Events | {_avg(by_mode['deterministic'], 'events_supported_direct')} | {_avg(by_mode['agentic_exa'], 'events_supported_direct')} |",
        f"| Avg. Runtime KIQ Answered + Partial | {round(sum(r['rkiq_answered'] + r['rkiq_partial'] for r in by_mode['deterministic']) / len(by_mode['deterministic']), 2) if by_mode['deterministic'] else '—'} | {round(sum(r['rkiq_answered'] + r['rkiq_partial'] for r in by_mode['agentic_exa']) / len(by_mode['agentic_exa']), 2) if by_mode['agentic_exa'] else '—'} |",
        f"| Avg. Acquisition Steps / Exa Calls | {_avg(by_mode['deterministic'], 'acq_steps')} / {_avg(by_mode['deterministic'], 'exa_calls')} | {_avg(by_mode['agentic_exa'], 'acq_steps')} / {_avg(by_mode['agentic_exa'], 'exa_calls')} |",
        f"| Avg. Collection Duration (s) | {_avg(by_mode['deterministic'], 'collection_sec')} | {_avg(by_mode['agentic_exa'], 'collection_sec')} |",
        f"| Avg. Total Runtime (s) | {_avg(by_mode['deterministic'], 'total_sec')} | {_avg(by_mode['agentic_exa'], 'total_sec')} |",
        f"| Avg. Estimated LLM Cost (USD) | ${_avg(by_mode['deterministic'], 'estimated_cost_usd', 5)} | ${_avg(by_mode['agentic_exa'], 'estimated_cost_usd', 5)} |",
        "",
        "## 2. Per-Run Breakdown",
        "",
        "| Scenario | Mode | Outcome | Docs (Prim/Full) | FR03 Acc (%) | Events (Supp/Unv) | RKIQ (A/P/U) | Steps/Exa | Time (s) | Cost (USD) | Run ID |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |",
    ]
    for r in rows:
        cost_s = f"${r['estimated_cost_usd']:.5f}" if isinstance(r["estimated_cost_usd"], float) else "—"
        md_lines.append(
            f"| {r['scenario_id']}: {r['query'][:36]} | `{r['collection_mode']}` | {r['outcome_status']} "
            f"| {r['docs_collected']} ({r['docs_primary']}/{r['docs_full_text']}) "
            f"| {r['fr03_accepted']} ({r['fr03_acceptance_pct']}%) "
            f"| {r['events_total']} ({r['events_supported_direct']}/{r['events_unverified']}) "
            f"| {r['rkiq_answered']}/{r['rkiq_partial']}/{r['rkiq_unanswered']} "
            f"| {r['acq_steps']}/{r['exa_calls']} "
            f"| {r['total_sec']} | {cost_s} | `{r['run_id']}` |"
        )

    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aero_EWS 2.0 Thesis A/B Benchmark Runner")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Running Aero_EWS FastAPI URL")
    parser.add_argument("--scenarios", default="ALL", help="Comma-separated IDs (e.g., S01,S02) or ALL")
    parser.add_argument("--modes", default="deterministic,agentic_exa", help="Comma-separated collection modes")
    parser.add_argument("--limit", type=int, default=5, help="Per-source document limit")
    parser.add_argument("--export-only", action="store_true", help="Export existing SQLite runs without launching new scans")
    parser.add_argument("--max-export-runs", type=int, default=30, help="Maximum recent runs to include in --export-only")
    parser.add_argument("--csv-out", default="thesis_benchmark_results.csv")
    parser.add_argument("--md-out", default="thesis_benchmark_summary.md")
    args = parser.parse_args()

    if not SQLITE_DB.is_file():
        print(f"ERROR: {SQLITE_DB} not found.", file=sys.stderr)
        return 1

    rows: List[Dict[str, Any]] = []
    with sqlite3.connect(SQLITE_DB) as conn:
        if args.export_only:
            run_ids = [
                r[0] for r in conn.execute(
                    "SELECT run_id FROM analytical_runs WHERE status = 'completed' "
                    "ORDER BY completed_at DESC LIMIT ?",
                    (args.max_export_runs,),
                ).fetchall()
            ]
            for rid in run_ids:
                if row := _extract_run_row(conn, rid):
                    rows.append(row)
        else:
            wanted = {s.strip().upper() for s in args.scenarios.split(",") if s.strip()}
            selected = THESIS_SCENARIOS if "ALL" in wanted else [s for s in THESIS_SCENARIOS if s.scenario_id in wanted]
            modes = [m.strip() for m in args.modes.split(",") if m.strip() in {"deterministic", "agentic_exa"}]
            if not selected or not modes:
                print("ERROR: No valid scenarios or modes selected.", file=sys.stderr)
                return 2

            for sc in selected:
                for mode in modes:
                    print(f"[BENCHMARK] Running {sc.scenario_id} ({mode}): {sc.query} [{sc.scope}, limit={args.limit}]")
                    try:
                        run_id = _trigger_run(args.base_url, sc, mode, args.limit, DEFAULT_PLATFORMS)
                        final_state = _wait_for_pipeline_idle(args.base_url, run_id)
                        print(f"  -> finished {run_id} ({final_state})")
                        if row := _extract_run_row(conn, run_id, scenario=sc):
                            rows.append(row)
                    except Exception as exc:
                        print(f"  -> FAILED {sc.scenario_id} ({mode}): {exc}", file=sys.stderr)

    csv_path, md_path = Path(args.csv_out), Path(args.md_out)
    _write_outputs(rows, csv_path, md_path)
    print(f"[BENCHMARK EXPORTED] {len(rows)} run(s) -> {csv_path} & {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())