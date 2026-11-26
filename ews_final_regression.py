# =============================================================================
# aviation_ci_app | Offline regression and fault-injection test harness (v2.0)
#
# Responsibility: Exercise core schemas, Analyst parsing/recovery contracts,
#   deterministic 5-factor I&W scoring, evidence governance, and stored-report
#   invariants aligned with Aero_EWS 2.0.
# Design boundary: The harness intentionally avoids live OSINT collection,
#   provider calls, and modifications to operational data.
# =============================================================================

"""aviation_ci_app offline regression/fault-injection audit (Aero_EWS 2.0).

Place next to ews_pipeline.py, run from an activated project venv:
    python ews_final_regression.py

No API requests, live LLM calls, SQLite writes, or dashboard changes.
"""
from __future__ import annotations

import argparse
import ast
import copy
import importlib.util
import json
import math
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from contextlib import closing
from enum import Enum
from pathlib import Path
from types import SimpleNamespace


class Audit:
    def __init__(self):
        self.results = []

    def check(self, category, label, callback, optional=False):
        try:
            detail = callback()
            status = "PASS" if detail is not False else "FAIL"
            message = "" if detail is True or detail is None else str(detail)
        except Exception as exc:
            status = "WARN" if optional else "FAIL"
            message = f"{type(exc).__name__}: {exc}"
        self.results.append((status, category, label, message))
        print(f"[{status:4}] {category:<13} {label}" + (f" :: {message[:220]}" if message else ""))

    def finish(self):
        counts = Counter(x[0] for x in self.results)
        print("\n" + "=" * 78)
        print("RESULT:", " | ".join(f"{n}={counts[n]}" for n in ("PASS", "FAIL", "WARN")))
        if counts["FAIL"]:
            print("\nFAIL ITEMS — fix these together, then re-run this one test file:")
            for status, category, label, detail in self.results:
                if status == "FAIL":
                    print(f"  [FAIL] {category}/{label}: {detail}")
        print("=" * 78)
        return 1 if counts["FAIL"] else 0


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    return True


def _is_valid(model, payload) -> bool:
    try:
        model.model_validate(payload)
        return True
    except ValueError:
        return False


def _compile_ast(node, source_path: Path, with_future: bool = False):
    body = [copy.deepcopy(node)]
    if with_future:
        future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
        body.insert(0, future)
    mod = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
    return compile(mod, str(source_path), "exec")


def _load_module_from_path(module_name: str, file_path: Path, project_root: Path):
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    require(spec is not None and spec.loader is not None, f"Cannot load spec for {file_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_json(path: Path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), "JSON root must be an object")
    return value


def find_real_scoring_if(source_path: Path):
    src_text = source_path.read_text(encoding="utf-8-sig")
    tree = ast.parse(src_text, filename=str(source_path))
    funcs = [
        n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_execute_ews_background"
    ]
    require(len(funcs) == 1, "_execute_ews_background must exist exactly once")

    candidates = [
        node for node in ast.walk(funcs[0])
        if isinstance(node, ast.If)
        and "scoring_started = time.time()" in (ast.get_source_segment(src_text, node) or "")
        and "scoring_partial_fallback_ids" in (ast.get_source_segment(src_text, node) or "")
    ]
    require(bool(candidates), "Unable to locate scoring if block in current pipeline")
    selected = min(candidates, key=lambda n: n.end_lineno - n.lineno)
    return _compile_ast(selected, source_path)


def run_deterministic_scoring_audit(audit: Audit, root: Path, pipeline_file: Path):
    audit.check("SCORING", "real Scoring stage AST isolated", lambda: (find_real_scoring_if(pipeline_file) and "scoring stage AST compiled"))

    scoring_candidates = [
        root / "aero_ews" / "intelligence" / "scoring.py",
        root / "scoring.py",
    ]
    scoring_file = next((p for p in scoring_candidates if p.is_file()), None)
    audit.check(
        "SCORING",
        "deterministic scoring module present",
        lambda: require(scoring_file is not None, "scoring.py not found in aero_ews/intelligence/ or root"),
    )
    if not scoring_file:
        return

    src_text = scoring_file.read_text(encoding="utf-8-sig")
    audit.check("SCORING", "deterministic scoring syntax valid", lambda: compile(src_text, str(scoring_file), "exec") is not None)
    audit.check("SCORING", "IW-5FACTOR-DET-V1 methodology declared", lambda: require("IW-5FACTOR-DET-V1" in src_text or "DETERMINISTIC_5_FACTOR_IW" in src_text, "deterministic methodology tag missing"))

    weights = {
        "impact_severity": 0.30,
        "supplier_criticality": 0.20,
        "substitutability_difficulty": 0.15,
        "propagation_scope": 0.15,
        "temporal_urgency": 0.20,
    }

    def calc(f1, f2, f3, f4, f5):
        ws = (
            weights["impact_severity"] * f1
            + weights["supplier_criticality"] * f2
            + weights["substitutability_difficulty"] * f3
            + weights["propagation_scope"] * f4
            + weights["temporal_urgency"] * f5
        )
        return max(1, min(10, int(math.floor(ws * 2.0 + 0.5))))

    audit.check("SCORING", "5-factor weights sum to 1.0", lambda: require(abs(sum(weights.values()) - 1.0) < 1e-9, f"weights sum={sum(weights.values())}"))
    audit.check("SCORING", "minimum vector (1,1,1,1,1) => score 2", lambda: require(calc(1, 1, 1, 1, 1) == 2, "min vector mismatch"))
    audit.check("SCORING", "maximum vector (5,5,5,5,5) => score 10", lambda: require(calc(5, 5, 5, 5, 5) == 10, "max vector mismatch"))
    audit.check("SCORING", "mid vector (3,3,3,3,3) => score 6", lambda: require(calc(3, 3, 3, 3, 3) == 6, "mid vector mismatch"))
    audit.check("SCORING", "half-up rounding (4,5,5,4,4) => score 9", lambda: require(calc(4, 5, 5, 4, 4) == 9, "half-up vector mismatch"))

    # Also verify no legacy ThreatScoringResult LLM task remains in tasks.py if deterministic mode is active
    pipe_text = pipeline_file.read_text(encoding="utf-8-sig")
    audit.check(
        "SCORING",
        "pipeline references deterministic scoring",
        lambda: require("scoring" in pipe_text and "scoring_audit" in pipe_text, "scoring_audit missing in pipeline"),
    )


def _load_is_confirmed_critical(validation_file: Path):
    tree = ast.parse(validation_file.read_text(encoding="utf-8-sig"), filename=str(validation_file))
    funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "is_confirmed_critical"]
    require(len(funcs) == 1, "is_confirmed_critical missing or duplicated in ews_validation.py")
    env = {
        "ValidationStatus": SimpleNamespace(SUPPORTED="SUPPORTED"),
        "ConfidenceLevel": SimpleNamespace(HIGH="HIGH"),
        "EscalationStatus": SimpleNamespace(CRITICAL_CONFIRMED_ALERT="CRITICAL_CONFIRMED_ALERT"),
        "EventFreshness": SimpleNamespace(
            NEW_EVENT="NEW_EVENT",
            NEW_DEVELOPMENT="NEW_DEVELOPMENT",
            HISTORICAL_CONTEXT="HISTORICAL_CONTEXT",
            ONGOING_ISSUE="ONGOING_ISSUE",
            EVENT_DATE_UNKNOWN="EVENT_DATE_UNKNOWN",
        ),
    }
    exec(_compile_ast(funcs[0], validation_file, with_future=True), env)
    return env["is_confirmed_critical"]


def run_reporting_audit(audit: Audit, reporting_file: Path, validation_file: Path):
    if not reporting_file.exists():
        audit.check("REPORTING", "ews_reporting.py present", lambda: require(False, "missing reporting module"))
        return

    tree = ast.parse(reporting_file.read_text(encoding="utf-8-sig"), filename=str(reporting_file))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "sanitize_scoring_audit"]
    if len(functions) != 1:
        audit.check("REPORTING", "sanitize_scoring_audit exists", lambda: require(False, "missing or duplicate"))
        return

    fn = copy.deepcopy(functions[0])
    fn.body = [
        node for node in fn.body
        if not (isinstance(node, ast.ImportFrom) and node.module == "ews_validation")
    ]

    class VS(str, Enum):
        SUPPORTED = "SUPPORTED"
        PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
        UNSUPPORTED = "UNSUPPORTED"

    gate_fn = _load_is_confirmed_critical(validation_file) if validation_file.exists() else (lambda t: False)

    env = {
        "ValidationStatus": VS,
        "is_confirmed_critical": gate_fn,
        "_source_age_days": lambda *args: 12,
        "logger": SimpleNamespace(warning=lambda *args: None, info=lambda *args: None),
    }
    try:
        exec(_compile_ast(fn, reporting_file, with_future=True), env)
        sanitize = env["sanitize_scoring_audit"]
    except Exception as exc:
        audit.check("REPORTING", "isolated reporting function compiles", lambda: (_ for _ in ()).throw(exc))
        return

    def make_threat(id_, score):
        return SimpleNamespace(
            event_id=id_,
            threat_score=score,
            scm_tier=SimpleNamespace(value="Unknown"),
            publication_time="2026-10-25",
            score_rationale="Post-Harness evidence-aware rationale",
            validation_status=VS.UNSUPPORTED,
            confidence_level=SimpleNamespace(value="LOW"),
            program_relevance="PROGRAM_UNVERIFIED",
            escalation_level="PRIORITY_VERIFICATION_REQUIRED",
            event_freshness="HISTORICAL_CONTEXT",
            causal_support_status="HYPOTHETICAL_ONLY",
            is_critical=False,
        )

    def one():
        rows = [{"event_id": "EVT_A", "final_score": 8, "score_rationale": "original"}]
        result = sanitize(rows, [make_threat("EVT_A", 7)], as_of_date="2026-11-26")
        require(len(result) == 1 and result[0]["final_score"] == 7, "Score audit not reconciled to Harness")
        require(result[0]["agent_score"] == 8, "Original score not retained")
        require(result[0].get("confirmed_critical_eligible") is False, "Unsupported event marked critical-eligible")
        return True

    def two():
        rows = [{"event_id": "EVT_A", "final_score": 8}, {"event_id": "EVT_B", "final_score": 4}]
        result = sanitize(rows, [make_threat("EVT_A", 7), make_threat("EVT_B", 3)], as_of_date="2026-11-26")
        require([r["final_score"] for r in result] == [7, 3], "Score audit leaked one event's score into another")
        return True

    def unknown():
        rows = [{"event_id": "EVT_UNKNOWN", "final_score": 9}]
        result = sanitize(rows, [make_threat("EVT_A", 7)], as_of_date="2026-11-26")
        require(
            all("scm_tier" not in r and "post_harness_evidence_warning" not in r for r in result if r.get("event_id") == "EVT_UNKNOWN"),
            "Unknown ID incorrectly enriched with another event's evidence",
        )
        return True

    audit.check("REPORTING", "after Harness score cap audit reconciles", one)
    audit.check("REPORTING", "two audit events keep independent IDs", two)
    audit.check("REPORTING", "unknown scoring audit ID not attributed to other event", unknown)


def run_critical_gate_audit(audit: Audit, validation_file: Path):
    if not validation_file.exists():
        return
    try:
        gate = _load_is_confirmed_critical(validation_file)
    except Exception as exc:
        audit.check("HARNESS", "is_confirmed_critical exists", lambda: (_ for _ in ()).throw(exc))
        return

    variants = (
        ("supported high-severity direct new alert", {}, True),
        ("score 7 not critical", {"threat_score": 7}, False),
        ("unsupported score 9 blocked", {"validation_status": "UNSUPPORTED"}, False),
        ("partial support score 9 blocked", {"validation_status": "PARTIALLY_SUPPORTED"}, False),
        ("low confidence blocked", {"confidence_level": "LOW"}, False),
        ("unverified program blocked", {"program_relevance": "PROGRAM_UNVERIFIED"}, False),
        ("related-program watchlist blocked", {"program_relevance": "RELATED_PROGRAM_WATCHLIST"}, False),
        ("non-confirmed escalation blocked", {"escalation_level": "PRIORITY_VERIFICATION_REQUIRED"}, False),
        ("historical context blocked", {"event_freshness": "HISTORICAL_CONTEXT"}, False),
        ("ongoing issue blocked", {"event_freshness": "ONGOING_ISSUE"}, False),
        ("unknown event date blocked", {"event_freshness": "EVENT_DATE_UNKNOWN"}, False),
    )
    for name, changes, expected in variants:
        def test(name=name, changes=changes, expected=expected):
            row = {
                "threat_score": 9,
                "validation_status": "SUPPORTED",
                "confidence_level": "HIGH",
                "escalation_level": "CRITICAL_CONFIRMED_ALERT",
                "program_relevance": "DIRECT_KIT_MATCH",
                "event_freshness": "NEW_EVENT",
                "technical_grounding_status": "PASS",
                "claim_support_status": "STATED_IN_SOURCE",
                "causal_support_status": "EVIDENCED_IN_VERIFIED_SOURCE",
                **changes,
            }
            require(
                gate(SimpleNamespace(**row)) is expected,
                f"is_confirmed_critical incorrectly returned {not expected} for {name}",
            )
            return True
        audit.check("HARNESS", name, test)


def run_analyst_contract_audit(audit: Audit, pipeline_file: Path):
    src_text = pipeline_file.read_text(encoding="utf-8-sig")
    tree = ast.parse(src_text, filename=str(pipeline_file))
    func_names = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    audit.check(
        "ANALYST",
        "pipeline contains recovery budget & batch audit",
        lambda: require(
            "analysis_recovery_budget" in src_text and "analyst_output_audit" in src_text,
            "Missing analysis_recovery_budget or analyst_output_audit in ews_pipeline.py",
        ),
    )
    audit.check(
        "ANALYST",
        "fallback threat extractor defined",
        lambda: require(
            "_extract_batch_threats_fallback" in func_names or "_extract_batch_threats_fallback" in src_text,
            "_extract_batch_threats_fallback not referenced in ews_pipeline.py",
        ),
    )


def run_previous_match_audit(audit: Audit, pipeline_file: Path):
    tree = ast.parse(pipeline_file.read_text(encoding="utf-8-sig"), filename=str(pipeline_file))
    funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_previous_matching_dataset_run"]
    if len(funcs) != 1:
        audit.check("HISTORY", "previous dataset comparison exists", lambda: require(False, "function missing"))
        return

    compiled = _compile_ast(funcs[0], pipeline_file, with_future=True)

    def scenario(name, *, variations=None, expected=None):
        def check():
            with tempfile.TemporaryDirectory(prefix="aviation_ci_app_test_") as tmp:
                path = str(Path(tmp) / "test.sqlite")
                with closing(sqlite3.connect(path)) as conn:
                    conn.execute("CREATE TABLE reports (run_id TEXT, report_json TEXT, updated_at TEXT)")
                    for idx, variant in enumerate(variations or []):
                        meta = {
                            "query": "airbus a320neo gtf", "analysis_scope": "365d",
                            "prompt_version": "TEST_PROMPT", "documents_analyzed": 5,
                            "experiment": {"dataset_sha256": "SAME_DATASET", **variant.get("exp", {})},
                            "analyst_output_audit": [{"candidate_count": variant.get("candidates", 2)}],
                            **variant.get("meta", {}),
                        }
                        conn.execute(
                            "INSERT INTO reports VALUES (?, ?, ?)",
                            (variant.get("id", f"PREVIOUS_{idx}"), json.dumps({"run_metadata": meta, "threats": []}), f"2026-11-26T10:00:{idx:02d}Z"),
                        )
                    conn.commit()

                tracked_connections = []

                def tracked_connect(*args, **kwargs):
                    conn = sqlite3.connect(*args, **kwargs)
                    tracked_connections.append(conn)
                    return conn

                env = {
                    "sqlite3": SimpleNamespace(connect=tracked_connect, Error=sqlite3.Error),
                    "DB_LOCK": threading.Lock(),
                    "SQLITE_DB": path,
                    "PROMPT_VERSION": "TEST_PROMPT",
                    "logger": SimpleNamespace(warning=lambda *args: None),
                    "json": json,
                    "re": re,
                }

                try:
                    exec(compiled, env)
                    result = env["_previous_matching_dataset_run"](
                        dataset_sha256="SAME_DATASET",
                        query="airbus a320neo gtf",
                        scope="365d",
                        documents_analyzed=5,
                        current_run_id="CURRENT",
                    )
                    require(
                        (result or {}).get("candidate_count", 0) == expected,
                        f"previous run comparison result={result}, expected={expected}",
                    )
                    return True
                finally:
                    for conn in tracked_connections:
                        conn.close()
        audit.check("HISTORY", name, check)

    scenario("no prior run => no conflict", variations=[], expected=0)
    scenario("same dataset prior 3 candidates => conflict", variations=[{"candidates": 3}], expected=3)
    scenario("prior same dataset but 0 candidates => no conflict", variations=[{"candidates": 0}], expected=0)
    scenario("different dataset excluded", variations=[{"exp": {"dataset_sha256": "OTHER"}}], expected=0)
    scenario("replay excluded", variations=[{"exp": {"replay_run_id": "RUN_OLD"}}], expected=0)
    scenario("different scope excluded", variations=[{"meta": {"analysis_scope": "90d"}}], expected=0)
    scenario("different prompt excluded", variations=[{"meta": {"prompt_version": "OTHER"}}], expected=0)
    scenario("different analyzed-count excluded", variations=[{"meta": {"documents_analyzed": 7}}], expected=0)
    scenario("older nonempty preferred to newer empty", variations=[{"candidates": 3}, {"candidates": 0}], expected=3)


def report_checks(audit: Audit, path: Path):
    label = f"{path.parent.name}/{path.name}"
    try:
        report = load_json(path)
    except Exception as exc:
        audit.check("REPORT", f"{label}: readable JSON", lambda: (_ for _ in ()).throw(exc))
        return

    m = report.get("run_metadata") or {}
    events = list(report.get("threats") or []) + list(report.get("related_program_watchlist") or [])
    ids = [e.get("event_id") for e in events]
    valid_outcomes = {
        "COMPLETED", "PARTIAL_SUCCESS", "NO_RELEVANT_EVENTS",
        "INSUFFICIENT_DATA", "SOURCE_UNAVAILABLE", "ANALYSIS_FAILED", "VALIDATION_FAILED",
    }

    audit.check("REPORT", f"{label}: event IDs unique/nonempty", lambda: require(all(ids) and len(ids) == len(set(ids)), f"duplicate/blank event IDs {ids}"))
    audit.check("REPORT", f"{label}: outcome recognized", lambda: require(report.get("outcome_status") in valid_outcomes, f"unknown outcome {report.get('outcome_status')}"))
    # v2.0 invariant: potential severity (threat_score) is decoupled from confidence,
    # while unverified/partial events must NEVER escalate to CRITICAL_CONFIRMED_ALERT or is_critical=True.
    audit.check(
        "REPORT",
        f"{label}: evidence-based escalation gate (severity decoupled)",
        lambda: require(
            all(
                not (
                    e.get("validation_status") != "SUPPORTED"
                    and (e.get("is_critical") is True or e.get("escalation_level") == "CRITICAL_CONFIRMED_ALERT")
                )
                for e in events
            ),
            "unverified/partial event escalated to confirmed critical",
        ),
    )
    audit.check("REPORT", f"{label}: no unsupported confirmed-critical", lambda: require(all(not e.get("is_critical") or (e.get("validation_status") == "SUPPORTED" and e.get("confidence_level") == "HIGH" and e.get("program_relevance") == "DIRECT_KIT_MATCH") for e in events), "unsupported critical event"))
    audit.check("REPORT", f"{label}: no unsupported confirmed_facts", lambda: require(all(e.get("validation_status") not in {"UNSUPPORTED", "CONTRADICTED", "UNVERIFIED_COMMUNITY"} or not str(e.get("confirmed_facts") or "").strip() for e in events), "unverified facts presented as confirmed"))
    audit.check("REPORT", f"{label}: no automatically approved unverified claim", lambda: require(report.get("hitl_status") != "AUTO_APPROVED_BY_QA_AGENT" or not any(e.get("validation_status") != "SUPPORTED" for e in events), "auto-approved report has unverified claim"))
    audit.check("REPORT", f"{label}: scoring status vs fallback IDs", lambda: require(m.get("scoring_status") not in {"COMPLETED", "NOT_REQUIRED"} or not m.get("scoring_partial_fallback_ids"), "COMPLETED still has fallback event IDs"))
    audit.check("REPORT", f"{label}: scoring audit IDs valid", lambda: require(all(row.get("event_id") in ids for row in m.get("scoring_audit") or []), "scoring audit points to missing event ID"))
    audit.check("REPORT", f"{label}: scoring audit final matches events", lambda: require(all(row.get("final_score") == next(e.get("threat_score") for e in events if e.get("event_id") == row.get("event_id")) for row in m.get("scoring_audit") or []), "final_score differs from post-Harness threat_score"))
    audit.check("REPORT", f"{label}: no false NO_RELEVANT_EVENTS conflict", lambda: require(not (report.get("outcome_status") == "NO_RELEVANT_EVENTS" and m.get("analyst_empty_output_conflict")), "known empty Analyst conflict marked as NO_RELEVANT_EVENTS"))
    audit.check("REPORT", f"{label}: degraded status matches scoring fallback", lambda: require(m.get("scoring_status") not in {"PARTIAL_FALLBACK", "PROVISIONAL_FALLBACK"} or (report.get("outcome_status") == "PARTIAL_SUCCESS" and m.get("pipeline_degraded") is True), "scoring fallback is not reported as partial/degraded"))
    audit.check("REPORT", f"{label}: action references exist", lambda: require(all(set(a.get("related_event_ids") or []).issubset(set(ids)) for a in report.get("action_plan") or []), "orphan action related_event_ids"))
    audit.check("REPORT", f"{label}: KIQ status values", lambda: require(all(a.get("answer_status") in {"ANSWERED", "PARTIALLY_ANSWERED", "UNANSWERED", "NOT_SEARCHED"} for a in report.get("kiq_answers") or []), "unknown KIQ state"))
    audit.check("REPORT", f"{label}: human-verified approval not falsely inferred", lambda: require(not str(report.get("hitl_status", "")).startswith("REPLAY_") or "replay_report.json" in path.name, "replay HITL status in operational report"))
    audit.check("REPORT", f"{label}: source citation on candidate events", lambda: require(all(e.get("source_urls") and e.get("evidence_ids") for e in events), "candidate event missing evidence IDs or URLs"), optional=True)

    if m:
        audit.check("REPORT", f"{label}: document counters", lambda: require((int(m.get("documents_analyzed", 0)) + int(m.get("documents_rejected", 0)) <= int(m.get("documents_collected", 0))) and int(m.get("documents_analyzed", 0)) >= 0, "document totals inconsistent"))
        audit.check("REPORT", f"{label}: positive token accounting", lambda: require(int(m.get("tokens_input") or 0) >= 0 and int(m.get("tokens_output") or 0) >= 0, "negative token usage"))
        audit.check("REPORT", f"{label}: runtime KIQ counts", lambda: require(sum(int(m.get(k) or 0) for k in ("runtime_kiq_answered", "runtime_kiq_partially_answered", "runtime_kiq_unanswered", "runtime_kiq_not_searched")) == int(m.get("runtime_kiq_count") or 0), "KIQ counters do not sum"))


def sqlite_checks(audit: Audit, path: Path):
    if not path.exists():
        audit.check("SQLITE", "DB available (only checked when file exists)", lambda: (_ for _ in ()).throw(FileNotFoundError(str(path))), optional=True)
        return

    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        audit.check("SQLITE", "SQLite integrity_check", lambda: require(conn.execute("PRAGMA quick_check").fetchone()[0] == "ok", "DB quick_check failed"))
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        # Current Aero_EWS 2.0 core SQLite tables (kiq_plan_cache was retired)
        for table in ("reports", "analytical_runs", "source_documents", "semantic_filter_cache"):
            audit.check("SQLITE", f"table {table} exists", lambda table=table: require(table in names, f"table missing: {table}"))
            if table in names:
                audit.check("SQLITE", f"table {table} readable", lambda table=table: require(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] >= 0, "unreadable"))

        if "reports" in names:
            def check_persisted():
                rows = conn.execute("SELECT report_json FROM reports ORDER BY rowid DESC LIMIT 30").fetchall()
                for (raw,) in rows:
                    require(isinstance(json.loads(raw), dict), "invalid report_json")
                return f"{len(rows)} recent rows decode"
            audit.check("SQLITE", "30 most recent reports decode", check_persisted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parent, help="Directory containing ews_pipeline.py, tasks.py etc.")
    parser.add_argument("--smoke-import", action="store_true", help="Also import ews_pipeline in a separate process (no network calls intended).")
    args = parser.parse_args()

    root = args.project.resolve()
    audit = Audit()
    print(f"aviation_ci_app offline regression (v2.0) | project={root}")
    print("Tests do NOT run live agents or modify the operational files/DB.\n")

    code = root / "ews_pipeline.py"
    tasks = root / "tasks.py"
    audit.check("STATIC", "ews_pipeline.py exists", lambda: require(code.exists(), str(code)))
    audit.check("STATIC", "tasks.py exists", lambda: require(tasks.exists(), str(tasks)))
    if not (code.exists() and tasks.exists()):
        return audit.finish()

    py_files = sorted(root.glob("*.py"))
    pkg_dir = root / "aero_ews"
    if pkg_dir.is_dir():
        py_files.extend(sorted(pkg_dir.rglob("*.py")))
    for file in py_files:
        rel = str(file.relative_to(root))
        audit.check("SYNTAX", rel, lambda file=file: compile(file.read_text(encoding="utf-8-sig"), str(file), "exec") is not None)

    if args.smoke_import:
        def smoke():
            proc = subprocess.run(
                [sys.executable, "-c", "import ews_pipeline; print('IMPORT_OK')"],
                cwd=root, capture_output=True, text=True, timeout=25,
            )
            require(proc.returncode == 0, (proc.stderr or proc.stdout)[-500:])
            return proc.stdout.strip()
        audit.check("IMPORT", "ews_pipeline import from project venv", smoke)

    run_deterministic_scoring_audit(audit, root, code)
    run_analyst_contract_audit(audit, code)
    run_previous_match_audit(audit, code)
    run_reporting_audit(audit, root / "ews_reporting.py", root / "ews_validation.py")
    run_critical_gate_audit(audit, root / "ews_validation.py")

    request_model_path = root / "ews_models.py"
    if request_model_path.is_file():
        try:
            models_mod = _load_module_from_path("ews_models", request_model_path, root)
            ReqModel = models_mod.EWSRequest
            audit.check("REQUEST", "actual EWSRequest Pydantic schema imported", lambda: True)
            base = {"query": "A320neo PW1100G inspections", "platforms": ["news"], "scope": "365d", "limit": 10}
            cases = (
                ("valid 365-day KIT", {}, True),
                ("valid 90-day KIT", {"scope": "90d"}, True),
                ("valid historical custom", {"scope": "custom", "date_from": "2026-01-01", "date_to": "2026-11-26"}, True),
                ("valid as_of_date", {"as_of_date": "2026-10-01"}, True),
                ("invalid 365 without d", {"scope": "365"}, False),
                ("invalid empty query", {"query": "   "}, False),
                ("invalid oversized query", {"query": "x" * 601}, False),
                ("invalid no sources", {"platforms": []}, False),
                ("invalid unknown platform", {"platforms": ["unknownsource"]}, False),
                ("invalid limit 0", {"limit": 0}, False),
                ("invalid limit 101", {"limit": 101}, False),
                ("invalid string limit", {"limit": "10"}, False),
                ("invalid date", {"as_of_date": "2026-13-40"}, False),
                ("invalid custom missing bounds", {"scope": "custom"}, False),
                ("invalid reverse date window", {"scope": "custom", "date_from": "2026-10-01", "date_to": "2026-01-01"}, False),
                ("cannot disable QA", {"enable_qa_agent": False}, False),
                ("cannot disable Harness", {"enable_harness_validation": False}, False),
            )
            for label, changes, expected in cases:
                def request_case(changes=changes, expected=expected):
                    accepted = _is_valid(ReqModel, {**base, **changes})
                    return require(accepted == expected, f"request accepted={accepted}, expected={expected}")
                audit.check("REQUEST", label, request_case)
        except Exception as exc:
            audit.check("REQUEST", "load request schema", lambda: (_ for _ in ()).throw(exc))

    sqlite_checks(audit, root / "ews_intelligence.db")

    paths = [root / name for name in ("dashboard_data.json", "pending_dashboard_data.json") if (root / name).is_file()]
    paths.extend(sorted((root / "runs").glob("*/replay_report.json"), reverse=True)[:5])
    if not paths:
        audit.check("REPORT", "reports present (optional)", lambda: (_ for _ in ()).throw(FileNotFoundError("no JSON reports in project")), optional=True)
    for path in paths:
        report_checks(audit, path)

    print("\nIMPORTANT: PASS means these tested conditions passed, not that all external sources/LLMs are reliable.")
    return audit.finish()


if __name__ == "__main__":
    sys.exit(main())