# =============================================================================
# aviation_ci_app | Offline regression and fault-injection test harness
#
# Responsibility: Exercise core schemas, Analyst recovery, Scoring repairs, evidence governance, and
#   stored-report invariants.
# Design boundary: The harness intentionally avoids live OSINT collection, provider calls, and
#   modifications to operational data.
# =============================================================================

"""aviation_ci_app offline regression/fault-injection audit.

Place next to ews_pipeline.py, run from an activated project venv:
    python ews_final_regression.py

No API requests, live LLM calls, SQLite writes, or dashboard changes.
Uses real AST of the scoring stage and real Pydantic scoring schema, but stubs agents.
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from contextlib import closing
from datetime import date
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# Aggregate and print deterministic regression results with failure details.
class Audit:
    # Initialize the in-memory pass/fail collector; this is not application state.
    def __init__(self):
        # Track test outcomes without applying any changes to operational files.
        self.results = []

    # Execute one isolated check and retain exceptions as explicit test outcomes.
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

    # Summarize failures and return a nonzero exit code for failed invariants.
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


# Raise a descriptive assertion when a regression invariant is not satisfied.
def require(condition, message):
    if not condition:
        raise AssertionError(message)
    return True


# Check whether a payload satisfies the real Pydantic schema.
def _is_valid(model, payload) -> bool:
    try:
        model.model_validate(payload)
        return True
    except ValueError:
        return False


# Compile an isolated AST node for dependency-controlled fault injection.
def _compile_ast(node, source_path: Path, with_future: bool = False):
    body = [copy.deepcopy(node)]
    if with_future:
        future = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
        body.insert(0, future)
    mod = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
    return compile(mod, str(source_path), "exec")


# Load a structured report fixture and enforce object-shaped JSON.
def load_json(path: Path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    require(isinstance(value, dict), "JSON root must be an object")
    return value


# Locate the actual Scoring branch inside the operational pipeline AST.
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


# Load the production Scoring contract instead of a duplicated test schema.
def load_actual_scoring_schema(tasks_file: Path):
    tree = ast.parse(tasks_file.read_text(encoding="utf-8-sig"), filename=str(tasks_file))
    cls = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ThreatScoringResult"]
    require(len(cls) == 1, "ThreatScoringResult class missing/duplicated in tasks.py")
    env = {"BaseModel": BaseModel, "Field": Field, "str": str, "int": int}
    exec(_compile_ast(cls[0], tasks_file), env)
    return env["ThreatScoringResult"]


# Load the production API request contract for validation tests.
def load_actual_request_schema(models_file: Path):
    tree = ast.parse(models_file.read_text(encoding="utf-8-sig"), filename=str(models_file))
    cls = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "EWSRequest"]
    require(len(cls) == 1, "EWSRequest contract missing/duplicated")
    env = {
        "BaseModel": BaseModel, "Field": Field, "field_validator": field_validator,
        "model_validator": model_validator, "Literal": Literal, "List": List,
        "Optional": Optional, "date": date,
    }
    exec(_compile_ast(cls[0], models_file), env)
    env["EWSRequest"].model_rebuild(_types_namespace=env, force=True)
    return env["EWSRequest"]


# Build a controlled scoring payload for an individual test case.
def make_score(event_id, value=5):
    return {
        "event_id": event_id,
        "threat_score": value,
        "impact_assessment": "Potential impact; no claim of confirmed incident.",
        "supplier_criticality": "Supplier relationship not independently corroborated.",
        "temporal_urgency": "Historical publication; urgency requires manual check.",
        "score_rationale": "Potential severity based on available documents, not confirmed impact.",
    }


# Minimal stand-in for external CrewAI results in isolated tests.
class FakeResponse:
    # Store test-only LLM response data without invoking a provider.
    def __init__(self, raw):
        self.raw = raw


# Minimal stand-in for task envelopes in isolated regression tests.
class FakeTask:
    # Hold a synthetic CrewAI task description for isolated scoring tests.
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


# Prepare isolated scoring-stage dependencies and synthetic event fixtures.
# Only synthetic LLM responses are injected; no external provider is called.
def scoring_fixture(
    compiled_scoring, ScoreModel, *, initial=None, mode="valid",
    broken=None, all_broken=False, throw_initial=False,
):
    # Load real schema and source code for fault injection using isolated fixtures.
    events = ["EVT_A", "EVT_B", "EVT_C"]
    threats = [
        SimpleNamespace(
            event_id=key, threat_score=3, score_rationale="Analyst provisional",
            risk_type=SimpleNamespace(value="SUPPLY_CHAIN"),
            scm_tier=SimpleNamespace(value="Unknown"),
            company_affected="Fixture Supplier", affected_program="A320NEO_FAMILY",
            confirmed_facts="", fact_check_quote="", threat_description="",
            evidence_ids=[], publication_time="2026-10-01", is_critical=False,
        )
        for key in events
    ]
    record = SimpleNamespace(threats=threats)
    calls = []
    broken = broken or "EVT_C"
    output = initial if initial is not None else {"scores": [make_score(e, v) for e, v in zip(events, (5, 6, 7))]}

    # Exercise the real Scoring branch with mocked CrewAI call responses.
    def _run_crew(agent, task, label, **kwargs):
        calls.append(label)
        if label == "PHASE_5_SCORING":
            if throw_initial:
                raise RuntimeError("Injected first scoring call failure")
            raw = output if isinstance(output, str) else json.dumps(output)
            return FakeResponse(raw), 0, 0

        event = label.rsplit("EVT_", 1)
        event_id = f"EVT_{event[-1]}" if len(event) > 1 else "UNKNOWN"
        if mode == "repair_fail" and (all_broken or event_id == broken):
            raise RuntimeError("Injected repair failure")

        if "RATIONALE" in label:
            ident = "EVT_WRONG" if mode == "wrong_id" and event_id == broken else event_id
            return FakeResponse(json.dumps({
                "event_id": ident,
                "score_rationale": "Provisional severity explanation only; verify source evidence.",
            })), 0, 0

        score = make_score(event_id, 4)
        if mode == "wrong_id" and event_id == broken:
            score["event_id"] = "EVT_WRONG"
        return FakeResponse(json.dumps({"scores": [score]})), 0, 0

    # Require usable scoring fields before accepting a simulated model result.
    def _clean_raw_json(obj):
        raw = getattr(obj, "raw", str(obj)).strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return raw

    env = {
        "report_obj": record,
        "request": SimpleNamespace(use_keyword_baseline=False, as_of_date=None),
        "collected_docs": [], "started_at_iso": "2026-11-06T00:00:00Z",
        "tokens_in": 0, "tokens_out": 0, "json": json, "time": time,
        "logger": SimpleNamespace(info=lambda *args: None, warning=lambda *args: None),
        "create_scoring_agent": lambda: object(),
        "create_scoring_task": lambda *a, **k: FakeTask(**k),
        "_run_crew": _run_crew, "_clean_raw_json": _clean_raw_json,
        "ThreatScoringResult": ScoreModel, "Task": FakeTask,
        "scoring_status": "NOT_REQUIRED", "scoring_audit": [],
        "scoring_partial_fallback_ids": [], "scoring_duration": 0.0,
    }
    exec(compiled_scoring, env)
    return SimpleNamespace(env=env, calls=calls, threats=threats)


# Build parameterized failure cases for structured scoring recovery.
# Generate predictable malformed-score inputs to verify per-event recovery.
def test_case_factory(code, Model, scenario, expected, check_more=None):
    # Generate one malformed payload for the selected error-injection scenario.
    def execute():
        result = scoring_fixture(code, Model, **scenario)
        env = result.env
        require(env["scoring_status"] == expected, f"expected {expected}; got {env['scoring_status']}")
        assert len(env["scoring_audit"]) == (0 if scenario.get("throw_initial") else 3)
        if check_more:
            check_more(result)
        return True
    return execute


# Check report consistency after safety caps and event transformations.
# Use synthetic assessments to check post-validation report invariants.
def run_reporting_audit(audit: Audit, reporting_file: Path):
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

    # Reconstruct the minimal enum/schema interface expected by report validation.
    class VS(str, Enum):
        SUPPORTED = "SUPPORTED"
        UNSUPPORTED = "UNSUPPORTED"

    env = {
        "ValidationStatus": VS,
        "_source_age_days": lambda *args: 12,
        "logger": SimpleNamespace(warning=lambda *args: None, info=lambda *args: None),
    }
    try:
        exec(_compile_ast(fn, reporting_file, with_future=True), env)
        sanitize = env["sanitize_scoring_audit"]
    except Exception as exc:
        audit.check("REPORTING", "isolated reporting function compiles", lambda: (_ for _ in ()).throw(exc))
        return

    # Build a synthetic event for post-Harness scoring-audit checks.
    def make_threat(id_, score):
        return SimpleNamespace(
            event_id=id_, threat_score=score, scm_tier=SimpleNamespace(value="Unknown"),
            publication_time="2026-10-25", score_rationale="Post-Harness evidence-aware rationale",
            validation_status=VS.UNSUPPORTED, causal_support_status="HYPOTHETICAL_ONLY",
        )

    # Verify the first linked event retains its own scoring audit ID.
    def one():
        rows = [{"event_id": "EVT_A", "final_score": 8, "score_rationale": "original"}]
        result = sanitize(rows, [make_threat("EVT_A", 7)], as_of_date="2026-11-06")
        require(len(result) == 1 and result[0]["final_score"] == 7, "Score audit not reconciled to Harness")
        require(result[0]["agent_score"] == 8, "Original LLM score not retained")
        return True

    # Verify a second event cannot inherit the first event’s scoring audit ID.
    def two():
        rows = [{"event_id": "EVT_A", "final_score": 8}, {"event_id": "EVT_B", "final_score": 4}]
        result = sanitize(rows, [make_threat("EVT_A", 7), make_threat("EVT_B", 3)], as_of_date="2026-11-06")
        require([r["final_score"] for r in result] == [7, 3], "Score audit leaked one event's score into another")
        return True

    # Ensure unknown scoring IDs are not assigned to unrelated events.
    def unknown():
        rows = [{"event_id": "EVT_UNKNOWN", "final_score": 9}]
        result = sanitize(rows, [make_threat("EVT_A", 7)], as_of_date="2026-11-06")
        require(
            all("scm_tier" not in r and "post_harness_evidence_warning" not in r for r in result if r.get("event_id") == "EVT_UNKNOWN"),
            "Unknown ID incorrectly enriched with another event's evidence",
        )
        return True

    audit.check("REPORTING", "after Harness score cap audit reconciles", one)
    audit.check("REPORTING", "two audit events keep independent IDs", two)
    audit.check("REPORTING", "unknown scoring audit ID not attributed to other event", unknown)


# Verify that unsupported or unrelated events cannot become confirmed critical alerts.
# Exercise critical-alert eligibility without external facts.
# Tests ensure unsupported claims cannot be elevated to confirmed-critical status.
def run_critical_gate_audit(audit: Audit, validation_file: Path):
    if not validation_file.exists():
        return
    tree = ast.parse(validation_file.read_text(encoding="utf-8-sig"), filename=str(validation_file))
    funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "is_confirmed_critical"]
    if len(funcs) != 1:
        audit.check("HARNESS", "is_confirmed_critical exists", lambda: require(False, "missing critical gate"))
        return

    env = {
        "ValidationStatus": SimpleNamespace(SUPPORTED="SUPPORTED"),
        "ConfidenceLevel": SimpleNamespace(HIGH="HIGH"),
        "EscalationStatus": SimpleNamespace(CRITICAL_CONFIRMED_ALERT="CRITICAL_CONFIRMED_ALERT"),
    }
    exec(_compile_ast(funcs[0], validation_file, with_future=True), env)
    gate = env["is_confirmed_critical"]

    variants = (
        ("supported high-severity direct alert", {}, True),
        ("score 7 not critical", {"threat_score": 7}, False),
        ("unsupported score 9 blocked", {"validation_status": "UNSUPPORTED"}, False),
        ("low confidence blocked", {"confidence_level": "LOW"}, False),
        ("unverified program blocked", {"program_relevance": "PROGRAM_UNVERIFIED"}, False),
        ("related-program watchlist blocked", {"program_relevance": "RELATED_PROGRAM_WATCHLIST"}, False),
        ("non-confirmed escalation blocked", {"escalation_level": "PRIORITY_VERIFICATION_REQUIRED"}, False),
    )
    for name, changes, expected in variants:
        # Exercise critical-alert gating against supported and unsupported combinations.
        def test(name=name, changes=changes, expected=expected):
            row = {
                "threat_score": 9, "validation_status": "SUPPORTED", "confidence_level": "HIGH",
                "escalation_level": "CRITICAL_CONFIRMED_ALERT", "program_relevance": "DIRECT_KIT_MATCH",
                **changes,
            }
            require(
                gate(SimpleNamespace(**row)) is expected,
                f"is_confirmed_critical incorrectly returned {not expected} for {name}",
            )
            return True
        audit.check("HARNESS", name, test)


# Exercise valid-empty, retry, failure, and multi-batch Analyst outcomes.
# Simulate retries, empty outputs and failures with bounded fixtures.
def run_analyst_loop_audit(audit: Audit, pipeline_file: Path):
    # Exercise the Analyst batch loop under controlled provider-response failures.
    src_text = pipeline_file.read_text(encoding="utf-8-sig")
    tree = ast.parse(src_text, filename=str(pipeline_file))
    funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_execute_ews_background"]
    candidates = [
        node for node in ast.walk(funcs[0])
        if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple)
        and "_extract_batch_threats_fallback" in (ast.get_source_segment(src_text, node) or "")
        and "ANALYST EMPTY RETRY" in (ast.get_source_segment(src_text, node) or "")
    ]
    if not candidates:
        audit.check("ANALYST", "individual batch loop extracted", lambda: require(False, "loop not found"))
        return

    node = min(candidates, key=lambda x: x.end_lineno - x.lineno)
    compiled = _compile_ast(node, pipeline_file)
    audit.check("ANALYST", "real Analyst loop AST compiled", lambda: True)

    # Run the Analyst batch loop against a controlled response sequence.
    # Simulate retries, empty outputs and failures with bounded fixtures.
    def execute(
        initial, retry, *, expected_calls=1, expected_candidates=0,
        expected_empty=0, expected_retry_fail=0, expected_batch_fail=0, expected_retry_count=0,
    ):
        calls = []
        queued = list(initial if isinstance(initial, list) else [initial])
        retried = list(retry if isinstance(retry, list) else [retry])

        # Return the next synthetic Analyst result without contacting the LLM.
        def execute_crew(agent, task, label, shrink_cb=None):
            calls.append(label)
            response = retried.pop(0) if "EMPTY_RETRY" in label else queued.pop(0)
            if isinstance(response, Exception):
                raise response
            return FakeResponse(response), 0, 0

        # Extract candidate assessments from test-only response data.
        def extract(raw):
            try:
                threats = json.loads(raw).get("threats", [])
                if not isinstance(threats, list):
                    return [], 1
                events = [SimpleNamespace(event_id=e) for e in threats if isinstance(e, str)]
                return events, max(0, len(threats) - len(events))
            except (TypeError, ValueError, AttributeError):
                return [], 1

        e = {
            "batches": ["<untrusted_osint_document DOC_001>text" for _ in range(len(queued))],
            "batches_created": len(queued),
            "request": SimpleNamespace(query="A320neo GTF inspection"),
            "norm_scope": "365d", "kiq_summary": "fixture", "PIPELINE_STATE": {},
            "tokens_in": 0, "tokens_out": 0,
            "create_risk_analyst_agent": lambda: object(),
            "create_analysis_task": lambda *a, **k: FakeTask(description="original documented source"),
            "_run_crew": execute_crew, "_extract_batch_threats_fallback": extract,
            "logger": SimpleNamespace(info=lambda *x: None, warning=lambda *x: None, error=lambda *x: None),
            "all_candidate_threats": [], "batches_succeeded": 0, "batches_failed": 0, "documents_failed": 0,
            "analyst_invalid_batches": 0, "analyst_valid_empty_batches": 0, "analyst_empty_retry_count": 0,
            "analyst_empty_retry_failed_batches": 0, "candidate_schema_rejections": 0, "analyst_output_audit": [],
            "json": json, "re": re, "enumerate": enumerate,
        }
        exec(compiled, e)
        require(len(calls) == expected_calls, f"calls={calls} expected={expected_calls}")
        require(len(e["all_candidate_threats"]) == expected_candidates, f"candidates={e['all_candidate_threats']} expected={expected_candidates}")
        require(e["analyst_valid_empty_batches"] == expected_empty, f"empty batches={e['analyst_valid_empty_batches']}")
        require(e["analyst_empty_retry_failed_batches"] == expected_retry_fail, f"retry failures={e['analyst_empty_retry_failed_batches']}")
        require(e["analyst_empty_retry_count"] == expected_retry_count, f"retry count={e['analyst_empty_retry_count']}")
        require(e["batches_failed"] == expected_batch_fail, f"batch failures={e['batches_failed']}")
        return True

    tests = (
        ("valid 3 candidates => no retry", dict(initial='{"threats":["A","B","C"]}', retry=[], expected_candidates=3)),
        ("valid empty => one retry recovers 3", dict(initial='{"threats":[]}', retry='{"threats":["A","B","C"]}', expected_calls=2, expected_candidates=3, expected_retry_count=1)),
        ("two valid empty => visible uncertainty", dict(initial='{"threats":[]}', retry='{"threats":[]}', expected_calls=2, expected_empty=1, expected_retry_count=1)),
        ("empty then exception => retry failure count", dict(initial='{"threats":[]}', retry=RuntimeError("injected retry failure"), expected_calls=2, expected_empty=1, expected_retry_count=1, expected_retry_fail=1)),
        ("first Analyst call fails => batch failure count", dict(initial=RuntimeError("injected primary failure"), retry=[], expected_batch_fail=1)),
        ("schema-invalid output => batch counted as processed", dict(initial="not a JSON object", retry=[], expected_empty=0)),
        ("two batches: one success, one empty recovered", dict(initial=['{"threats":["A"]}', '{"threats":[]}'], retry=['{"threats":["B"]}'], expected_calls=3, expected_candidates=2, expected_retry_count=1)),
        ("two batches: one exception and one success", dict(initial=[RuntimeError("first batch offline"), '{"threats":["B"]}'], retry=[], expected_calls=2, expected_candidates=1, expected_batch_fail=1)),
    )
    for name, kw in tests:
        audit.check("ANALYST", name, lambda kw=kw: execute(**kw))


# Check same-dataset history matching against replay and scope differences.
# Compare synthetic dataset identity, not the operational history.
def run_previous_match_audit(audit: Audit, pipeline_file: Path):
    tree = ast.parse(pipeline_file.read_text(encoding="utf-8-sig"), filename=str(pipeline_file))
    funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_previous_matching_dataset_run"]
    if len(funcs) != 1:
        audit.check("HISTORY", "previous dataset comparison exists", lambda: require(False, "function missing"))
        return

    compiled = _compile_ast(funcs[0], pipeline_file, with_future=True)

    # Build one historical comparison case with the supplied dataset attributes.
    # Compare synthetic dataset identity, not the operational history.
    def scenario(name, *, variations=None, expected=None):
        # Evaluate whether this constructed dataset should match a prior run.
        # Test fixtures and injected failures remain isolated from live agents and persistent state.
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
                            (variant.get("id", f"PREVIOUS_{idx}"), json.dumps({"run_metadata": meta, "threats": []}), f"2026-11-06T10:00:{idx:02d}Z"),
                        )
                    conn.commit()


                tracked_connections = []

                # Instrument a test-only database call so history matching can be asserted.
                def tracked_connect(*args, **kwargs):
                    conn = sqlite3.connect(*args, **kwargs)
                    tracked_connections.append(conn)
                    return conn

                env = {
                    "sqlite3": SimpleNamespace(
                        connect=tracked_connect,
                        Error=sqlite3.Error,
                    ),
                    "DB_LOCK": threading.Lock(),
                    "SQLITE_DB": path,
                    "PROMPT_VERSION": "TEST_PROMPT",
                    "logger": SimpleNamespace(
                        warning=lambda *args: None
                    ),
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


# Validate historical JSON report invariants without modifying report files.
# Read reports and validate schema invariants without editing them.
def report_checks(audit: Audit, path: Path):
    # Validate only read-only report invariants.
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
    audit.check("REPORT", f"{label}: evidence-based severity cap", lambda: require(all(not (e.get("validation_status") != "SUPPORTED" and int(e.get("threat_score") or 0) >= 8) for e in events), "unverified/partial event carries score >= 8"))
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


# Check SQLite integrity and the presence of required persistence tables.
# Database validation is strictly read-only and must release file handles after inspection.
def sqlite_checks(audit: Audit, path: Path):
    # Inspect existing SQLite schema and integrity without writing data.
    if not path.exists():
        audit.check("SQLITE", "DB available (only checked when file exists)", lambda: (_ for _ in ()).throw(FileNotFoundError(str(path))), optional=True)
        return

    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        audit.check("SQLITE", "SQLite integrity_check", lambda: require(conn.execute("PRAGMA quick_check").fetchone()[0] == "ok", "DB quick_check failed"))
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("reports", "analytical_runs", "source_documents", "kiq_plan_cache", "semantic_filter_cache"):
            audit.check("SQLITE", f"table {table} exists", lambda table=table: require(table in names, f"table missing: {table}"))
            if table in names:
                audit.check("SQLITE", f"table {table} readable", lambda table=table: require(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] >= 0, "unreadable"))

        if "reports" in names:
            # Implement the check persisted helper used by this local workflow.
            def check_persisted():
                rows = conn.execute("SELECT report_json FROM reports ORDER BY rowid DESC LIMIT 30").fetchall()
                for (raw,) in rows:
                    require(isinstance(json.loads(raw), dict), "invalid report_json")
                return f"{len(rows)} recent rows decode"
            audit.check("SQLITE", "30 most recent reports decode", check_persisted)


# Run the offline regression catalog and summarize pass/fail outcomes.
# Test fixtures and injected failures remain isolated from live agents and persistent state.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parent, help="Directory containing ews_pipeline.py, tasks.py etc.")
    parser.add_argument("--smoke-import", action="store_true", help="Also import ews_pipeline in a separate process (no network calls intended).")
    args = parser.parse_args()

    root = args.project.resolve()
    audit = Audit()
    print(f"aviation_ci_app offline regression | project={root}")
    print("Tests do NOT run live agents or modify the operational files/DB.\n")

    code = root / "ews_pipeline.py"
    tasks = root / "tasks.py"
    audit.check("STATIC", "ews_pipeline.py exists", lambda: require(code.exists(), str(code)))
    audit.check("STATIC", "tasks.py exists", lambda: require(tasks.exists(), str(tasks)))
    if not (code.exists() and tasks.exists()):
        return audit.finish()

    for file in sorted(root.glob("*.py")):
        audit.check("SYNTAX", file.name, lambda file=file: compile(file.read_text(encoding="utf-8-sig"), str(file), "exec") is not None)

    if args.smoke_import:
        # Implement the smoke helper used by this local workflow.
        def smoke():
            proc = subprocess.run(
                [sys.executable, "-c", "import ews_pipeline; print('IMPORT_OK')"],
                cwd=root, capture_output=True, text=True, timeout=25,
            )
            require(proc.returncode == 0, (proc.stderr or proc.stdout)[-500:])
            return proc.stdout.strip()
        audit.check("IMPORT", "ews_pipeline import from project venv", smoke)

    code_obj, Model = None, None

    # Retrieve stage.
    def get_stage():
        nonlocal code_obj
        code_obj = find_real_scoring_if(code)
        return "scoring stage AST compiled"

    # Retrieve model.
    def get_model():
        nonlocal Model
        Model = load_actual_scoring_schema(tasks)
        return "real ThreatScoringResult schema loaded"

    audit.check("SCORING", "real Scoring stage AST isolated", get_stage)
    audit.check("SCORING", "real Pydantic scoring schema isolated", get_model)

    if code_obj and Model:
        # Implement the scenario helper used by this local workflow.
        def scenario(name, kwargs, exp, extra=None):
            audit.check("INJECTION", name, test_case_factory(code_obj, Model, kwargs, exp, extra))

        # Implement the clean three helper used by this local workflow.
        def clean_three(out):
            require(len(out.calls) == 1, "Unexpected repair call")
            require([t.threat_score for t in out.threats] == [5, 6, 7], "Scoring not applied")
            require(all(x["scoring_source"] == "ORIGINAL_VALID" for x in out.env["scoring_audit"]), "valid events unexpectedly repaired")

        scenario("three complete scores – zero retries", {}, "COMPLETED", clean_three)

        mutations = (
            (lambda a: a.pop("score_rationale"), "missing rationale", "RATIONALE"),
            (lambda a: a.update(score_rationale=None), "null rationale", "RATIONALE"),
            (lambda a: a.update(score_rationale=" "), "blank rationale", "RATIONALE"),
            (lambda a: a.update(score_rationale="short"), "short rationale", "RATIONALE"),
            (lambda a: a.update(threat_score=0), "score below 1", "SINGLE_EVENT"),
            (lambda a: a.update(threat_score=11), "score above 10", "SINGLE_EVENT"),
            (lambda a: a.pop("impact_assessment"), "missing impact", "SINGLE_EVENT"),
            (lambda a: a.pop("supplier_criticality"), "missing supplier criticality", "SINGLE_EVENT"),
            (lambda a: a.pop("temporal_urgency"), "missing urgency", "SINGLE_EVENT"),
            (lambda a: a.update(threat_score="NaN"), "invalid numeric score", "SINGLE_EVENT"),
        )
        for mutate, name, check_label in mutations:
            initial = {"scores": [make_score(e, v) for e, v in zip(("EVT_A", "EVT_B", "EVT_C"), (5, 6, 7))]}
            mutate(initial["scores"][2])

            # Implement the extra helper used by this local workflow.
            def extra(out, check_label=check_label):
                require(len(out.calls) == 2, f"expected 1 targeted retry; got {out.calls}")
                require(check_label in out.calls[-1], f"wrong repair mode: {out.calls[-1]}")
                require([t.threat_score for t in out.threats[:2]] == [5, 6], "valid scores lost")
                require(out.env["scoring_partial_fallback_ids"] == [], "unexpected fallback")

            scenario(name, {"initial": initial}, "COMPLETED", extra)

        with_items = lambda items: {"scores": items}
        base_three = lambda: [make_score("EVT_A", 5), make_score("EVT_B", 6), make_score("EVT_C", 7)]

        scenario("unknown extra ID ignored", {"initial": with_items(base_three() + [make_score("EVT_UNKNOWN")])}, "COMPLETED")
        scenario("duplicate ID repaired only for affected event", {"initial": with_items(base_three() + [make_score("EVT_C", 7)])}, "COMPLETED")
        scenario("missing event score repaired", {"initial": with_items(base_three()[:2])}, "COMPLETED")
        scenario("empty score array repaired per event", {"initial": with_items([])}, "COMPLETED")
        scenario("non-list score payload repaired", {"initial": {"scores": "no list"}}, "COMPLETED")
        scenario("invalid JSON repaired", {"initial": "not a json response"}, "COMPLETED")
        scenario("markdown-fenced JSON parsed", {"initial": f"```json\n{json.dumps(with_items(base_three()))}\n```"}, "COMPLETED")

        initial_missing_rat = with_items(base_three())
        initial_missing_rat["scores"][2].pop("score_rationale")

        # Implement the one fallback helper used by this local workflow.
        def one_fallback(out):
            require(out.env["scoring_partial_fallback_ids"] == ["EVT_C"], "fallback IDs incorrect")
            require([t.threat_score for t in out.threats] == [5, 6, 3], "valid scores lost or provisional changed")
            require(out.env["scoring_audit"][-1]["scoring_source"] == "ANALYST_PROVISIONAL_FALLBACK", "fallback not traceable in audit")

        scenario("rationale retry raises exception – only one fallback", {"initial": initial_missing_rat, "mode": "repair_fail"}, "PARTIAL_FALLBACK", one_fallback)
        scenario("rationale retry returns wrong event ID – only one fallback", {"initial": initial_missing_rat, "mode": "wrong_id"}, "PARTIAL_FALLBACK", one_fallback)
        scenario("all three repairs fail – provisional fallback", {"initial": with_items([]), "mode": "repair_fail", "all_broken": True}, "PROVISIONAL_FALLBACK")
        scenario("first scoring LLM call fails – safe fallback", {"throw_initial": True}, "PROVISIONAL_FALLBACK")

        for val, ok in ((1, True), (10, True), (0, False), (11, False), (-1, False), ("abc", False)):
            # Implement the model case helper used by this local workflow.
            def model_case(val=val, ok=ok):
                passed = _is_valid(Model, make_score("EVT_A", val))
                return require(passed == ok, f"validation result for score={val!r}: {passed}")
            audit.check("SCHEMA", f"score range {val!r}", model_case)

        for rationale, valid in ((None, False), ("", False), ("short", False), ("Enough chars for a valid rationale", True)):
            # Implement the rationale case helper used by this local workflow.
            def rationale_case(rationale=rationale, valid=valid):
                passed = _is_valid(Model, {**make_score("EVT_A"), "score_rationale": rationale})
                return require(passed == valid, f"rationale={rationale!r} accepted={passed}")
            audit.check("SCHEMA", f"rationale length/type {str(rationale)!r}", rationale_case)

    run_analyst_loop_audit(audit, code)
    run_previous_match_audit(audit, code)
    run_reporting_audit(audit, root / "ews_reporting.py")
    run_critical_gate_audit(audit, root / "ews_validation.py")

    request_model_path = root / "ews_models.py"
    if request_model_path.is_file():
        try:
            ReqModel = load_actual_request_schema(request_model_path)
            audit.check("REQUEST", "actual EWSRequest Pydantic schema extracted", lambda: True)
            base = {"query": "A320neo PW1100G inspections", "platforms": ["news"], "scope": "365d", "limit": 10}
            cases = (
                ("valid 365-day KIT", {}, True),
                ("valid 90-day KIT", {"scope": "90d"}, True),
                ("valid historical custom", {"scope": "custom", "date_from": "2026-01-01", "date_to": "2026-11-06"}, True),
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
                # Implement the request case helper used by this local workflow.
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