"""Opt-in replay cache for exact, schema-parseable Analyst *raw outputs* only.

This never caches decisions of QA, Harness, Scoring, Editor or HITL, and is
disabled in ordinary live production runs. Bump CACHE_VERSION after changing
Analyst interpretation/validation rules.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any
from contextlib import closing


CACHE_VERSION = "ANALYST-REPLAY-PARSED-1"
_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS analyst_replay_cache ("
    "cache_key TEXT PRIMARY KEY, analyst_raw TEXT NOT NULL)"
)


def make_analyst_replay_cache_key(
    *, kit: str, scope: str, dataset_sha256: str, replay_run_id: str,
    batch_payload: str, task_description: str, expected_output: str,
    kiq_summary: str, prompt_version: str, model: dict[str, Any],
    effective_from: str, effective_to: str, as_of_date: str,
) -> str:
    """Hash the entire evidence, task and model contract, never URL alone."""
    settings = {
        "cache_version": CACHE_VERSION,
        "kit": kit,
        "scope": scope,
        "dataset_sha256": dataset_sha256,
        "replay_run_id": replay_run_id,
        "batch_payload": batch_payload,
        "task_description": task_description,
        "expected_output": expected_output,
        "kiq_summary": kiq_summary,
        "prompt_version": prompt_version,
        "model": {key: model.get(key) for key in (
            "primary_model", "fast_model", "reasoning_model", "temperature", "provider",
        )},
        "effective_from": effective_from,
        "effective_to": effective_to,
        "as_of_date": as_of_date,
    }
    return hashlib.sha256(
        json.dumps(settings, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def get_cached_analyst_raw(
    db_path: str,
    lock: Any,
    cache_key: str,
) -> str | None:

    try:
        with lock:
            with closing(sqlite3.connect(db_path)) as conn:

                conn.execute(_TABLE_SQL)

                row = conn.execute(
                    "SELECT analyst_raw "
                    "FROM analyst_replay_cache "
                    "WHERE cache_key = ?",
                    (cache_key,),
                ).fetchone()

                conn.commit()

        return row[0] if row and row[0] else None

    except sqlite3.Error:
        return None


def save_cached_analyst_raw(
    db_path: str,
    lock: Any,
    cache_key: str,
    raw: str,
) -> None:

    if not raw:
        return

    try:
        with lock:
            with closing(sqlite3.connect(db_path)) as conn:

                conn.execute(_TABLE_SQL)

                conn.execute(
                    "INSERT OR REPLACE INTO analyst_replay_cache "
                    "(cache_key, analyst_raw) VALUES (?, ?)",
                    (cache_key, raw),
                )

                conn.commit()

    except sqlite3.Error:
        return
