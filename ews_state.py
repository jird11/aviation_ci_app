"""Shared application dependencies, models, and process-local runtime state."""

# Standard library and third-party re-exports shared across backend modules.
import json, logging, math, os, re, sqlite3, threading, time, uuid
from datetime import datetime, timezone
from difflib import SequenceMatcher
from logging.handlers import RotatingFileHandler
from secrets import compare_digest
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import pandas as pd
from crewai import Crew, Process
from fastapi import FastAPI, HTTPException
from google import genai
from pydantic import BaseModel, Field

# Internal agent, task, and OSINT tool re-exports (kept stable for downstream imports).
from agents import (
    LLM_RUNTIME_STATS, PROMPT_VERSION, classify_llm_error, create_editor_agent,
    create_planner_agent, create_quality_assurance_agent, create_risk_analyst_agent,
    fast_llm, get_llm_metadata, get_llm_runtime_stats,
    reset_llm_runtime_stats,
)
from tasks import (
    ActionItem, CIDimension, ConfidenceLevel, EWSReport, EditorialOutput,
    EscalationStatus, EventFreshness, EventStatus, IntelligenceGap, KIQAnswer,
    KIQPlan, PropagationEffect, RiskType, RunOutcomeStatus, SCMTier,
    ThreatAssessment, ThreatReport, TripleAPillar,
    UrgencyLevel, ValidationStatus, create_analysis_task, create_editorial_task,
    create_planning_task, create_quality_assurance_task,
)
from tools import (
    AEROSPACE_SUPPLIER_REGISTRY, GEMINI_API_KEY, SOURCE_REGISTRY,
    extract_youtube_transcript, get_collected_documents, get_connector_telemetry,
    get_time_window_utc, is_date_within_scope, lookup_supplier_in_registry,
    normalize_date_str, normalize_scope_value, reset_collected_urls,
    scrape_airshow_website, scrape_manufacturer_pr_news,
    scrape_ntsb_investigations, scrape_regulatory_agencies,
    search_aerospace_news, search_bluesky_aviation,
)

# Stable artifact paths and workspace initialization.
LOG_FILE, PENDING_FILE, FINAL_FILE = "ews_system.log", "pending_dashboard_data.json", "dashboard_data.json"
HISTORICAL_CSV, SQLITE_DB, RUNS_DIR = "historical_threats_archive.csv", "ews_intelligence.db", "runs"
os.makedirs(RUNS_DIR, exist_ok=True)

# Configure rotating file + console logging and initialize the shared FastAPI app.
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=5, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
app = FastAPI(title="Aerospace EWS API")

# In-process thread synchronization locks and pipeline worker state.
PIPELINE_LOCK, DB_LOCK = threading.Lock(), threading.Lock()
PIPELINE_STATE: Dict[str, Any] = {
    "running": False, "cancel_requested": False, "last_status": "idle",
    "current_run_id": None, "last_run_id": None, "state": "IDLE", "last_error": None,
}


def recover_pipeline_state(
    run_id: str | None, *, error: Exception | str | None = None, outcome: str = "idle",
) -> bool:
    """Release a finished/failed run without resetting a newer active run.

    Call outside an already-held PIPELINE_LOCK. Returns False for a stale run ID.
    """
    with PIPELINE_LOCK:
        if PIPELINE_STATE.get("current_run_id") != run_id:
            return False
        failed = error is not None
        PIPELINE_STATE.update(
            running=False, cancel_requested=False, current_run_id=None, last_run_id=run_id,
            state="FAILED" if failed else "IDLE", last_status="failed" if failed else outcome,
            last_error=str(error) if failed else None,
        )
        return True


# Controlled trust-domain sets and linguistic warning markers (preserved verbatim).
OFFICIAL_HIGH_TRUST_DOMAINS = {
    "federalregister.gov", "easa.europa.eu", "ntsb.gov", "boeing.mediaroom.com",
    "boeing.com", "airbus.com", "comac.cc", "farnboroughairshow.com",
    "dubaiairshow.aero", "singaporeairshow.com", "siae.fr",
}
UNVERIFIED_SOCIAL_VIDEO_DOMAINS = {
    "bsky.app", "youtube.com", "youtu.be", "reddit.com", "tiktok.com", "x.com", "twitter.com",
}
SPECULATIVE_DISINFO_MARKERS = re.compile(
    r"\b(?:speculat\w*|rumor\w*|rumour\w*|unconfirmed|alleged\w*|conspirac\w*|"
    r"unverified|transcript unavailable|no transcript|missing evidence)\b", re.I,
)
CONTRADICTION_MARKERS = re.compile(
    r"\b(?:denied|false|debunked|hoax|no evidence of|contrary to|retracted)\b", re.I,
)