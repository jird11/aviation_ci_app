# =============================================================================
# aviation_ci_app | Shared application dependencies and mutable runtime state
#
# Responsibility: Centralize FastAPI app construction, shared model imports, path constants, logging,
#   locks, and active pipeline status.
# Design boundary: Importing this module initializes selected logging and filesystem state; other modules
#   depend on these objects.
# =============================================================================

"""Shared application state, models, dependencies, and runtime configuration."""


import logging
import os
import re
import threading
from typing import Any, Dict
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI
import json, math, sqlite3, time, uuid
from difflib import SequenceMatcher
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse
from secrets import compare_digest

import pandas as pd
from crewai import Crew, Process
from fastapi import HTTPException
from pydantic import BaseModel, Field
from google import genai

from agents import (
    LLM_RUNTIME_STATS, PROMPT_VERSION, classify_llm_error,
    create_editor_agent, create_planner_agent, create_quality_assurance_agent,
    create_risk_analyst_agent, create_scoring_agent, fast_llm,
    get_llm_metadata, get_llm_runtime_stats, reset_llm_runtime_stats
)

from tasks import (
    ActionItem, CIDimension, ConfidenceLevel, EWSReport, EditorialOutput,
    EscalationStatus, EventFreshness, EventStatus, IntelligenceGap,
    KIQAnswer, KIQPlan, PropagationEffect, RiskType, RunOutcomeStatus,
    SCMTier, ThreatAssessment, ThreatReport, ThreatScoringBatch,
    TripleAPillar, UrgencyLevel, ValidationStatus,
    create_analysis_task, create_editorial_task, create_planning_task,
    create_quality_assurance_task, create_scoring_task
)

from tools import (
    AEROSPACE_SUPPLIER_REGISTRY, GEMINI_API_KEY, SOURCE_REGISTRY,
    extract_youtube_transcript, get_collected_documents,
    get_connector_telemetry, get_time_window_utc, is_date_within_scope,
    lookup_supplier_in_registry, normalize_date_str, normalize_scope_value,
    reset_collected_urls, scrape_airshow_website,
    scrape_manufacturer_pr_news, scrape_ntsb_investigations,
    scrape_regulatory_agencies, search_aerospace_news,
    search_bluesky_aviation
)


# Persistent run artifacts and log destinations.
# These are relative paths; callers are expected to use the configured project workspace.
LOG_FILE = "ews_system.log"

PENDING_FILE = "pending_dashboard_data.json"

FINAL_FILE = "dashboard_data.json"

HISTORICAL_CSV = "historical_threats_archive.csv"

SQLITE_DB = "ews_intelligence.db"

RUNS_DIR = "runs"

os.makedirs(RUNS_DIR, exist_ok=True)


# Initialize rotating file and console diagnostics at import time.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler(
            LOG_FILE,
            maxBytes=5_000_000,
            backupCount=5,
            encoding="utf-8",
        ),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger(__name__)


# Create one shared FastAPI instance for all route modules.
app = FastAPI(title="Aerospace EWS API")


# Serialize local pipeline scheduling; this lock is process-local, not distributed.
PIPELINE_LOCK = threading.Lock()

# This lock coordinates threads in one process, not independent worker processes.
DB_LOCK = threading.Lock()


# Track active-run and cancellation status for API polling; this state is process-local.
PIPELINE_STATE: Dict[str, Any] = {
    "running": False,
    "cancel_requested": False,
    "last_status": "idle",
    "current_run_id": None,
    "state": "IDLE",
}


# Identify preferred institutional sources; domain trust alone does not verify a claim.
OFFICIAL_HIGH_TRUST_DOMAINS = {
    "federalregister.gov",
    "easa.europa.eu",
    "ntsb.gov",
    "boeing.mediaroom.com",
    "boeing.com",
    "airbus.com",
    "comac.cc",
    "farnboroughairshow.com",
    "dubaiairshow.aero",
    "singaporeairshow.com",
    "siae.fr",
}


# Classify community and video platforms as unverified until corroborated.
UNVERIFIED_SOCIAL_VIDEO_DOMAINS = {
    "bsky.app",
    "youtube.com",
    "youtu.be",
    "reddit.com",
    "tiktok.com",
    "x.com",
    "twitter.com",
}


# Flag uncertainty and speculative language for review, not automatic factual falsity.
SPECULATIVE_DISINFO_MARKERS = re.compile(
    r"\b(?:speculat\w*|rumor\w*|rumour\w*|unconfirmed|alleged\w*|conspirac\w*|"
    r"unverified|transcript unavailable|no transcript|missing evidence)\b",
    re.I,
)

CONTRADICTION_MARKERS = re.compile(
    r"\b(?:denied|false|debunked|hoax|no evidence of|contrary to|retracted)\b",
    re.I,
)
