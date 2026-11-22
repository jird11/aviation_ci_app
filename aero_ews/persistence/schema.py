"""Stable SQLite schema, backward-compatible migrations and built-in KIQ fixtures."""

import sqlite3
from typing import Any, Dict, List


DEFAULT_KIQ_CATALOG: List[Dict[str, Any]] = [
    {
        "kiq_id": "KIQ_1_1", "kit_id": "KIT_1",
        "kit_title": "Supply Chain – Production and Delivery Disruptions",
        "question": "Which aerospace suppliers are reporting production delays or delivery disruptions?",
        "monitored_entities": ["Airbus", "Boeing", "Spirit AeroSystems", "Safran", "Pratt & Whitney", "GE Aerospace"],
        "indicators": ["IND_1_1A: Production delay", "IND_1_1B: Delivery postponement", "IND_1_1C: Supplier factory disruption"],
        "time_scope": "30d", "sources": ["News API", "Official PR Releases"],
        "expected_output": "Identify affected suppliers and potential production impacts.",
        "verification_rule": "Corroborate with official supplier or manufacturer announcements.",
        "priority": "CRITICAL", "owner": "Supply Chain Manager",
    },
    {
        "kiq_id": "KIQ_1_2", "kit_id": "KIT_1",
        "kit_title": "Supply Chain – Critical Materials and Components",
        "question": "Are critical aircraft components or aerospace raw materials at risk of shortage?",
        "monitored_entities": ["Safran", "GE Aerospace", "Howmet", "Spirit AeroSystems", "Collins Aerospace", "VSMPO-AVISMA"],
        "indicators": ["IND_1_2A: Critical component shortage", "IND_1_2B: Raw material supply restriction", "IND_1_2C: Supplier financial distress or strike"],
        "time_scope": "90d", "sources": ["News API", "Official PR Releases"],
        "expected_output": "Detect critical component and material supply exposure.",
        "verification_rule": "Seek independent corroboration; qualify any unverified signal.",
        "priority": "HIGH", "owner": "Procurement Manager",
    },
    {
        "kiq_id": "KIQ_2_1", "kit_id": "KIT_2",
        "kit_title": "Competitive Environment – Strategy and Innovation",
        "question": "What strategic innovations, product launches or partnerships are aerospace competitors introducing?",
        "monitored_entities": ["Airbus", "Boeing", "COMAC", "Embraer"],
        "indicators": ["IND_2_1A: New aircraft product announcement", "IND_2_1B: Strategic partnership or alliance", "IND_2_1C: New competitive technology or business model"],
        "time_scope": "7d", "sources": ["Airshow Websites", "News API", "Official PR Releases"],
        "expected_output": "Identify strategic competitor moves and innovation signals.",
        "verification_rule": "Confirm material strategic claims through primary company releases.",
        "priority": "HIGH", "owner": "Strategy Director",
    },
    {
        "kiq_id": "KIQ_2_2", "kit_id": "KIT_2",
        "kit_title": "Competitive Environment – Aircraft Orders and Contracts",
        "question": "Which major aircraft orders, fleet contracts or cancellations have competitors announced?",
        "monitored_entities": ["Airbus", "Boeing", "COMAC", "Embraer"],
        "indicators": ["IND_2_2A: New firm aircraft order", "IND_2_2B: Fleet purchase agreement", "IND_2_2C: Major order cancellation"],
        "time_scope": "7d", "sources": ["Airshow Websites", "Official PR Releases", "News API"],
        "expected_output": "Monitor competitor orderbooks and commercial positioning.",
        "verification_rule": "Validate firm orders against manufacturer or airline announcements.",
        "priority": "HIGH", "owner": "Market Intelligence Manager",
    },
    {
        "kiq_id": "KIQ_3_1", "kit_id": "KIT_3",
        "kit_title": "Technological Trends and Aviation Regulation",
        "question": "How do emerging aircraft technologies, SAF developments and technology-related regulations affect aerospace development?",
        "monitored_entities": ["Airbus", "Boeing", "EASA", "FAA", "Safran", "GE Aerospace"],
        "indicators": ["IND_3_1A: New propulsion or aircraft technology", "IND_3_1B: SAF technology and availability", "IND_3_1C: Emissions or technology certification regulation"],
        "time_scope": "365d", "sources": ["FAA & EASA Regulations", "News API", "Official PR Releases"],
        "expected_output": "Identify emerging technologies and strategic regulatory changes.",
        "verification_rule": "Check technology and regulation claims against primary documentation.",
        "priority": "HIGH", "owner": "Technology Strategy Manager",
    },
]


_DDL_SCRIPT = """
CREATE TABLE IF NOT EXISTS analytical_runs (
    run_id TEXT PRIMARY KEY, report_id TEXT, started_at TEXT, completed_at TEXT,
    status TEXT, outcome_status TEXT, query TEXT, normalized_query TEXT,
    analysis_scope TEXT, effective_from TEXT, effective_to TEXT, as_of_date TEXT,
    platforms_json TEXT, search_limit INTEGER, documents_collected INTEGER,
    documents_analyzed INTEGER, documents_rejected INTEGER, events_identified INTEGER,
    count_critical INTEGER, count_elevated INTEGER, count_monitored INTEGER,
    new_events INTEGER, continuing_events INTEGER, resolved_events INTEGER,
    collection_duration REAL, analysis_duration REAL, qa_duration REAL,
    total_duration REAL, validation_errors INTEGER, llm_calls INTEGER,
    tokens_input INTEGER, tokens_output INTEGER, estimated_cost REAL,
    model_id TEXT, prompt_version TEXT, ablation_config_json TEXT,
    connector_telemetry_json TEXT
);
CREATE TABLE IF NOT EXISTS source_documents (
    doc_id TEXT, run_id TEXT, source_id TEXT, connector_name TEXT, url TEXT,
    publisher_domain TEXT, origin_type TEXT, source_type TEXT, verified_domain INTEGER,
    title TEXT, text TEXT, published_at TEXT, collected_at TEXT, query_used TEXT,
    syndication_fingerprint TEXT, prompt_injection_flagged INTEGER, pii_redacted_count INTEGER,
    content_status TEXT DEFAULT 'TEXT_COMPLETENESS_UNVERIFIED', content_sha256 TEXT,
    content_truncated INTEGER DEFAULT 0, content_limit_reason TEXT,
    source_metadata_json TEXT,
    PRIMARY KEY (doc_id, run_id)
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY, canonical_url TEXT, syndication_fingerprint TEXT,
    company_affected TEXT, risk_type TEXT, scm_tier TEXT, ci_dimension TEXT,
    propagation_effect TEXT, geographic_epicenter TEXT, threat_description TEXT,
    confirmed_facts TEXT, analytical_interpretation TEXT, hypothetical_scenario TEXT,
    fact_check_quote TEXT, threat_score INTEGER, score_rationale TEXT,
    confidence_level TEXT, urgency TEXT, escalation_level TEXT, event_status TEXT,
    validation_status TEXT, verification_status TEXT, first_seen_at TEXT,
    last_seen_at TEXT, updated_at TEXT, kiq_ids_json TEXT, source_urls_json TEXT,
    evidence_ids_json TEXT, impact_path_json TEXT, corroboration_json TEXT, missing_data TEXT
);
CREATE TABLE IF NOT EXISTS event_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, run_id TEXT,
    recorded_at TEXT, threat_score INTEGER, confidence_level TEXT,
    event_status TEXT, change_type TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY, run_id TEXT, version INTEGER, hitl_status TEXT,
    outcome_status TEXT, created_at TEXT, updated_at TEXT, report_json TEXT
);
CREATE TABLE IF NOT EXISTS review_decisions (
    decision_id TEXT PRIMARY KEY, report_id TEXT, run_id TEXT, version_reviewed INTEGER,
    reviewer_name TEXT, reviewer_role TEXT, decision TEXT,
    rejected_event_ids_json TEXT, rationale TEXT, decided_at TEXT
);
CREATE TABLE IF NOT EXISTS analyst_feedback (
    feedback_id TEXT PRIMARY KEY, event_id TEXT, report_id TEXT, analyst_name TEXT,
    feedback_type TEXT, corrected_risk_type TEXT, corrected_score INTEGER,
    flagged_source_url TEXT, added_missing_info TEXT, proposed_kiq TEXT,
    rationale TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS kiq_catalog (
    kiq_id TEXT PRIMARY KEY, kit_id TEXT, kit_title TEXT, question TEXT,
    monitored_entities_json TEXT, indicators_json TEXT, time_scope TEXT,
    sources_json TEXT, expected_output TEXT, verification_rule TEXT,
    priority TEXT, owner TEXT, active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS reference_dataset (
    case_id TEXT PRIMARY KEY, kit_topic TEXT, company_affected TEXT,
    expected_scm_tier TEXT, expected_program TEXT, headline_or_topic TEXT,
    problem_keywords TEXT, is_relevant INTEGER, reference_risk_type TEXT,
    reference_threat_score INTEGER, source_url TEXT, published_date TEXT,
    supporting_quote TEXT, evaluator_comment TEXT, verification_state TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS usability_logs (
    log_id TEXT PRIMARY KEY, view_mode TEXT, task_type TEXT,
    duration_ms INTEGER, notes TEXT, recorded_at TEXT
);
CREATE TABLE IF NOT EXISTS document_filter_log (
    run_id TEXT, doc_id TEXT, source_id TEXT, url TEXT, title TEXT,
    filter_stage TEXT, is_accepted INTEGER, signal_type TEXT,
    entities_models_tech TEXT, matched_kiq_id TEXT, decision_rationale TEXT,
    evaluated_at TEXT, PRIMARY KEY (run_id, doc_id)
);
"""


def migrate_schema(connection: sqlite3.Connection) -> bool:
    """Initialize tables and add legacy evidence metadata once, preserving existing rows.

    Returns True only when the missing column was added. Call during database
    initialization; executing _DDL_SCRIPT alone cannot migrate an existing table.
    """
    connection.executescript(_DDL_SCRIPT)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(source_documents)")}
    if "source_metadata_json" in columns:
        return False
    try:
        connection.execute("ALTER TABLE source_documents ADD COLUMN source_metadata_json TEXT")
    except sqlite3.OperationalError as exc:
        # Concurrent migrations may race after the schema check; reject all other failures.
        columns = {row[1] for row in connection.execute("PRAGMA table_info(source_documents)")}
        if "duplicate column" not in str(exc).lower() or "source_metadata_json" not in columns:
            raise
        return False
    return True
