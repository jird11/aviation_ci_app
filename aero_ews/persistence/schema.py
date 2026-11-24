"""Stable SQLite schema, backward-compatible migrations, and built-in KIQ fixtures."""

import sqlite3
from typing import Any, Dict, List

# Built-in KIQ catalog fixtures (all IDs, titles, questions, indicators, and rules preserved verbatim).
_KIQ_FIELDS = (
    "kiq_id", "kit_id", "kit_title", "question", "monitored_entities", "indicators",
    "time_scope", "sources", "expected_output", "verification_rule", "priority", "owner",
)
DEFAULT_KIQ_CATALOG: List[Dict[str, Any]] = [
    dict(zip(_KIQ_FIELDS, row))
    for row in (
        (
            "KIQ_1_1",
            "KIT_1",
            "Supply Chain – Production and Delivery Continuity",
            "Which aircraft manufacturers or aerospace suppliers are experiencing production disruptions, bottlenecks, or delivery delays?",
            [],
            [
                "IND_1_1A: Production rate change or slowdown",
                "IND_1_1B: Delivery delay or schedule slippage",
                "IND_1_1C: Manufacturing or logistics disruption",
            ],
            "30d",
            ["News API", "Official PR Releases"],
            "Detect operational delays and delivery risks across aerospace manufacturing and supply chains.",
            "Corroborate with official manufacturer/supplier disclosures or regulatory filings.",
            "CRITICAL",
            "Supply Chain Manager",
        ),
        (
            "KIQ_1_2",
            "KIT_1",
            "Supply Chain – Critical Inputs, Capacity, and Supplier Stability",
            "Are there shortages, capacity constraints, or stability risks affecting critical aerospace components, raw materials, or suppliers?",
            [],
            [
                "IND_1_2A: Critical component or raw material constraint",
                "IND_1_2B: Supplier capacity bottleneck or labor/financial issue",
                "IND_1_2C: Quality or durability defect affecting supply",
            ],
            "90d",
            ["News API", "Official PR Releases", "SEC EDGAR"],
            "Identify supply bottlenecks, critical input risks, and supplier-level vulnerabilities.",
            "Cross-check across multiple independent sources or primary corporate filings.",
            "HIGH",
            "Procurement Manager",
        ),
        (
            "KIQ_2_1",
            "KIT_2",
            "Market & Competitive Dynamics – Programs, Strategy, and Partnerships",
            "What major program milestones, product launches, strategic partnerships, or restructuring moves are occurring across the aerospace market?",
            [],
            [
                "IND_2_1A: Aircraft, engine, or system program milestone",
                "IND_2_1B: Strategic partnership, M&A, or joint venture",
                "IND_2_1C: Competitive positioning or business model shift",
            ],
            "14d",
            ["Airshow Websites", "News API", "Official PR Releases"],
            "Track competitive developments, strategic alliances, and major industry moves.",
            "Verify strategic claims against primary company announcements or official filings.",
            "HIGH",
            "Strategy Director",
        ),
        (
            "KIQ_2_2",
            "KIT_2",
            "Market & Competitive Dynamics – Orders, Contracts, and Fleet Demand",
            "What significant aircraft or propulsion orders, contract awards, modifications, or cancellations have been announced?",
            [],
            [
                "IND_2_2A: Firm order or fleet agreement",
                "IND_2_2B: Contract award, extension, or commercial commitment",
                "IND_2_2C: Order deferral, reduction, or cancellation",
            ],
            "14d",
            ["Airshow Websites", "Official PR Releases", "News API"],
            "Monitor commercial demand signals, backlog changes, and contract risks.",
            "Confirm order or contract details via manufacturer, operator, or filing sources.",
            "HIGH",
            "Market Intelligence Manager",
        ),
        (
            "KIQ_3_1",
            "KIT_3",
            "Technology, Safety, and Regulation – Certification and Airworthiness",
            "How are regulatory decisions, certification milestones, airworthiness actions, or safety mandates affecting aircraft and propulsion programs?",
            [],
            [
                "IND_3_1A: Certification milestone or regulatory timeline update",
                "IND_3_1B: Airworthiness directive, safety finding, or compliance requirement",
                "IND_3_1C: New or amended aviation regulation",
            ],
            "365d",
            ["FAA & EASA Regulations", "News API", "Official PR Releases"],
            "Track regulatory gates, airworthiness actions, and compliance impacts on programs.",
            "Verify regulatory actions and dates against primary authority publications.",
            "HIGH",
            "Regulatory & Certification Manager",
        ),
        (
            "KIQ_3_2",
            "KIT_3",
            "Technology, Safety, and Regulation – Emerging Tech and Sustainability",
            "What emerging propulsion, digital/avionics, manufacturing, or sustainable aviation fuel (SAF) developments are shaping industry requirements?",
            [],
            [
                "IND_3_2A: Propulsion, airframe, or avionics technology advance",
                "IND_3_2B: SAF production, adoption, or policy/standard shift",
                "IND_3_2C: Environmental or emissions requirement change",
            ],
            "365d",
            ["FAA & EASA Regulations", "News API", "Official PR Releases"],
            "Identify medium- and long-term technological and sustainability shifts in aviation.",
            "Check technical and sustainability claims against primary technical or regulatory sources.",
            "MEDIUM",
            "Technology Strategy Manager",
        ),
    )
]

# Declarative SQLite table definitions (compiled into _DDL_SCRIPT with identical tables/columns/defaults).
_TABLES = (
    ("analytical_runs", "run_id TEXT PRIMARY KEY, report_id TEXT, started_at TEXT, completed_at TEXT, status TEXT, outcome_status TEXT, query TEXT, normalized_query TEXT, analysis_scope TEXT, effective_from TEXT, effective_to TEXT, as_of_date TEXT, platforms_json TEXT, search_limit INTEGER, documents_collected INTEGER, documents_analyzed INTEGER, documents_rejected INTEGER, events_identified INTEGER, count_critical INTEGER, count_elevated INTEGER, count_monitored INTEGER, new_events INTEGER, continuing_events INTEGER, resolved_events INTEGER, collection_duration REAL, analysis_duration REAL, qa_duration REAL, total_duration REAL, validation_errors INTEGER, llm_calls INTEGER, tokens_input INTEGER, tokens_output INTEGER, estimated_cost REAL, model_id TEXT, prompt_version TEXT, ablation_config_json TEXT, connector_telemetry_json TEXT"),
    ("source_documents", "doc_id TEXT, run_id TEXT, source_id TEXT, connector_name TEXT, url TEXT, publisher_domain TEXT, origin_type TEXT, source_type TEXT, verified_domain INTEGER, title TEXT, text TEXT, published_at TEXT, collected_at TEXT, query_used TEXT, syndication_fingerprint TEXT, prompt_injection_flagged INTEGER, pii_redacted_count INTEGER, content_status TEXT DEFAULT 'TEXT_COMPLETENESS_UNVERIFIED', content_sha256 TEXT, content_truncated INTEGER DEFAULT 0, content_limit_reason TEXT, source_metadata_json TEXT, PRIMARY KEY (doc_id, run_id)"),
    ("events", "event_id TEXT PRIMARY KEY, canonical_url TEXT, syndication_fingerprint TEXT, company_affected TEXT, risk_type TEXT, scm_tier TEXT, ci_dimension TEXT, propagation_effect TEXT, geographic_epicenter TEXT, threat_description TEXT, confirmed_facts TEXT, analytical_interpretation TEXT, hypothetical_scenario TEXT, fact_check_quote TEXT, threat_score INTEGER, score_rationale TEXT, confidence_level TEXT, urgency TEXT, escalation_level TEXT, event_status TEXT, validation_status TEXT, verification_status TEXT, first_seen_at TEXT, last_seen_at TEXT, updated_at TEXT, kiq_ids_json TEXT, source_urls_json TEXT, evidence_ids_json TEXT, impact_path_json TEXT, corroboration_json TEXT, missing_data TEXT"),
    ("event_history", "history_id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, run_id TEXT, recorded_at TEXT, threat_score INTEGER, confidence_level TEXT, event_status TEXT, change_type TEXT, notes TEXT"),
    ("reports", "report_id TEXT PRIMARY KEY, run_id TEXT, version INTEGER, hitl_status TEXT, outcome_status TEXT, created_at TEXT, updated_at TEXT, report_json TEXT"),
    ("review_decisions", "decision_id TEXT PRIMARY KEY, report_id TEXT, run_id TEXT, version_reviewed INTEGER, reviewer_name TEXT, reviewer_role TEXT, decision TEXT, rejected_event_ids_json TEXT, rationale TEXT, decided_at TEXT"),
    ("analyst_feedback", "feedback_id TEXT PRIMARY KEY, event_id TEXT, report_id TEXT, analyst_name TEXT, feedback_type TEXT, corrected_risk_type TEXT, corrected_score INTEGER, flagged_source_url TEXT, added_missing_info TEXT, proposed_kiq TEXT, rationale TEXT, created_at TEXT"),
    ("kiq_catalog", "kiq_id TEXT PRIMARY KEY, kit_id TEXT, kit_title TEXT, question TEXT, monitored_entities_json TEXT, indicators_json TEXT, time_scope TEXT, sources_json TEXT, expected_output TEXT, verification_rule TEXT, priority TEXT, owner TEXT, active INTEGER DEFAULT 1"),
    ("reference_dataset", "case_id TEXT PRIMARY KEY, kit_topic TEXT, company_affected TEXT, expected_scm_tier TEXT, expected_program TEXT, headline_or_topic TEXT, problem_keywords TEXT, is_relevant INTEGER, reference_risk_type TEXT, reference_threat_score INTEGER, source_url TEXT, published_date TEXT, supporting_quote TEXT, evaluator_comment TEXT, verification_state TEXT, created_at TEXT"),
    ("usability_logs", "log_id TEXT PRIMARY KEY, view_mode TEXT, task_type TEXT, duration_ms INTEGER, notes TEXT, recorded_at TEXT"),
    ("document_filter_log", "run_id TEXT, doc_id TEXT, source_id TEXT, url TEXT, title TEXT, filter_stage TEXT, is_accepted INTEGER, signal_type TEXT, entities_models_tech TEXT, matched_kiq_id TEXT, decision_rationale TEXT, evaluated_at TEXT, PRIMARY KEY (run_id, doc_id)"),
)
_DDL_SCRIPT = "\n".join(f"CREATE TABLE IF NOT EXISTS {name} ({cols});" for name, cols in _TABLES)


def migrate_schema(connection: sqlite3.Connection) -> bool:
    """Initialize all SQLite tables and backfill source_metadata_json on legacy databases.

    Returns True only when the missing column is newly added; preserves existing rows.
    """
    connection.executescript(_DDL_SCRIPT)
    has_col = lambda: any(r[1] == "source_metadata_json" for r in connection.execute("PRAGMA table_info(source_documents)"))
    if has_col():
        return False
    try:
        connection.execute("ALTER TABLE source_documents ADD COLUMN source_metadata_json TEXT")
    except sqlite3.OperationalError as exc:
        # Handle concurrent migration races while re-raising unrelated SQLite errors.
        if "duplicate column" not in str(exc).lower() or not has_col():
            raise
        return False
    return True