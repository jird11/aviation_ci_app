# =============================================================================
# aviation_ci_app | SQLite persistence and cross-run event reconciliation
#
# Responsibility: Store source documents, reports, KIQ catalog entries, event observations, and historical
#   comparisons.
# Design boundary: Event matching is evidence-aware; a similar organization or aircraft name alone does
#   not establish event identity.
# =============================================================================

"""Persistent storage, event identity reconciliation, and historical reporting."""

import re
import uuid
from ews_state import (
    Any, DB_LOCK, Dict, EWSReport, EventStatus, HISTORICAL_CSV, List,
    Optional, SQLITE_DB, SequenceMatcher, ThreatAssessment, Tuple,
    datetime, json, logger, os, pd, sqlite3, timezone,
)


# Provide a normalized UTC timestamp for report metadata and audit records.
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Built-in strategic question catalog and reference evaluation fixtures.
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


# Initialize persistent tables and indexes required by the intelligence pipeline.
# Schema changes must preserve existing observations and provenance links.
# Schema initialization occurs before database-dependent pipeline operations.
def init_sqlite_db() -> None:
    # Create or migrate the persistence schema without requiring a separate migration command.
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        cur = conn.cursor()
        cur.executescript(_DDL_SCRIPT)

        for col, col_type in [
            ("content_status", "TEXT DEFAULT 'TEXT_COMPLETENESS_UNVERIFIED'"),
            ("content_sha256", "TEXT"),
            ("content_truncated", "INTEGER DEFAULT 0"),
            ("content_limit_reason", "TEXT"),
        ]:
            if col not in {row[1] for row in cur.execute("PRAGMA table_info(source_documents)")}:
                cur.execute(f"ALTER TABLE source_documents ADD COLUMN {col} {col_type}")

        for col, col_type in [
            ("kit_topic", "TEXT DEFAULT 'GENERAL'"),
            ("expected_scm_tier", "TEXT DEFAULT 'OEM (Final Assembler)'"),
            ("expected_program", "TEXT DEFAULT 'Unspecified'"),
            ("problem_keywords", "TEXT DEFAULT ''"),
            ("supporting_quote", "TEXT DEFAULT ''"),
        ]:
            try:
                cur.execute(f"ALTER TABLE reference_dataset ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass

        if cur.execute("SELECT COUNT(*) FROM kiq_catalog").fetchone()[0] == 0:
            cur.executemany(
                """
                INSERT INTO kiq_catalog (
                    kiq_id, kit_id, kit_title, question, monitored_entities_json,
                    indicators_json, time_scope, sources_json, expected_output,
                    verification_rule, priority, owner, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                [
                    (
                        i["kiq_id"], i["kit_id"], i["kit_title"], i["question"],
                        json.dumps(i["monitored_entities"]), json.dumps(i["indicators"]),
                        i["time_scope"], json.dumps(i["sources"]), i["expected_output"],
                        i["verification_rule"], i["priority"], i["owner"],
                    )
                    for i in DEFAULT_KIQ_CATALOG
                ],
            )

        if cur.execute("SELECT COUNT(*) FROM reference_dataset").fetchone()[0] < 50:
            cur.executemany(
                """
                INSERT OR REPLACE INTO reference_dataset (
                    case_id, kit_topic, company_affected, expected_scm_tier, expected_program,
                    headline_or_topic, problem_keywords, is_relevant, reference_risk_type,
                    reference_threat_score, source_url, published_date, supporting_quote,
                    evaluator_comment, verification_state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _build_default_ground_truth_cases(_now_iso()),
            )
        conn.commit()


# Seed illustrative reference cases for reproducible research evaluation.
# Reference fixtures are research cases, not independently confirmed live incidents.
def _build_default_ground_truth_cases(now_iso: str) -> List[Tuple]:
    """Construct the bundled illustrative reference cases for evaluation."""
    raw_cases = [

        ("REF_001", "Airbus A321XLR / A320neo", "Pratt & Whitney (RTX)", "Tier 1 (Systems/Engines)", "A320NEO_FAMILY", "Pratt & Whitney GTF powdered metal contamination forces 600-700 premature engine removals", "powder metal,gtf,pratt,removal,grounded", 1, "TECHNICAL_QUALITY", 9, "https://www.youtube.com/watch?v=B3QTB3YbO8M", "2026-08-10", "powdered metal contamination affecting certain engine components manufactured between 2015 and 2021", "Confirmed Tier-1 engine durability crisis.", "VERIFIED_POSITIVE"),
        ("REF_002", "Airbus A321XLR / A320neo", "Turkish Airlines", "Regulator / Airline", "A320NEO_FAMILY", "Turkish Airlines grounds up to 50 Airbus A321neo jets over Pratt & Whitney GTF shop queues", "turkish,grounded,gtf,shop,200 days", 1, "SUPPLY_CHAIN", 8, "https://www.youtube.com/watch?v=WNDNn3gXlMo", "2026-09-22", "Turkish Airlines still expects dozens of aircraft on the ground well into next year", "Confirmed airline fleet grounding from Tier-1 MRO bottleneck.", "VERIFIED_POSITIVE"),
        ("REF_003", "Airbus A321XLR / A320neo", "Spirit Airlines", "Regulator / Airline", "A320NEO_FAMILY", "Three-year-old Spirit Airlines A320neo jets parted out in Arizona due to GTF engine shortage", "spirit,dismantled,scrapped,shortage,goodyear", 1, "SUPPLY_CHAIN", 8, "https://www.youtube.com/watch?v=HqACO9TeexU", "2026-10-28", "Spirit Airlines jets that are only three or four years old are being stripped for parts", "Confirmed severe JIT engine shortage consequence.", "VERIFIED_POSITIVE"),
        ("REF_004", "Airbus A321XLR / A320neo", "Air Canada", "Regulator / Airline", "A321XLR", "Airbus A321XLR program running behind schedule affecting Air Canada and IndiGo deliveries", "a321xlr,behind schedule,delay,air canada,indigo", 1, "SUPPLY_CHAIN", 7, "https://www.youtube.com/watch?v=K6KGQHnayqU", "2026-09-08", "THE A321 XLR PROGRAM IS RUNNING ROUGHLY TWO YEARS BEHIND SCHEDULE IN MANY CASES", "Schedule delay signal for A321XLR operators.", "VERIFIED_POSITIVE"),
        ("REF_005", "Airbus A321XLR / A320neo", "Qantas", "Regulator / Airline", "A321XLR", "Qantas postpones A321XLR international service rollout until 2027", "qantas,a321xlr,delay,2027", 1, "SUPPLY_CHAIN", 6, "https://bsky.app/profile/boardingarea.bsky.social/post/3mswr7si5rr2y", "2026-08-13", "QANTAS: Delay in A321XLR international flights 'till 2027", "Weak community signal requiring OEM corroboration.", "VERIFIED_POSITIVE"),
        ("REF_006", "Airbus A321XLR / A320neo", "Pratt & Whitney (RTX)", "Tier 1 (Systems/Engines)", "A321XLR", "United Airlines receives first GTF Advantage-powered Airbus A321XLR", "united,gtf advantage,a321xlr,pratt", 1, "COMPETITIVE", 5, "https://bsky.app/profile/airpronews.bsky.social/post/3mwbzlyefcm24", "2026-09-24", "Pratt & Whitney delivered the first GTF Advantage-powered Airbus A321XLR to United Airlines", "Milestone delivery and component transition to new spec.", "VERIFIED_POSITIVE"),
        ("REF_007", "Airbus A321XLR / A320neo", "British Airways", "Regulator / Airline", "A320NEO_FAMILY", "British Airways selects Pratt & Whitney GTF engines for up to 63 Airbus A320neo family jets", "british airways,gtf,63,farnborough,cfm", 1, "COMPETITIVE", 5, "https://www.youtube.com/watch?v=B3QTB3YbO8M", "2026-08-10", "British Airways, has selected Pratt and Whitney's geared turbofan or GTF engine to power up to 63 Airbus A320neo", "Major competitor engine market shift.", "VERIFIED_POSITIVE"),
        ("REF_008", "Airbus A321XLR / A320neo", "Wizz Air", "Regulator / Airline", "A320NEO_FAMILY", "Wizz Air fleet disruptions from Pratt & Whitney GTF engine inspections", "wizz air,gtf,inspections,groundings", 1, "SUPPLY_CHAIN", 7, "https://bsky.app/profile/aviationnews-eu.bsky.social/post/3mttlteblc42a", "2026-08-24", "Wizz Air, Pratt and Whitney, GTF engine inspections, aircraft groundings", "Ongoing European carrier grounding signal.", "VERIFIED_POSITIVE"),
        ("REF_009", "Airbus A321XLR / A320neo", "easyJet", "Regulator / Airline", "A320NEO_FAMILY", "easyJet Airbus A320neo 1:200 Scale Model Unboxing Review in Mallorca", "1:200,scale model,mallorca,unboxing", 0, "SUPPLY_CHAIN", 1, "https://www.youtube.com/watch?v=nXBthomClKY", "2026-10-28", "looking at the PPC Horizons EasyJet Airbus A320 neo model, which is in 1 to 200 scale", "Irrelevant hobbyist scale model video (must be rejected by filter).", "VERIFIED_NEGATIVE"),
        ("REF_010", "Airbus A321XLR / A320neo", "Airbus SE", "OEM (Final Assembler)", "A350", "Airbus A350 widebody cabin catering update for long-haul flights", "a350,catering,cabin,menu", 0, "COMPETITIVE", 1, "https://example.org/a350-catering", "2026-09-10", "new catering menu on A350 flights", "Irrelevant different aircraft family (A350 vs A320neo).", "VERIFIED_NEGATIVE"),
        ("REF_011", "Airbus A321XLR / A320neo", "The Boeing Company", "OEM (Final Assembler)", "737_NG", "CFM56 fan blade inspection on older Boeing 737-800 fleet", "cfm56,737-800,fan blade", 0, "TECHNICAL_QUALITY", 2, "https://example.org/cfm56-737ng", "2026-09-12", "CFM56 engine inspection on Boeing 737 NG", "Tricky negative: CFM56 on 737 must never be used to confirm A320neo GTF issues.", "VERIFIED_NEGATIVE"),
        ("REF_012", "Airbus A321XLR / A320neo", "Cyprus Airways", "Regulator / Airline", "A320NEO_FAMILY", "Cyprus Airways plans post-2027 fleet growth with two A320neo aircraft", "cyprus airways,1q27,london route", 1, "COMPETITIVE", 3, "https://bsky.app/profile/domsipinski.bsky.social/post/3mwl4amfur22o", "2026-09-28", "Cyprus Airways has an open book for its post-2027 fleet growth", "Low-severity routine fleet planning signal.", "VERIFIED_POSITIVE"),


        ("REF_013", "FAA / EASA Regulations", "Airbus SE", "OEM (Final Assembler)", "A320NEO_FAMILY", "FAA Proposed Airworthiness Directive for Airbus A320 family engine fire switch self-releasing", "fire switch,self-releasing,uncommanded,in-flight shut down,2026-18072", 1, "REGULATORY", 8, "https://www.federalregister.gov/documents/2026/09/03/2026-18072/airworthiness-directives-airbus-sas-airplanes", "2026-09-03", "reports of one engine fire switch self-releasing, causing an uncommanded in-flight shut down to one engine", "Primary FAA regulatory directive on safety-critical cockpit fire switch.", "VERIFIED_POSITIVE"),
        ("REF_014", "FAA / EASA Regulations", "Airbus SE", "OEM (Final Assembler)", "A320NEO_FAMILY", "FAA Proposed AD 2026-21047 for Airbus A320 family emergency evacuation slide hose fracture", "evacuation slide,failing to inflate,fracture,2026-21047", 1, "REGULATORY", 7, "https://www.federalregister.gov/documents/2026/10/15/2026-21047/airworthiness-directives-airbus-sas-airplanes", "2026-10-15", "reports of door evacuation slide systems failing to inflate during emergency evacuations", "Primary FAA AD on evacuation slide connector fracture.", "VERIFIED_POSITIVE"),
        ("REF_015", "FAA / EASA Regulations", "Airbus SE", "OEM (Final Assembler)", "A320NEO_FAMILY", "FAA Proposed AD 2026-20700 for Airbus A320 wing thrust spigot slotted nut corrosion", "slotted nuts,wing thrust spigots,corrosion,2026-20700", 1, "REGULATORY", 7, "https://www.federalregister.gov/documents/2026/10/08/2026-20700/airworthiness-directives-airbus-sas-airplanes", "2026-10-08", "finding that severe corrosion could occur on affected slotted nuts located at the wing thrust spigots", "Primary FAA AD requiring repetitive structural inspections.", "VERIFIED_POSITIVE"),
        ("REF_016", "FAA / EASA Regulations", "Airbus SE", "OEM (Final Assembler)", "A320NEO_FAMILY", "Pilots warn of engine shutdown risk on Airbus A320neo and A350", "pilots warn,shutdown risk,a320neo,a350", 1, "REGULATORY", 6, "https://news.google.com/rss/articles/CBMijgFBVV95cUxOOVlyOENpaUxYUGppZ0pQcXNpRU5SLVZQSmVOWkQwczh2c3Jwb1hnVEhOdlBXUlY5VEoxdWpmOXZJVWNWX3lWU19BejVaYnFtbFFJTE9RLXdnQVlLZVFNR2RBTDFqVE5hajJKUi1aWFBBdnpyQ29VZ3ZaMnFpNXZwVTZUVTdTdUdmenQxclR3?oc=5", "2026-08-04", "Pilots Warn of Engine Shutdown Risk on Airbus A320neo and A350", "Secondary media headline via EASA monitor (snippet only -> PARTIALLY_SUPPORTED).", "VERIFIED_POSITIVE"),
        ("REF_017", "FAA / EASA Regulations", "The Boeing Company", "OEM (Final Assembler)", "737_MAX", "FAA maintains production cap oversight on Boeing 737 MAX manufacturing in Renton", "production cap,faa,renton,737 max,oversight", 1, "REGULATORY", 8, "https://www.federalregister.gov/documents/2026/09/18/boeing-737-oversight", "2026-09-18", "FAA continues enhanced manufacturing oversight and production rate cap at Renton facility", "Primary regulatory cap limiting OEM output.", "VERIFIED_POSITIVE"),
        ("REF_018", "FAA / EASA Regulations", "The Boeing Company", "OEM (Final Assembler)", "787", "FAA AD on Boeing 787 Dreamliner horizontal stabilizer fitting shims inspection", "787,dreamliner,stabilizer,shims,inspection", 1, "REGULATORY", 7, "https://www.federalregister.gov/documents/2026/09/25/boeing-787-ad", "2026-09-25", "repetitive inspections of horizontal stabilizer gap shims on Model 787 airplanes", "Confirmed widebody airworthiness directive.", "VERIFIED_POSITIVE"),
        ("REF_019", "FAA / EASA Regulations", "EASA", "Regulator / Airline", "A350", "EASA issues airworthiness directive on Rolls-Royce Trent XWB fuel manifold hose inspections", "easa,trent xwb,a350,fuel hose,inspection", 1, "REGULATORY", 8, "https://www.easa.europa.eu/en/newsroom-and-events/news/trent-xwb-inspection", "2026-09-05", "EASA requires one-off inspection of flexible fuel hose connections on Trent XWB engines", "Primary European regulatory action on widebody engines.", "VERIFIED_POSITIVE"),
        ("REF_020", "FAA / EASA Regulations", "FAA", "Regulator / Airline", "Unspecified", "FAA drone hobbyist registration renewal reminder for recreational flyers", "drone,recreational,hobbyist,registration", 0, "REGULATORY", 1, "https://example.org/faa-drone-hobby", "2026-10-01", "recreational drone flyers must renew registration", "Irrelevant non-commercial aviation notice.", "VERIFIED_NEGATIVE"),
        ("REF_021", "FAA / EASA Regulations", "NTSB", "Regulator / Airline", "Unspecified", "NTSB highway truck tire blowout investigation report in Texas", "highway,truck,tire,texas", 0, "REGULATORY", 1, "https://example.org/ntsb-highway", "2026-10-02", "NTSB highway safety report on commercial truck tire", "Irrelevant non-aviation NTSB report.", "VERIFIED_NEGATIVE"),
        ("REF_022", "FAA / EASA Regulations", "Airbus SE", "OEM (Final Assembler)", "A320NEO_FAMILY", "Airbus A320 and A321 under review: which airplanes are affected by the FAA order", "under review,faa order,a320,a321,democrata", 1, "REGULATORY", 6, "https://news.google.com/rss/articles/CBMi5wFBVV95cUxPcnp6S3lMN1FhcUFKTlZfU09HUHd1M1J1SzdGRk9PQkxmUVpqYW1FQTgyM1hzcEFhSWVsS1lodm1BNW1FUWF2NnVfTm5UQU5odkNHcGxFanhGWVRaQmc3MXlKX3NSQmJnMUMxUWI1OXpGZ2VfMVBscFRFYTNRakstZi1mdlNGUmVZNDZ5Y3RDVVlYREwwdkRLdUh5bWVreVoxRGgyRy1uUVlZMWRXeThzOGk5S2N0akpTSnl2WmdzcXZ1MzluRHlFQWtPMnFfWXRCWWhhMW5HeWR5d3hacmFqcEN2bEpwcEHSAewBQVVfeXFMTXA0N2VKaURLUldZaGx4Z18zbXpocGhla1pNa0djcXEtVlJsZ3pkajZmeTl0eF8yWGxtMWtkV2lDTFpmSmNLNFBGNDVURDV6T3NvWENIWGMzeUlBa2lUbmliLTZBMEJsSVkxZHJjRW5TR3hKZGtTdlJLMHFmS0t0S283dUw4VnoxMndTcG80NHFPTTVGMXZuS00zemNLX29oOHVEWlYtNG9UcXBSSnJuMkxEbUJDUmx5ek1QV3ZfR091ZjlNajViajBTMUppdDJsVjMxNWRZbmctVHBZX0ZaZEw1RmdJZHNjUmxqeUU?oc=5", "2026-08-28", "Airbus A320 and A321 under review: which airplanes are affected by the FAA order", "Secondary media summary of FAA order.", "VERIFIED_POSITIVE"),


        ("REF_023", "Boeing 777X", "The Boeing Company", "OEM (Final Assembler)", "777X", "Boeing 777X flight test pause after severed thrust link discovered on 777-9 test aircraft", "777x,777-9,thrust link,flight test,pause", 1, "TECHNICAL_QUALITY", 9, "https://www.boeing.com/777x-thrust-link-update", "2026-08-25", "structural crack in a thrust link component connecting the GE9X engine to the 777-9 airframe", "Critical technical defect delaying 777X certification.", "VERIFIED_POSITIVE"),
        ("REF_024", "Boeing 777X", "The Boeing Company", "OEM (Final Assembler)", "777X", "Boeing pushes first 777X commercial delivery target to 2027 amid FAA certification delays", "777x,2027,certification delay,first delivery,boeing", 1, "SUPPLY_CHAIN", 8, "https://www.boeing.mediaroom.com/2026-10-12-777x-schedule", "2026-10-12", "Boeing now anticipates first delivery of the 777-9 in 2027 due to certification timelines", "Confirmed OEM program schedule slip.", "VERIFIED_POSITIVE"),
        ("REF_025", "Boeing 777X", "Lufthansa", "Regulator / Airline", "777X", "Lufthansa adjusts long-haul widebody capacity plan as launch customer for delayed Boeing 777-9", "lufthansa,777-9,launch customer,capacity,delay", 1, "SUPPLY_CHAIN", 7, "https://example.org/lufthansa-777x-delay", "2026-10-14", "Lufthansa forced to extend older widebody leases due to Boeing 777-9 delivery delay to 2027", "Downstream airline fleet impact from 777X delay.", "VERIFIED_POSITIVE"),
        ("REF_026", "Boeing 777X", "Emirates", "Regulator / Airline", "777X", "Emirates warns of fleet growth bottleneck from repeated Boeing 777X delays", "emirates,777x,bottleneck,retrofit,delay", 1, "SUPPLY_CHAIN", 7, "https://example.org/emirates-777x-warning", "2026-10-18", "Emirates expands cabin retrofit program to offset delayed Boeing 777X deliveries", "Major Middle East customer impact.", "VERIFIED_POSITIVE"),
        ("REF_027", "Boeing 777X", "The Boeing Company", "OEM (Final Assembler)", "777F", "Boeing halts 777F freighter production line temporarily due to supplier strike", "777f,freighter,strike,halt", 0, "SUPPLY_CHAIN", 6, "https://example.org/777f-freighter-halt", "2026-10-20", "777F freighter production halted during machinist strike", "Variant trap (P0-2.3 / P1-3.4): 777F freighter headline must NOT be marked as confirmed 777X halt.", "VERIFIED_NEGATIVE"),
        ("REF_028", "Boeing 777X", "The Boeing Company", "OEM (Final Assembler)", "737_MAX", "Boeing 737 MAX delivery figures for September 2026", "737 max,september deliveries,narrowbody", 0, "SUPPLY_CHAIN", 2, "https://example.org/737-sept-deliveries", "2026-10-05", "Boeing delivered 27 737 MAX jets in September", "Irrelevant model mismatch (737 MAX when querying 777X).", "VERIFIED_NEGATIVE"),
        ("REF_029", "Boeing 777X", "Unknown", "Unknown (Verification Required)", "777X", "Flight simulator MSFS 2026 Boeing 777X add-on release date announced", "msfs,flight simulator,add-on,virtual", 0, "COMPETITIVE", 1, "https://example.org/msfs-777x", "2026-10-19", "PMDG announces virtual 777X for Microsoft Flight Simulator", "Irrelevant flight simulator noise.", "VERIFIED_NEGATIVE"),
        ("REF_030", "Boeing 777X", "The Boeing Company", "OEM (Final Assembler)", "777X", "Boeing records pre-tax charge on 777X program amid Everett production and test delays", "charge,everett,777x,pre-tax,financial", 1, "FINANCIAL", 8, "https://www.boeing.mediaroom.com/2026-10-23-q3-charge", "2026-10-23", "Boeing recognized a multi-billion dollar pre-tax charge on the 777X program", "Confirmed financial & supply chain impact on OEM.", "VERIFIED_POSITIVE"),
        ("REF_031", "Boeing 777X", "Qatar Airways", "Regulator / Airline", "777X", "Qatar Airways reaffirms commitment to Boeing 777-9 orderbook despite schedule slip", "qatar airways,777-9,orderbook", 1, "COMPETITIVE", 4, "https://example.org/qatar-777x", "2026-10-21", "Qatar Airways remains committed to its 777-9 orders", "Low-severity monitored customer statement.", "VERIFIED_POSITIVE"),
        ("REF_032", "Boeing 777X", "UnknownPassenger", "Regulator / Airline", "777_LEGACY", "My flight on a 777-200 had a broken entertainment screen and lost my luggage", "my flight,luggage,screen,vacation", 0, "SUPPLY_CHAIN", 1, "https://bsky.app/profile/traveler.bsky.social/post/111", "2026-10-22", "My flight was delayed and they lost my bag", "Irrelevant personal passenger post (must be blocked by GDPR/relevance filter).", "VERIFIED_NEGATIVE"),


        ("REF_033", "GE9X / GE Aerospace", "GE Aerospace", "Tier 1 (Systems/Engines)", "777X", "GE Aerospace announces agreement to acquire precision-castings supplier CPP for $11.75 billion", "ge aerospace,cpp,precision-castings,11.75 billion,turbine", 1, "SUPPLY_CHAIN", 6, "https://www.youtube.com/watch?v=gOEHDApqXLY", "2026-10-29", "GE Aerospace announced an agreement to acquire precision-castings supplier CPP for $11.75 billion", "Strategic Tier-1 vertical integration of Tier-2 casting supplier.", "VERIFIED_POSITIVE"),
        ("REF_034", "GE9X / GE Aerospace", "GE Aerospace", "Tier 1 (Systems/Engines)", "777X", "GE Aerospace conducts additional GE9X durability and seal inspections during 777X test pause", "ge9x,durability,seal,inspection,ge aerospace", 1, "TECHNICAL_QUALITY", 7, "https://example.org/ge9x-seal-inspection", "2026-09-15", "GE Aerospace is inspecting high-pressure turbine seals on GE9X test engines", "Tier-1 engine technical inspection signal.", "VERIFIED_POSITIVE"),
        ("REF_035", "GE9X / GE Aerospace", "CFM International (GE / Safran)", "Tier 1 (Systems/Engines)", "A320NEO_FAMILY", "CFM International introduces high-pressure turbine durability kit for LEAP-1A engines", "cfm,leap-1a,durability,safran,ge", 1, "TECHNICAL_QUALITY", 5, "https://www.youtube.com/watch?v=B3QTB3YbO8M", "2026-08-10", "CFM has also introduced a series of engineering upgrades to improve the long-term durability of the LEAP-1A", "Tier-1 engine durability upgrade.", "VERIFIED_POSITIVE"),
        ("REF_036", "GE9X / GE Aerospace", "Safran S.A.", "Tier 1 (Systems/Engines)", "A320NEO_FAMILY", "Safran reports forging and casting bottlenecks constraining LEAP engine delivery ramp-up", "safran,forging,casting,leap,ramp-up", 1, "SUPPLY_CHAIN", 7, "https://example.org/safran-forging-bottleneck", "2026-09-30", "Safran cited Tier-2 forging and casting bottlenecks limiting LEAP deliveries", "Confirmed Tier-1/Tier-2 engine supply bottleneck.", "VERIFIED_POSITIVE"),
        ("REF_037", "GE9X / GE Aerospace", "VSMPO-AVISMA / Titanium Suppliers", "Tier 3 (Raw Materials)", "A350", "Aerospace titanium forging lead times remain elevated across European and US sub-tier suppliers", "titanium,forging,lead times,howmet,tier 3", 1, "SUPPLY_CHAIN", 7, "https://example.org/titanium-lead-times", "2026-10-04", "Aerospace-grade titanium forging lead times remain above 60 weeks", "Tier-3 raw material bottleneck.", "VERIFIED_POSITIVE"),
        ("REF_038", "GE9X / GE Aerospace", "Rolls-Royce Holdings", "Tier 1 (Systems/Engines)", "A350", "Rolls-Royce TotalCare engine flying hour maintenance model overview", "totalcare,flying hours,rolls-royce", 0, "COMPETITIVE", 2, "https://www.youtube.com/watch?v=gOEHDApqXLY", "2026-10-29", "Rolls-Royce’s TotalCare is a maintenance and risk-transfer service with payments linked to engine flying hours", "General educational background on business model, not an active disruption.", "VERIFIED_NEGATIVE"),
        ("REF_039", "GE9X / GE Aerospace", "GE Vernova", "Unknown (Verification Required)", "Unspecified", "GE Vernova wind turbine blade installation in North Sea offshore wind farm", "wind turbine,offshore,ge vernova,north sea", 0, "ENVIRONMENTAL_TECHNOLOGICAL", 1, "https://example.org/ge-vernova-wind", "2026-10-06", "GE Vernova installs offshore wind turbine", "Irrelevant non-aviation energy company.", "VERIFIED_NEGATIVE"),
        ("REF_040", "GE9X / GE Aerospace", "GE Aerospace", "Tier 1 (Systems/Engines)", "787", "GEnx engine MRO turnaround times improve at GE Aerospace overhaul shops", "genx,787,mro,turnaround", 1, "SUPPLY_CHAIN", 3, "https://example.org/genx-mro-improvement", "2026-10-11", "GE Aerospace reduced GEnx shop turnaround times by 12%", "Positive/low-risk monitored MRO signal.", "VERIFIED_POSITIVE"),
        ("REF_041", "GE9X / GE Aerospace", "Collins Aerospace", "Tier 1 (Systems/Engines)", "777X", "Collins Aerospace nacelle actuation qualification completed for 777X", "collins,nacelle,actuation,777x", 1, "TECHNICAL_QUALITY", 3, "https://example.org/collins-nacelle", "2026-09-19", "Collins Aerospace completed nacelle actuation qualification testing", "Monitored Tier-1 milestone.", "VERIFIED_POSITIVE"),
        ("REF_042", "GE9X / GE Aerospace", "UnknownBlog", "Unknown (Verification Required)", "Unspecified", "Top 10 biggest jet engines in history compilation video", "top 10,compilation,biggest", 0, "COMPETITIVE", 1, "https://example.org/top10-engines", "2026-10-03", "welcome to our top 10 biggest jet engines compilation", "Irrelevant compilation video.", "VERIFIED_NEGATIVE"),


        ("REF_043", "Airbus A220", "Pratt & Whitney (RTX)", "Tier 1 (Systems/Engines)", "A220", "Airbus A220 operators face ongoing PW1500G geared turbofan shop visit delays", "a220,pw1500g,pratt,shop visit,grounded", 1, "SUPPLY_CHAIN", 8, "https://example.org/a220-pw1500g-delays", "2026-09-27", "Airbus A220 operators report continued aircraft-on-ground delays awaiting PW1500G engine overhauls", "Confirmed Tier-1 engine bottleneck on A220 program.", "VERIFIED_POSITIVE"),
        ("REF_044", "Airbus A220", "Spirit AeroSystems", "Tier 1 (Systems/Engines)", "A220", "Spirit AeroSystems A220 wing and pylon integration transfer to Airbus nears completion", "spirit aerosystems,a220,wing,pylon,transfer", 1, "SUPPLY_CHAIN", 7, "https://example.org/spirit-a220-wings", "2026-10-09", "Airbus and Spirit AeroSystems progress on transferring A220 wing production in Belfast", "Critical Tier-1 aerostructures supply chain restructuring.", "VERIFIED_POSITIVE"),
        ("REF_045", "Airbus A220", "FAA", "Regulator / Airline", "A220", "FAA issues Airworthiness Directive on Airbus A220 flight control software check", "faa,a220,flight control,software,directive", 1, "REGULATORY", 7, "https://www.federalregister.gov/documents/2026/09/14/airbus-a220-ad", "2026-09-14", "FAA adopts airworthiness directive for Airbus Canada Model BD-500-1A10 and 1A11 (A220) airplanes", "Primary regulatory action on A220.", "VERIFIED_POSITIVE"),
        ("REF_046", "Airbus A220", "airBaltic", "Regulator / Airline", "A220", "airBaltic wet-leases replacement aircraft due to PW1500G engine shortages on A220-300 fleet", "airbaltic,a220-300,wet-lease,pw1500g,shortage", 1, "SUPPLY_CHAIN", 7, "https://example.org/airbaltic-a220-engines", "2026-10-07", "airBaltic forced to wet-lease capacity as A220-300 jets wait for PW1500G engines", "Confirmed operator disruption from Tier-1 engine shortage.", "VERIFIED_POSITIVE"),
        ("REF_047", "Airbus A220", "Airbus SE", "OEM (Final Assembler)", "A220", "Airbus Mirabel and Mobile assembly lines target A220 rate 14 ramp-up in 2026", "mirabel,mobile,a220,rate 14,ramp-up", 1, "SUPPLY_CHAIN", 5, "https://www.airbus.com/en/newsroom/a220-ramp-up-2026", "2026-09-21", "Airbus continues A220 production ramp-up toward 14 aircraft per month across Mirabel and Mobile", "OEM production rate target signal.", "VERIFIED_POSITIVE"),
        ("REF_048", "Airbus A220", "Swiss International Air Lines", "Regulator / Airline", "A220", "SWISS completes PW1500G inspection cycle on Zurich-based A220 fleet", "swiss,zurich,a220,pw1500g,inspection", 1, "SUPPLY_CHAIN", 4, "https://example.org/swiss-a220-zurich", "2026-09-16", "SWISS returned two parked A220 aircraft to service in Zurich after engine maintenance", "Monitored fleet recovery signal.", "VERIFIED_POSITIVE"),
        ("REF_049", "Airbus A220", "Embraer", "OEM (Final Assembler)", "Unspecified", "Embraer E195-E2 regional jet order at airshow", "embraer,e195-e2,order", 0, "COMPETITIVE", 2, "https://example.org/embraer-e2-order", "2026-10-02", "Embraer announces E195-E2 order", "Different aircraft manufacturer/model when querying A220 technical issues.", "VERIFIED_NEGATIVE"),
        ("REF_050", "Airbus A220", "UnknownRecruiter", "Unknown (Verification Required)", "A220", "Careers and graduate internship openings at Mirabel aerospace park", "careers,internship,graduate,mirabel", 0, "SUPPLY_CHAIN", 1, "https://example.org/mirabel-careers", "2026-10-10", "Apply now for our 2026 graduate internship program", "Irrelevant HR/career posting.", "VERIFIED_NEGATIVE"),
        ("REF_051", "Airbus A220", "QantasLink", "Regulator / Airline", "A220", "QantasLink adds new domestic Airbus A220 route in Australia", "qantaslink,domestic route,tasmania", 0, "COMPETITIVE", 2, "https://example.org/qantaslink-route", "2026-10-13", "QantasLink launches new A220 flights to Hobart", "Routine airline route launch, not a supply chain disruption.", "VERIFIED_NEGATIVE"),
        ("REF_052", "Airbus A220", "Spirit AeroSystems", "Tier 1 (Systems/Engines)", "A220", "Spirit AeroSystems reports quality rework on A220 fuselage frames delaying batch shipment", "spirit aerosystems,a220,rework,fuselage,delay", 1, "TECHNICAL_QUALITY", 8, "https://example.org/spirit-a220-rework", "2026-10-17", "Spirit AeroSystems identified quality rework required on A220 mid-fuselage frames", "High-severity Tier-1 quality escape affecting OEM line.", "VERIFIED_POSITIVE"),
    ]
    return [(*c, now_iso) for c in raw_cases]


# Load enabled strategic KIQ definitions from persistent storage.
def get_active_kiq_catalog() -> List[Dict[str, Any]]:
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM kiq_catalog WHERE active = 1 ORDER BY kiq_id").fetchall()
        return [
            {
                "kiq_id": r["kiq_id"],
                "kit_id": r["kit_id"],
                "kit_title": r["kit_title"],
                "question": r["question"],
                "monitored_entities": json.loads(r["monitored_entities_json"] or "[]"),
                "indicators": json.loads(r["indicators_json"] or "[]"),
                "time_scope": r["time_scope"],
                "sources": json.loads(r["sources_json"] or "[]"),
                "expected_output": r["expected_output"],
                "verification_rule": r["verification_rule"],
                "priority": r["priority"],
                "owner": r["owner"],
            }
            for r in rows
        ]


_AIRFRAME_MARKERS = {
    "A320NEO_FAMILY": re.compile(r"\b(?:a3(?:19|20|21)\s*neo|a320neo_family)\b", re.I),
    "A350": re.compile(r"\ba350(?:[- ]?(?:900|1000|f))?\b", re.I),
    "A220": re.compile(r"\ba220(?:[- ]?(?:100|300))?\b", re.I),
    "B787": re.compile(r"\b(?:b?787|dreamliner)\b", re.I),
    "B777": re.compile(r"\b(?:b?777|777x)\b", re.I),
    "B737": re.compile(r"\b(?:b?737|737\s*max)\b", re.I),
}


# Identify aircraft references used when comparing incident identity.
def _incident_airframes(text: str) -> set[str]:
    return {name for name, regex in _AIRFRAME_MARKERS.items() if regex.search(text or "")}


# Recover docket identity and previous-document linkage for FAA lifecycle tracking.
def _faa_lifecycle_identity(summary: Dict[str, Any]) -> Tuple[str, str]:
    """Extract verified FAA docket identity and earlier-document URL."""
    if not isinstance(summary, dict) or summary.get("FAA Lifecycle Verified") != "YES":
        return "", ""

    docket = str(summary.get("FAA Docket") or "").strip().upper()
    earlier_url = str(summary.get("FAA Prior Document") or "").strip()

    if not re.fullmatch(r"FAA-\d{4}-\d+", docket):
        docket = ""
    if "federalregister.gov/documents/" not in earlier_url:
        earlier_url = ""

    return docket, earlier_url


# Assess whether two observations refer to the same supported real-world event.
# Do not equate high textual similarity with confirmed event identity.
def _incident_match_score(threat: ThreatAssessment, row: sqlite3.Row, old_urls: List[str]) -> float:
    """Return 0 when same-event identity is not adequately supported."""
    incoming_urls = set(threat.source_urls or []) | {threat.evidence_citation}
    historical_urls = set(old_urls) | {row["canonical_url"]}
    shared_source = bool({u for u in incoming_urls & historical_urls if u})

    same_actor = (threat.company_affected or "").strip().casefold() == (row["company_affected"] or "").strip().casefold()
    if not shared_source and not same_actor:
        return 0.0
    if shared_source and threat.risk_type.value != row["risk_type"]:
        return 0.0

    new_models = _incident_airframes(f"{threat.affected_program} {threat.threat_description} {threat.fact_check_quote}")
    old_models = _incident_airframes(f"{row['threat_description'] or ''} {row['fact_check_quote'] or ''}")
    if new_models and old_models and new_models.isdisjoint(old_models):
        return 0.0

    if same_actor and threat.risk_type.value == "REGULATORY" and row["risk_type"] == "REGULATORY":
        new_docket, earlier_url = _faa_lifecycle_identity(threat.corroboration_summary or {})
        try:
            old_audit = json.loads(row["corroboration_json"] or "{}")
        except (KeyError, IndexError, ValueError, TypeError):
            old_audit = {}

        old_docket, _ = _faa_lifecycle_identity(old_audit)
        old_canonical = (row["canonical_url"] or "").strip()
        current_url = (threat.evidence_citation or "").strip()

        if new_docket and old_docket:
            if new_docket != old_docket:
                return 0.0
            return 1.20 if (current_url and old_canonical == current_url) else 1.10

        if new_docket and earlier_url and old_canonical == earlier_url:
            return 1.00
        if new_docket and old_canonical and current_url == old_canonical:
            return 1.15
        if new_docket and earlier_url and "federalregister.gov/documents/" in old_canonical:
            return 0.0

    norm = lambda v: re.sub(r"\s+", " ", (v or "").casefold()).strip()
    similarity = SequenceMatcher(None, norm(threat.threat_description), norm(row["threat_description"])).ratio()

    if shared_source:
        if not same_actor:
            return 0.0

        new_text = f"{threat.threat_description} {threat.fact_check_quote}"
        old_text = f"{row['threat_description']} {row['fact_check_quote']}"
        issue_patterns = (
            r"engine\s+shutdowns?|schaltet.{0,90}triebwerk\w*|triebwerk\w*.{0,40}lahm",
            r"\b(?:engine shortage|triebwerksmangel)\b",
            r"\b(?:production delay|produktionsverzögerung)\b",
            r"\b(?:fuel leak|treibstoffleck)\b",
        )
        if any(re.search(p, new_text, re.I | re.S) and re.search(p, old_text, re.I | re.S) for p in issue_patterns):
            return 0.95

        threshold = 0.62 if (new_models and old_models) else 0.83
        return similarity + 0.1 if similarity >= threshold else 0.0

    same_type = threat.risk_type.value == row["risk_type"]
    return similarity if (same_actor and same_type and similarity >= 0.87) else 0.0


# Resolve stable event IDs and persist current observations for historical tracing.
# Persistent event IDs allow trend analysis without assuming every repeated mention is a new incident.
# Keep first-seen identity and individual observation history distinct.
# Prefer evidence-backed event identity over name similarity when updating the observation history.
def reconcile_and_store_events(
    run_id: str, threats: List[ThreatAssessment]
) -> Tuple[List[ThreatAssessment], int, int, int]:
    # Match candidate identities against stored event history using source and issue evidence.
    """Reconcile event identities across runs and persist their observation history."""
    now_iso = _now_iso()
    new_count = continuing_count = 0

    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        existing_rows = [
            (r, json.loads(r["source_urls_json"] or "[]"))
            for r in cur.execute("SELECT * FROM events WHERE event_status != 'DISMISSED'").fetchall()
        ]
        matched_existing_ids: set[str] = set()
        assigned_this_run: set[str] = set()
        reserved_database_ids = {row["event_id"] for row, _ in existing_rows}

        for threat in threats:
            matched_row, row_urls = None, []
            best_score = 0.0

            for row, r_urls in existing_rows:
                if row["event_id"] in matched_existing_ids:
                    continue
                score = _incident_match_score(threat, row, r_urls)
                if score > best_score:
                    best_score = score
                    matched_row, row_urls = row, r_urls

            if matched_row is not None:
                continuing_count += 1
                ev_id = matched_row["event_id"]
                matched_existing_ids.add(ev_id)
                threat.event_id = ev_id
                threat.first_seen_at = matched_row["first_seen_at"] or now_iso

                current_urls = list(threat.source_urls or [])
                primary_url = (threat.evidence_citation or "").strip()
                if primary_url:
                    current_urls.insert(0, primary_url)

                verified_faa = (
                    threat.risk_type.value == "REGULATORY"
                    and (threat.corroboration_summary or {}).get("FAA Lifecycle Verified") == "YES"
                    and bool((threat.corroboration_summary or {}).get("FAA Docket"))
                )

                if verified_faa:
                    urls = [
                        u for u in current_urls
                        if "federalregister.gov/documents/" not in u.lower() or u.strip() == primary_url
                    ]
                else:
                    urls = current_urls + row_urls

                # Historické odkazy zachovej pouze v databázovém archivu.
                archived_urls = [
                                    u for u in dict.fromkeys(urls)
                                    if u and "example.com" not in u
                                ][:5]

                # Aktuální report smí uvádět pouze URL
                # přiřazené důkazům z tohoto běhu.
                threat.source_urls = [
                                         u for u in dict.fromkeys(current_urls)
                                         if u and "example.com" not in u
                                     ][:5]

                prev_score = int(matched_row["threat_score"] or threat.threat_score)
                change_type = (
                    "SCORE_ESCALATED" if threat.threat_score > prev_score
                    else "SCORE_DEESCALATED" if threat.threat_score < prev_score
                    else "ADDITIONAL_SOURCE" if set(threat.source_urls) - set(row_urls)
                    else "REDETECTED"
                )
                notes = f"Updated in {run_id} (previous score: {prev_score})"
            else:
                if threat.event_id in reserved_database_ids or threat.event_id in assigned_this_run:
                    previous_id = threat.event_id
                    while threat.event_id in reserved_database_ids or threat.event_id in assigned_this_run:
                        threat.event_id = f"EVT_{uuid.uuid4().hex[:8].upper()}"
                    logger.warning("[EVENT ID] Collision %s -> %s", previous_id, threat.event_id)

                archived_urls = list(threat.source_urls or [])
                new_count += 1
                threat.first_seen_at = now_iso
                change_type = "FIRST_DETECTED"
                notes = f"Initial detection in {run_id}"

            if threat.event_id in assigned_this_run:
                raise ValueError(f"Duplicate event_id after reconciliation: {threat.event_id}")

            # Persist event observations transactionally while preserving first-seen identity.
            assigned_this_run.add(threat.event_id)
            threat.last_seen_at = threat.updated_at = now_iso

            state_vals = (
                threat.threat_description, threat.confirmed_facts, threat.analytical_interpretation,
                threat.hypothetical_scenario, threat.fact_check_quote, threat.threat_score,
                threat.score_rationale, threat.confidence_level.value, threat.urgency.value,
                threat.escalation_level.value, threat.event_status.value,
                threat.validation_status.value, threat.verification_status,
            )
            meta_vals = (
                now_iso, now_iso, json.dumps(threat.kiq_ids), json.dumps(archived_urls),
                json.dumps(threat.evidence_ids), json.dumps(threat.impact_path),
                json.dumps(threat.corroboration_summary), threat.missing_data,
            )

            if matched_row is not None:
                cur.execute(
                    """
                    UPDATE events SET
                        threat_description = ?, confirmed_facts = ?, analytical_interpretation = ?,
                        hypothetical_scenario = ?, fact_check_quote = ?, threat_score = ?,
                        score_rationale = ?, confidence_level = ?, urgency = ?, escalation_level = ?,
                        event_status = ?, validation_status = ?, verification_status = ?,
                        last_seen_at = ?, updated_at = ?, kiq_ids_json = ?, source_urls_json = ?,
                        evidence_ids_json = ?, impact_path_json = ?, corroboration_json = ?, missing_data = ?
                    WHERE event_id = ?
                    """,
                    (*state_vals, *meta_vals, threat.event_id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO events (
                        event_id, canonical_url, syndication_fingerprint, company_affected,
                        risk_type, scm_tier, ci_dimension, propagation_effect, geographic_epicenter,
                        threat_description, confirmed_facts, analytical_interpretation, hypothetical_scenario,
                        fact_check_quote, threat_score, score_rationale, confidence_level, urgency,
                        escalation_level, event_status, validation_status, verification_status,
                        first_seen_at, last_seen_at, updated_at, kiq_ids_json, source_urls_json,
                        evidence_ids_json, impact_path_json, corroboration_json, missing_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        threat.event_id, threat.evidence_citation, "", threat.company_affected,
                        threat.risk_type.value, threat.scm_tier.value, threat.ci_dimension.value,
                        threat.propagation_effect.value, threat.geographic_epicenter,
                        *state_vals, now_iso, *meta_vals,
                    ),
                )

            cur.execute(
                """
                INSERT INTO event_history (
                    event_id, run_id, recorded_at, threat_score, confidence_level, event_status, change_type, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    threat.event_id, run_id, now_iso, threat.threat_score,
                    threat.confidence_level.value, threat.event_status.value, change_type, notes,
                ),
            )

        resolved_count = max(0, len(existing_rows) - len(matched_existing_ids)) if existing_rows else 0
        conn.commit()

    return threats, new_count, continuing_count, resolved_count


# Calculate event and severity changes between analytically comparable runs.
# A run delta is meaningful only for matching KIT, scope, and dataset conditions.
# Only runs with compatible scope and dataset conditions should be compared.
def compute_comparable_run_delta(
    current_run_id: str,
    normalized_query: str,
    analysis_scope: str,
    c_crit: int,
    c_elev: int,
    c_mon: int,
    current_threats: List[ThreatAssessment],
    current_watchlist: Optional[List[ThreatAssessment]] = None,
    effective_to: str = "",
    as_of_date: str = "",
) -> Dict[str, Any]:
    # Select only comparable runs for change reporting and avoid replay contamination.
    """Compare event identities and classifications across compatible analytical runs."""
    explicitly_resolved = sum(1 for t in current_threats if t.event_status == EventStatus.RESOLVED)
    unknown_state = sum(1 for t in current_threats if t.publication_time == "DATE_UNKNOWN")

    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        prev = cur.execute(
            """
            SELECT * FROM analytical_runs
            WHERE run_id != ?
              AND normalized_query = ?
              AND analysis_scope = ?
              AND status = 'completed'
              AND outcome_status IN ('COMPLETED', 'NO_RELEVANT_EVENTS')
              AND COALESCE(as_of_date, '') = ?
              AND ABS(julianday(effective_to) - julianday(?)) <=
                  CASE WHEN analysis_scope = '24h' THEN 0.5
                       WHEN analysis_scope = '7d' THEN 1 ELSE 3 END
            ORDER BY completed_at DESC LIMIT 1
            """,
            (current_run_id, normalized_query, analysis_scope, as_of_date, effective_to),
        ).fetchone()

        if not prev:
            return {
                "has_comparable_run": False,
                "previous_run_id": None,
                "note": "No previous run with identical KIT and time scope; baseline established.",
                "delta_critical": 0,
                "delta_elevated": 0,
                "delta_monitored": 0,
                "new_events": len(current_threats),
                "continuing_events": 0,
                "not_redetected_events": 0,
                "resolved_events": explicitly_resolved,
                "unknown_status_events": unknown_state,
                "reclassified_to_watchlist": 0,
                "methodology_changed": False,
            }

        prev_run_id = prev["run_id"]
        prev_rep_row = cur.execute("SELECT report_json FROM reports WHERE run_id = ? LIMIT 1", (prev_run_id,)).fetchone()

    prev_report_data = {}
    if prev_rep_row and prev_rep_row["report_json"]:
        try:
            prev_report_data = json.loads(prev_rep_row["report_json"])
        except (ValueError, TypeError):
            pass

    previous_events = prev_report_data.get("threats") or []
    prev_event_ids = {e["event_id"] for e in previous_events if e.get("event_id")}
    curr_event_ids = {t.event_id for t in current_threats if t.event_id}
    watchlist_events = current_watchlist or []
    watch_ids = {w.event_id for w in watchlist_events if w.event_id}

    reclassified_previous_ids = set()
    for old_event in previous_events:
        old_id = old_event.get("event_id")
        if not old_id or not watchlist_events:
            continue

        previous_row = {
            "canonical_url": old_event.get("evidence_citation") or "",
            "company_affected": old_event.get("company_affected") or "",
            "risk_type": old_event.get("risk_type") or "",
            "threat_description": old_event.get("threat_description") or "",
            "fact_check_quote": old_event.get("fact_check_quote") or "",
        }
        if old_id in watch_ids or any(
            _incident_match_score(w, previous_row, old_event.get("source_urls") or []) > 0
            for w in watchlist_events
        ):
            reclassified_previous_ids.add(old_id)

    continuing_in_scope = len(curr_event_ids & prev_event_ids)
    new_in_scope = len(curr_event_ids - prev_event_ids)
    not_redetected_in_scope = len(prev_event_ids - curr_event_ids - reclassified_previous_ids)
    reclassified_count = len(reclassified_previous_ids)

    previous_metadata = prev_report_data.get("run_metadata") or {}
    methodology_changed = previous_metadata.get("classification_version") != "SUPPORTED_ONLY_DASHBOARD_V3_EVENT_ID_1TO1"

    return {
        "has_comparable_run": True,
        "previous_run_id": prev_run_id,
        "previous_completed_at": prev["completed_at"],
        "delta_critical": c_crit - int(prev["count_critical"] or 0),
        "delta_elevated": c_elev - int(prev["count_elevated"] or 0),
        "delta_monitored": c_mon - int(prev["count_monitored"] or 0),
        "new_events": new_in_scope,
        "continuing_events": continuing_in_scope,
        "not_redetected_events": not_redetected_in_scope,
        "resolved_events": explicitly_resolved,
        "unknown_status_events": unknown_state,
        "reclassified_to_watchlist": reclassified_count,
        "methodology_changed": methodology_changed,
        "note": (
            f"NEW: {new_in_scope} | CONTINUING: {continuing_in_scope} | "
            f"RECLASSIFIED_TO_WATCHLIST: {reclassified_count} | "
            f"NOT_REDETECTED: {not_redetected_in_scope} | RESOLVED (evidenced): {explicitly_resolved}"
            + (
                " | CLASSIFICATION METHODOLOGY CHANGED: historical severity deltas are not directly comparable."
                if methodology_changed else ""
            )
        ),
    }


# Update the historical export using schema-safe, atomic CSV replacement.
# The CSV export is a projection of stored history, not the event-identity authority.
def append_to_historical_archive(threats_data: List[Dict[str, Any]]) -> None:
    # Write historical CSV exports with schema reconciliation and atomic replacement.
    """Safely update historical CSV with schema alignment and atomic write."""
    if not threats_data:
        return

    df_new = pd.DataFrame(threats_data).copy()
    df_new["run_timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if os.path.exists(HISTORICAL_CSV):
        try:
            df_existing = pd.read_csv(HISTORICAL_CSV, encoding="utf-8-sig")
        except Exception as e:
            logger.error("[ARCHIVE ERROR] Historical CSV is malformed. Append aborted to prevent further corruption: %s", e)
            return

        columns = list(dict.fromkeys(list(df_existing.columns) + list(df_new.columns)))
        df_existing, df_new = df_existing.reindex(columns=columns), df_new.reindex(columns=columns)

        if "evidence_citation" in df_existing.columns:
            existing_urls = set(df_existing["evidence_citation"].dropna().astype(str))
            df_new = df_new[~df_new["evidence_citation"].astype(str).isin(existing_urls)]

        if df_new.empty:
            return
        df_final = pd.concat([df_existing, df_new], ignore_index=True)
    else:
        df_final = df_new

    temp_path = HISTORICAL_CSV + ".tmp"
    try:
        df_final.to_csv(temp_path, index=False, encoding="utf-8-sig")
        os.replace(temp_path, HISTORICAL_CSV)
        logger.info("[HISTORICAL ARCHIVE] Safely saved %s new records.", len(df_new))
    except Exception:
        logger.exception("[ARCHIVE ERROR] Atomic CSV write failed.")
        if os.path.exists(temp_path):
            os.remove(temp_path)


# Persist the completed structured intelligence report to SQLite.
def save_report_to_db(report: EWSReport) -> None:
    now_iso = _now_iso()
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO reports (
                report_id, run_id, version, hitl_status, outcome_status, created_at, updated_at, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.report_id, report.run_id, report.version, report.hitl_status,
                report.outcome_status.value, now_iso, now_iso, report.model_dump_json(indent=2),
            ),
        )
        conn.commit()


init_sqlite_db()