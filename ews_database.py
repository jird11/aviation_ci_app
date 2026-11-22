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
import hashlib
import hmac
from contextlib import contextmanager
from ews_state import (
    Any, DB_LOCK, Dict, EWSReport, EventStatus, HISTORICAL_CSV, List,
    Optional, SQLITE_DB, SequenceMatcher, ThreatAssessment, Tuple,
    datetime, json, logger, os, pd, sqlite3, timezone,
)

# Provide a normalized UTC timestamp for report metadata and audit records.
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

from aero_ews.persistence.schema import DEFAULT_KIQ_CATALOG, _DDL_SCRIPT


@contextmanager
def _database(write: bool = False):
    """Own the connection and commit only complete write operations."""
    with DB_LOCK:
        conn = sqlite3.connect(SQLITE_DB)
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except Exception:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()


def _document_digest(document: Dict[str, Any]) -> str:
    payload = json.dumps(document, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_VERIFIED_FLAGS = frozenset({
    "verified", "is_verified", "evidence_verified", "validated", "is_validated",
    "quote_verified", "full_quote_verified", "source_quote_verified", "passage_verified",
    "document_verified", "claim_verified", "event_confirmed", "claim_confirmed",
    "semantic_evidence_verified", "raw_verified", "source_verified", "source_identity_verified",
    "fully_verified", "direct_verified", "claims_verified", "certificate_document_verified",
    "direct_kit_confirmed", "is_confirmed", "regulator_decision_verified", "issuer_identity_verified",
})
_VERIFICATION_STATUSES = frozenset({
    "verification_status", "validation_status", "quote_verification_status",
    "evidence_verification_status", "source_verification_status", "passage_verification_status",
    "document_verification_status", "claim_verification_status", "event_verification_status",
    "independent_verification_status",
})


def _unverify_evidence(document: Dict[str, Any], reason: str) -> None:
    """Invalidate every derived verdict, retaining its prior state for audit."""
    prior = []

    def invalidate(item: Any, path: str) -> None:
        if isinstance(item, list):
            for index, child in enumerate(item):
                invalidate(child, f"{path}[{index}]")
        elif isinstance(item, dict):
            keys = (_VERIFIED_FLAGS | _VERIFICATION_STATUSES | {"evidence_authority"}) & item.keys()
            if keys:
                prior.append({"path": path, "values": {key: item[key] for key in sorted(keys)}})
            for key in keys:
                item[key] = (False if key in _VERIFIED_FLAGS else "UNKNOWN" if key == "evidence_authority"
                             else "UNVERIFIED")
            for key in ("evidence_passages", "source_passages", "evidence", "validation", "claims", "passages"):
                if key in item:
                    invalidate(item[key], f"{path}.{key}")

    invalidate(document, "document")
    document["replay_prior_verification"] = prior
    document["replay_integrity_status"] = "INVALID" if any(
        code in reason for code in ("MISMATCH", "MALFORMED", "INVALID", "CONFLICT")
    ) else "UNKNOWN"
    document["replay_integrity_reason"] = reason
    document["replay_requires_reverification"] = True
    document["replay_evidence_usable"] = False


# Initialize persistent tables and indexes required by the intelligence pipeline.
# Schema changes must preserve existing observations and provenance links.
# Schema initialization occurs before database-dependent pipeline operations.
def init_sqlite_db() -> None:
    # Create or migrate the persistence schema without requiring a separate migration command.
    with _database(write=True) as conn:
        cur = conn.cursor()
        if re.search(r"\bDROP\s+TABLE\b", _DDL_SCRIPT, re.I):
            raise RuntimeError("Destructive schema DDL requires manual review; existing data were not modified")
        # executescript() commits a pending transaction; execute each DDL statement instead.
        for statement in _DDL_SCRIPT.split(";"):
            if statement.strip():
                cur.execute(statement)

        existing_columns = {row[1] for row in cur.execute("PRAGMA table_info(source_documents)")}
        for col, col_type in [
            ("content_status", "TEXT DEFAULT 'TEXT_COMPLETENESS_UNVERIFIED'"),
            ("content_sha256", "TEXT"),
            ("content_truncated", "INTEGER DEFAULT 0"),
            ("content_limit_reason", "TEXT"),
            ("source_metadata_json", "TEXT"),
        ]:
            if col not in existing_columns:
                cur.execute(f"ALTER TABLE source_documents ADD COLUMN {col} {col_type}")

        if "evidence_metadata_json" in existing_columns:
            cur.execute("""
                UPDATE source_documents
                SET source_metadata_json = evidence_metadata_json
                WHERE (source_metadata_json IS NULL OR TRIM(source_metadata_json) = '')
                  AND evidence_metadata_json IS NOT NULL
                  AND TRIM(evidence_metadata_json) <> ''
            """)

        reference_columns = {row[1] for row in cur.execute("PRAGMA table_info(reference_dataset)")}
        for col, col_type in [
            ("kit_topic", "TEXT DEFAULT 'GENERAL'"),
            ("expected_scm_tier", "TEXT DEFAULT 'OEM (Final Assembler)'"),
            ("expected_program", "TEXT DEFAULT 'Unspecified'"),
            ("problem_keywords", "TEXT DEFAULT ''"),
            ("supporting_quote", "TEXT DEFAULT ''"),
        ]:
            if col not in reference_columns:
                cur.execute(f"ALTER TABLE reference_dataset ADD COLUMN {col} {col_type}")

        cur.executemany(
            """
            INSERT OR REPLACE INTO kiq_catalog (
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


def save_source_document_metadata(run_id: str, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Persist immutable, checksummed source snapshots for reproducible replay."""
    if not documents:
        return {"saved": 0, "missing_doc_ids": []}
    with _database(write=True) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(source_documents)")}
        key = next((name for name in ("doc_id", "document_id") if name in columns), None)
        if not key or "run_id" not in columns or "source_metadata_json" not in columns:
            raise RuntimeError("source_documents replay schema is missing document ID, run ID or metadata column")
        saved, seen, missing = 0, {}, []
        for doc in documents:
            doc_id = str(doc.get("doc_id") or doc.get("document_id") or "")
            if not doc_id:
                missing.append("<NO_DOC_ID>")
                continue
            document = json.loads(json.dumps(doc, ensure_ascii=False, default=str))
            digest = _document_digest(document)
            if doc_id in seen and seen[doc_id] != digest:
                raise ValueError(f"Conflicting evidence snapshots for {run_id}/{doc_id}")
            seen[doc_id] = digest
            previous = conn.execute(
                f"SELECT source_metadata_json FROM source_documents WHERE {key} = ? AND run_id = ?",
                (doc_id, run_id),
            ).fetchone()
            if previous is None:
                missing.append(doc_id)
                continue
            if previous[0]:
                old = json.loads(previous[0])
                if not isinstance(old, dict) or old.get("document", old) != document:
                    raise ValueError(f"Refusing to overwrite different evidence for {run_id}/{doc_id}")
            snapshot = json.dumps({"schema_version": 2, "run_id": run_id, "doc_id": doc_id,
                                   "document": document,
                                   "snapshot_sha256": digest}, ensure_ascii=False)
            conn.execute(
                f"UPDATE source_documents SET source_metadata_json = ? WHERE {key} = ? AND run_id = ?",
                (snapshot, doc_id, run_id),
            )
            saved += 1
        if missing:
            raise RuntimeError(f"Missing source document rows for {run_id}: {missing}")
    return {"saved": saved, "missing_doc_ids": []}


def restore_source_document(row: Dict[str, Any]) -> Dict[str, Any]:
    """Restore evidence without promoting missing or inconsistent hashes to verified."""
    doc = dict(row)
    doc_id, run_id = doc.get("doc_id") or doc.get("document_id"), doc.get("run_id")
    integrity_issues: List[str] = []
    valid_snapshot = False
    snapshot_digests = set()

    for column in ("evidence_metadata_json", "source_metadata_json"):
        payload = doc.pop(column, None)
        if not payload:
            continue

        try:
            metadata = json.loads(payload) if isinstance(payload, str) else payload
            if not isinstance(metadata, dict):
                raise ValueError("Invalid metadata structure")

            original = metadata.get("document", metadata)
            if not isinstance(original, dict):
                raise ValueError("Invalid document snapshot")
            if (metadata.get("doc_id", doc_id) != doc_id
                    or metadata.get("run_id", run_id) != run_id):
                integrity_issues.append("SNAPSHOT_BINDING_MISMATCH")
            if column == "source_metadata_json" and not (
                    (original.get("doc_id") or original.get("document_id")) and original.get("source_id")):
                integrity_issues.append("SOURCE_IDENTITY_UNVERIFIABLE")
            if column == "source_metadata_json" and original.get("replay_integrity_status") in {"INVALID", "UNKNOWN"}:
                integrity_issues.append(f"PREVIOUS_REPLAY_INTEGRITY_{original['replay_integrity_status']}")
            checksum = metadata.get("snapshot_sha256")
            digest = _document_digest(original)
            if checksum:
                if not hmac.compare_digest(str(checksum), digest):
                    integrity_issues.append("SNAPSHOT_HASH_MISMATCH")
                else:
                    snapshot_digests.add(digest)
                    valid_snapshot |= column == "source_metadata_json"
            if (original.get("doc_id", original.get("document_id", doc_id)) != doc_id
                    or original.get("run_id", run_id) != run_id):
                integrity_issues.append("SOURCE_IDENTITY_MISMATCH")
            for name in ("url", "source_url", "link", "source_id", "text", "citation",
                         "evidence_citation", "evidence_quote", "content_sha256", "source_metadata",
                         "issuer_identity", "issuer_id", "issuer_cik", "issuer", "publisher",
                         "source_name", "published_at"):
                if name in row and name in original and row[name] != original[name]:
                    integrity_issues.append(f"ROW_SNAPSHOT_MISMATCH:{name}")
            doc.update(original)
            if column == "source_metadata_json":
                doc["source_snapshot_sha256"] = checksum or ""
                doc["source_snapshot_schema_version"] = metadata.get("schema_version", 1)
        except (TypeError, ValueError):
            integrity_issues.append("SNAPSHOT_UNVERIFIABLE_MALFORMED")
            logger.warning(
                "[REPLAY METADATA] Invalid %s for document %s",
                column, doc_id,
            )

    if not valid_snapshot:
        integrity_issues.append("SNAPSHOT_UNVERIFIABLE_LEGACY")
    if len(snapshot_digests) > 1:
        integrity_issues.append("CONFLICTING_SNAPSHOTS")

    doc["doc_id"], doc["run_id"] = doc_id, run_id

    if isinstance(doc.get("metadata"), dict):
        for key, value in doc["metadata"].items():
            doc.setdefault(key, value)

    for canonical, alternatives in {
        "url": ("source_url", "link"),
        "published_at": ("date",),
        "text": ("body", "content"),
    }.items():
        if not doc.get(canonical):
            doc[canonical] = next(
                (doc[key] for key in alternatives if doc.get(key)), ""
            )

    passages = []
    for key in ("evidence_passages", "source_passages"):
        items = doc.get(key)
        if items is not None:
            if not isinstance(items, list):
                integrity_issues.append(f"PASSAGE_UNVERIFIABLE_STRUCTURE:{key}")
            else:
                passages.extend(items)
    for index, passage in enumerate(passages):
        if not isinstance(passage, dict):
            integrity_issues.append(f"PASSAGE_UNVERIFIABLE_STRUCTURE:{index}")
            continue
        digest = passage.get("passage_sha256") or passage.get("passage_hash") or passage.get("quote_hash")
        if not digest:
            if (any(passage.get(flag) is True for flag in _VERIFIED_FLAGS)
                    or any(str(passage.get(status) or "").upper() in {
                        "VERIFIED", "SOURCE_PASSAGE_VERIFIED", "QUOTE_VERIFIED", "FULL_QUOTE_VERIFIED"
                    } for status in _VERIFICATION_STATUSES)):
                integrity_issues.append(f"PASSAGE_UNVERIFIABLE_HASH:{index}")
            continue
        quote = passage.get("passage_text") or passage.get("quote") or passage.get("text")
        if not isinstance(quote, str):
            integrity_issues.append(f"PASSAGE_UNVERIFIABLE_TEXT:{index}")
        elif not hmac.compare_digest(str(digest).lower().removeprefix("sha256:"),
                                     hashlib.sha256(quote.encode("utf-8")).hexdigest()):
            integrity_issues.append(f"PASSAGE_HASH_MISMATCH:{index}")
        elif doc.get("content_status") == "FULL_TEXT" and isinstance(doc.get("text"), str):
            source_text = re.sub(r"\s+", " ", doc["text"]).casefold()
            if re.sub(r"\s+", " ", quote).casefold() not in source_text:
                integrity_issues.append(f"PASSAGE_SOURCE_TEXT_MISMATCH:{index}")

    if integrity_issues:
        doc["replay_integrity_issues"] = list(dict.fromkeys(integrity_issues))
        _unverify_evidence(doc, "; ".join(doc["replay_integrity_issues"]))
    else:
        doc["replay_integrity_issues"] = []
        doc["replay_integrity_status"] = "SNAPSHOT_HASH_MATCH"
        doc["replay_integrity_reason"] = ""
        doc["replay_requires_reverification"] = False
        doc["replay_evidence_usable"] = False  # A checksum is not external quote/source verification.
    if doc.get("source_content_sha256"):
        doc["source_hash_recheck_status"] = "NOT_RECHECKED_RAW_SOURCE"
    return doc


def load_source_documents_for_replay(run_id: str) -> List[Dict[str, Any]]:
    """Load only the requested run with evidence metadata intact."""
    with _database() as conn:
        conn.row_factory = sqlite3.Row
        columns = {row[1] for row in conn.execute("PRAGMA table_info(source_documents)")}
        if "run_id" not in columns:
            raise RuntimeError("Replay requires a run_id column to prevent mixing different runs")
        rows = conn.execute(
            "SELECT * FROM source_documents WHERE run_id = ? ORDER BY doc_id",
            (run_id,),
        ).fetchall()
    return [restore_source_document(dict(row)) for row in rows]

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
    with _database() as conn:
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

_FR_DOC_NUM_RE = re.compile(r"/documents/(?:20\d{2}/\d{2}/\d{2}/)?(20\d{2}-\d{4,6})(?:/|$)", re.I)
_EASA_AD_NUM_RE = re.compile(r"(?:\bEASA\s+P?AD\s+|#ad=)(20\d{2}-\d{4})\b", re.I)
_NTSB_CASE_RE = re.compile(r"(?:\bNTSB\s+(?:case\s+)?|#)([A-Z]{3}\d{2}[A-Z]{2}\d{3})\b", re.I)


def _faa_lifecycle_identity(summary: Dict[str, Any]) -> Tuple[str, str]:
    """Extract verified FAA docket identity and earlier-document URL."""
    if not isinstance(summary, dict):
        return "", ""
    if (summary.get("FAA Lifecycle Verified") != "YES"
            and summary.get("FAA Publication Verified") != "YES"):
        return "", ""

    docket = str(summary.get("FAA Docket") or "").strip().upper()
    earlier_url = str(summary.get("FAA Prior Document") or "").strip()

    if not re.fullmatch(r"FAA-\d{4}-\d+", docket):
        docket = ""
    if "federalregister.gov/documents/" not in earlier_url:
        earlier_url = ""

    return docket, earlier_url


def _official_record_ids(summary: Dict[str, Any], urls: set[str], text: str) -> Dict[str, str]:
    """Extract authoritative document/case identifiers to prevent cross-document merges."""
    ids: Dict[str, str] = {}
    if isinstance(summary, dict):
        doc_num = str(summary.get("FAA Document Number") or "").strip()
        if re.fullmatch(r"20\d{2}-\d{4,6}", doc_num):
            ids["fr_doc"] = doc_num
        docket = str(summary.get("FAA Docket") or "").strip().upper()
        if re.fullmatch(r"FAA-\d{4}-\d+", docket):
            ids["faa_docket"] = docket
    joined_urls = " ".join(str(u or "") for u in urls)
    if "fr_doc" not in ids and (m := _FR_DOC_NUM_RE.search(joined_urls)):
        ids["fr_doc"] = m.group(1)
    if m := _EASA_AD_NUM_RE.search(f"{joined_urls} {text}"):
        ids["easa_ad"] = m.group(1)
    if m := _NTSB_CASE_RE.search(f"{joined_urls} {text}"):
        ids["ntsb_case"] = m.group(1).upper()
    return ids


# Assess whether two observations refer to the same supported real-world event.
# Do not equate high textual similarity with confirmed event identity.
def _incident_match_score(threat: ThreatAssessment, row: sqlite3.Row, old_urls: List[str]) -> float:
    """Return 0 when same-event identity is not adequately supported."""
    incoming_urls = {u for u in (set(threat.source_urls or []) | {threat.evidence_citation}) if u}
    historical_urls = {u for u in (set(old_urls) | {row["canonical_url"]}) if u}
    shared_source = bool(incoming_urls & historical_urls)

    same_actor = (threat.company_affected or "").strip().casefold() == (row["company_affected"] or "").strip().casefold()
    if not shared_source and not same_actor:
        return 0.0
    if shared_source and threat.risk_type.value != row["risk_type"]:
        return 0.0

    new_models = _incident_airframes(f"{threat.affected_program} {threat.threat_description} {threat.fact_check_quote}")
    old_models = _incident_airframes(f"{row['threat_description'] or ''} {row['fact_check_quote'] or ''}")
    if new_models and old_models and new_models.isdisjoint(old_models):
        return 0.0

    try:
        old_audit = json.loads(row["corroboration_json"] or "{}")
    except (KeyError, IndexError, ValueError, TypeError):
        old_audit = {}
    new_audit = threat.corroboration_summary or {}

    new_ids = _official_record_ids(new_audit, incoming_urls, f"{threat.threat_description} {threat.fact_check_quote}")
    old_ids = _official_record_ids(old_audit, historical_urls, f"{row['threat_description'] or ''} {row['fact_check_quote'] or ''}")

    # Distinct official regulatory or investigation identifiers must never collapse into one event.
    for key in ("faa_docket", "easa_ad", "ntsb_case"):
        if new_ids.get(key) and old_ids.get(key) and new_ids[key] != old_ids[key]:
            return 0.0

    if same_actor and threat.risk_type.value == "REGULATORY" and row["risk_type"] == "REGULATORY":
        new_docket, earlier_url = _faa_lifecycle_identity(new_audit)
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

    # Two different Federal Register documents without a shared verified docket/prior link are distinct.
    if (new_ids.get("fr_doc") and old_ids.get("fr_doc")
            and new_ids["fr_doc"] != old_ids["fr_doc"]):
        return 0.0

    norm = lambda v: re.sub(r"\s+", " ", (v or "").casefold()).strip()
    new_desc_norm = norm(threat.threat_description)
    old_desc_norm = norm(row["threat_description"])
    similarity = SequenceMatcher(None, new_desc_norm, old_desc_norm).ratio()

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

    # Generic fallback descriptions (e.g. "Unverified source claim...") cannot prove identity without matching quotes.
    if new_desc_norm.startswith("unverified source claim") or old_desc_norm.startswith("unverified source claim"):
        q_new, q_old = norm(threat.fact_check_quote), norm(row["fact_check_quote"])
        if not (q_new and q_old and SequenceMatcher(None, q_new, q_old).ratio() >= 0.85):
            return 0.0

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

    with _database(write=True) as conn:
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
                archived_urls = [u for u in dict.fromkeys(urls) if u and 'example.com' not in u][:5]

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

            prior = cur.execute(
                "SELECT * FROM event_history WHERE event_id = ? AND run_id = ? LIMIT 1",
                (threat.event_id, run_id),
            ).fetchone()
            if prior:
                if (prior["threat_score"] != threat.threat_score
                        or prior["event_status"] != threat.event_status.value
                        or prior["confidence_level"] != threat.confidence_level.value):
                    raise ValueError(f"Conflicting observation for {run_id}/{threat.event_id}")
                if prior["change_type"] == "FIRST_DETECTED" and matched_row is not None:
                    new_count += 1
                    continuing_count -= 1
            else:
                cur.execute(
                    """
                    INSERT INTO event_history (
                        event_id, run_id, recorded_at, threat_score, confidence_level,
                        event_status, change_type, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (threat.event_id, run_id, now_iso, threat.threat_score,
                     threat.confidence_level.value, threat.event_status.value, change_type, notes),
                )

        resolved_count = max(0, len(existing_rows) - len(matched_existing_ids)) if existing_rows else 0

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

    with _database() as conn:
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
    with _database(write=True) as conn:
        source_rows = conn.execute(
            "SELECT doc_id, source_metadata_json FROM source_documents WHERE run_id = ?",
            (report.run_id,),
        ).fetchall()
        for doc_id, payload in source_rows:
            try:
                snapshot = json.loads(payload)
                if not isinstance(snapshot, dict):
                    raise ValueError("Invalid snapshot")
                checksum = snapshot.get("snapshot_sha256")
                if checksum and not hmac.compare_digest(
                    str(checksum), _document_digest(snapshot.get("document", {}))
                ):
                    raise ValueError("Snapshot checksum mismatch")
            except (TypeError, ValueError) as exc:
                raise RuntimeError(f"Report {report.run_id}: incomplete or corrupt evidence {doc_id}") from exc
        duplicate = conn.execute(
            "SELECT report_id FROM reports WHERE run_id = ? AND version = ? AND report_id != ?",
            (report.run_id, report.version, report.report_id),
        ).fetchone()
        if duplicate:
            raise ValueError(f"Conflicting report identity for run {report.run_id}, version {report.version}")
        conn.execute(
            """
            INSERT INTO reports (
                report_id, run_id, version, hitl_status, outcome_status, created_at, updated_at, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(report_id) DO UPDATE SET
                run_id = excluded.run_id, version = excluded.version,
                hitl_status = excluded.hitl_status, outcome_status = excluded.outcome_status,
                updated_at = excluded.updated_at, report_json = excluded.report_json
            """,
            (
                report.report_id, report.run_id, report.version, report.hitl_status,
                report.outcome_status.value, now_iso, now_iso, report.model_dump_json(indent=2),
            ),
        )

init_sqlite_db()
