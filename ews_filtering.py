# =============================================================================
# aviation_ci_app | Two-stage KIT-relevance screening and audit trail
#
# Responsibility: Apply deterministic document gates, model-assisted semantic decisions, conservative
#   context checks, and analyst batching.
# Design boundary: A rejected or unavailable source must not be misrepresented as proof that no relevant
#   event exists.
# =============================================================================


"""Document relevance screening, audit logging, and analyst input batching."""

import hashlib
from ews_database import get_active_kiq_catalog
from ews_evidence_contract import assess_official_faa_fact
from ews_kiq import build_catalog_prompt_context
from ews_state import (
    Any, DB_LOCK, Dict, GEMINI_API_KEY, List, PROMPT_VERSION, SQLITE_DB,
    Tuple, datetime, fast_llm, genai, is_date_within_scope, json, logger,
    os, re, sqlite3, timezone,
)
from ews_validation import (
    _detect_aircraft_families,
    _detect_exact_variants,
    _detect_engine_models,
    _engine_models_match,
    kit_direct_relevance_gap,
)

# Deterministic screening patterns and relevance-cache configuration.
OBVIOUS_NOISE_REGEX = re.compile(
    r"\b(?:1:200|1:400|scale\s+model|diecast|unboxing|flight\s+simulator|msfs\s*202\d|x-plane|infinite\s+flight)\b",
    re.I,
)
_SEMANTIC_CACHE_VERSION = "FR03-EVIDENCE-CONTRACT-4"
_SOURCE_TYPE_SCORES = {
    "REGULATORY": 100,
    "OEM_PR": 80,
    "INDUSTRY_EVENT": 60,
    "MEDIA_AGGREGATOR": 50,
    "GEOGRAPHIC_SIGNAL": 50,
}


# Normalize text for stable identity and overlap comparisons.
def _alnum_norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()


# Select a bounded source excerpt emphasizing KIT terms and operational risk indicators.
def relevant_excerpt(text: str, query: str, limit: int = 1500) -> str:
    """Prioritize KIT-specific and risk-related passages under a bounded context budget."""
    terms = set(re.findall(r"\b[a-z0-9]{3,}\b", query.lower()))
    risks = {"delay", "shortage", "defect", "recall", "grounded", "disruption", "inspection"}

    pattern = "|".join(re.escape(x) for x in terms | risks)
    matches = list(re.finditer(r"\b(?:" + pattern + r")\b", text, re.I))

    snippets = [text[max(0, m.start() - 200):m.end() + 350] for m in matches]
    snippets.sort(
        key=lambda s: sum(3 for w in terms if w in s.lower()) + sum(2 for w in risks if w in s.lower()),
        reverse=True,
    )
    return (text[:250] + "\n...\n" + "\n...\n".join(snippets[:2]))[:limit]


# Identify documents that share background context but do not support the specific KIT issue.
# Record why contextual overlap was insufficient for a direct KIT signal.
def _kit_context_reason(query: str, doc: Dict[str, Any]) -> str:
    """Identify related context that does not establish the actual technical or operational KIT issue."""
    kit = query.lower()
    evidence = f"{doc.get('title') or ''} {doc.get('text') or ''}".lower()

    # General exclusion-aware identity guard. 'exclude X' is a negative
    # constraint, never an additional model that could justify relevance.
    positive_kit = re.split(
        r"\b(?:exclude|excluding|except)\b", kit, maxsplit=1, flags=re.I
    )[0]
    if (
        _detect_engine_models(positive_kit)
        and _detect_engine_models(evidence)
        and not _engine_models_match(positive_kit, evidence)
    ):
        return "RELATED_CONTEXT: source propulsion identity conflicts with the positively requested engine."

    # Treat specific engine identity as a technical constraint, not a generic keyword overlap.
    requested_blades = {
        part
        for part in ("turbine", "compressor", "fan")
        if re.search(rf"\b{part}\s+blades?\b", kit)
    }

    if (
        requested_blades
        and _detect_engine_models(kit)
        and _engine_models_match(kit, evidence)
        and not any(
            re.search(rf"\b{part}\s+blades?\b", evidence)
            for part in requested_blades
        )
    ):
        return (
            "RELATED_CONTEXT: matching engine, but the requested "
            "blade component is not evidenced."
        )

    issue_kit = bool(
        re.search(
            r"\b(?:engine\s+(?:inspection\w*|defect\w*|problem\w*)|"
            r"supply\s+constraint|grounding|"
            r"failure\w*|defect\w*|inspect\w*|"
            r"shortag\w*|disrupt\w*|delay\w*)\b",
            kit,
        )
    )
    transaction = bool(
        re.search(r"\b(?:order(?:ed|s|ing)?|selected|purchas\w*|leasing|fleet\s+acquisition|agreement\s+to\s+buy)\b", evidence)
    )
    direct_issue = bool(
        re.search(
            r"\b(?:inspect(?:ion|ions|ed)?|defect\w*|failure\w*|shortag\w*|ground(?:ed|ing)?|"
            r"disrupt\w*|delay\w*|capacity\s+constraint|unscheduled\s+removal)\b",
            evidence,
        )
    )

    if issue_kit and transaction and not direct_issue:
        return "RELATED_CONTEXT: commercial transaction without evidence of the requested technical/operational problem."

    if (
        re.search(r"\b(?:inspection\w*|defect\w*|failure\w*|shortag\w*|grounding|disruption\w*|production\s+constraint\w*)\b", kit)
        and not re.search(r"\b(?:certification|certified|type\s+certificate|approval)\b", kit)
        and re.search(
            r"\b(?:certified|certification|product\s+launch|new\s+engine\s+variant|technology\s+upgrade|engine\s+upgrade)\b",
            evidence,
        )
        and not direct_issue
    ):
        return (
            "RELATED_CONTEXT: product certification or technology announcement "
            "without evidence of the monitored technical/operational problem."
        )

    if (
        _detect_engine_models(kit)
        and re.search(
            r"\b(?:easa\s+ad|airworthiness\s+directive|flight\s+controls?)\b",
            evidence,
        )
        and not _engine_models_match(kit, evidence)
    ):
        return (
            "RELATED_CONTEXT: regulatory source does not identify "
            "the engine requested by the KIT."
        )

# Conservatively recognize a direct match in official EASA metadata-only records.
def _official_easa_interim_direct_match(doc: Dict[str, Any], kit: str) -> bool:
    """Conservative fallback for official EASA AD index records."""
    if doc.get("source_id") != "SRC_002" or doc.get("origin_type") != "PRIMARY_OFFICIAL_INDEX_METADATA":
        return False

    text = f"{doc.get('title') or ''} {doc.get('text') or ''}".lower()
    query = kit.lower()

    if not re.search(r"\beasa\s+ad\s+20\d{2}-\d{4}", text):
        return False

    if not _detect_engine_models(query):
        return False

    if not _engine_models_match(query, text):
        return False

    # Require issue-specific evidence in official metadata.
    if (
        re.search(r"\binspect\w*", query)
        and not re.search(r"\binspect\w*", text)
    ):
        return False

    requested_blades = {
        part
        for part in ("turbine", "compressor", "fan")
        if re.search(rf"\b{part}\s+blades?\b", query)
    }

    if requested_blades and not any(
        re.search(rf"\b{part}\s+blades?\b", text)
        for part in requested_blades
    ):
        return False

    return True

# Ask the LLM to classify a batch while distinguishing events, weak signals, and general noise.
# Rejected classifications must retain their reason for subsequent manual review.
def _run_batch_semantic_llm_filter(
    candidates: List[Dict[str, Any]], user_query: str, _retry_split: bool = True
) -> Dict[str, Dict[str, Any]]:
    # Request a structured batch response and keep the semantic categories distinct.
    """Classify candidate sources for KIT relevance in a single model-assisted batch."""
    if not candidates:
        return {}

    if len(candidates) > 5:
        combined = {}
        for start in range(0, len(candidates), 5):
            combined.update(_run_batch_semantic_llm_filter(candidates[start:start + 5], user_query))
        return combined

    catalog_ctx = build_catalog_prompt_context(user_query)
    items_payload = [
        {
            "doc_id": d["doc_id"],
            "source_type": d.get("source_type", "MEDIA"),
            "title": d.get("title", "")[:160],
            "excerpt": relevant_excerpt(d.get("text", ""), user_query, limit=900),
        }
        for d in candidates
    ]

    prompt = (
        f"You are a Competitive Intelligence semantic pre-filter for the aerospace Early Warning System.\n"
        f"Target Key Intelligence Topic (KIT): '{user_query}'\n"
        f"Active KIQ Context:\n{catalog_ctx}\n\n"
        "Evaluate EACH document in the JSON array below and classify it strictly:\n"
        "- Reject (`is_relevant: false`, `signal_type: \"GENERAL_NOISE\"`) if the document is about a DIFFERENT aircraft family "
        "(compare exact models and variants rather than assuming compatibility) "
        "unless it directly concerns a shared supplier bottleneck requested in the KIT.\n"
        "- Reject routine airline PR, hobbyist/model reviews, or general background noise without a concrete event or warning indicator.\n"
        "- Reject purely historical background, aircraft specifications "
        "and documentaries unless they describe a NEW development "
        "within the monitoring period that directly matches the KIT.\n"
        "- Label RELATED_CONTEXT (is_relevant=false) for orders "
        "or other events involving the same entity but not "
        "the KIT issue.\n"
        "- Do NOT reject a document solely because its claims are unverified.\n"
        "- Retain relevant technical anomalies as WEAK_SIGNAL when they match the KIT.\n"
        "- When evidence is ambiguous, prefer WEAK_SIGNAL over GENERAL_NOISE.\n"
        "- Accept (`is_relevant: true`) if it contains a `RELEVANT_EVENT` (confirmed delay, AD directive, defect, shortage, order shift) "
        "or a `WEAK_SIGNAL` (early community/operational anomaly matching the KIT).\n\n"
        "- For competitive KITs, retain concrete new aircraft orders, "
        "cancellations, contracts and market-position changes.\n"
        "- For SAF/environmental KITs, retain concrete certification decisions, "
        "regulatory changes and new compliance obligations.\n"
        "- These must directly match the KIT; reject unrelated routine PR.\n"
        "Return ONLY a valid JSON array where each element has this exact schema:\n"
        "[\n"
        "  {\n"
        '    "doc_id": "DOC_001",\n'
        '    "is_relevant": true,\n'
        '    "matched_kiq_id": "",\n'
        '    "entities_models_tech": "Entities and technology explicitly named in the document",\n'
        '    "signal_type": "RELEVANT_EVENT",\n'
        '    "rationale": "Dated source event directly addresses the monitored KIT."\n'
        "  }\n"
        "]\n\n"
        f"DOCUMENTS TO EVALUATE:\n{json.dumps(items_payload, ensure_ascii=False)}"
    )

    raw_response = ""
    if GEMINI_API_KEY:
        try:
            client = genai.Client(api_key=GEMINI_API_KEY)
            resp = client.models.generate_content(model="gemini-3.5-flash-lite", contents=prompt)
            raw_response = resp.text or ""
        except Exception as e:
            logger.debug(f"[SEMANTIC FILTER] Gemini batch call failed ({e}), falling back to fast_llm.")

    if not raw_response:
        try:
            res = fast_llm.call([{"role": "user", "content": prompt}])
            raw_response = str(res or "")
        except Exception as e:
            logger.warning(f"[SEMANTIC FILTER] LLM batch call unavailable ({e}), using deterministic fallback.")
            return {}

    result_map: Dict[str, Dict[str, Any]] = {}
    allowed_ids = {str(d["doc_id"]).strip().upper() for d in candidates}

    # Parse model JSON defensively; an invalid response is not evidence of irrelevance.
    try:
        match = re.search(r"\[.*\]", raw_response, re.S)
        if not match:
            raise ValueError("Model response does not contain a JSON array")

        parsed_list = json.loads(match.group(0))
        if not isinstance(parsed_list, list):
            raise ValueError("Semantic response must be a JSON array")

        for item in parsed_list:
            if not isinstance(item, dict):
                continue
            doc_id = str(item.get("doc_id") or "").strip().upper()
            if doc_id in allowed_ids and type(item.get("is_relevant")) is bool:
                result_map[doc_id] = item
    except (ValueError, TypeError) as exc:
        logger.warning("[SEMANTIC FILTER] Invalid batch JSON: %s", exc)

    missing = [d for d in candidates if str(d["doc_id"]).strip().upper() not in result_map]
    if missing and _retry_split:
        midpoint = max(1, len(missing) // 2)
        groups = [missing] if len(missing) == 1 else [missing[:midpoint], missing[midpoint:]]
        logger.warning(
            "[SEMANTIC FILTER RECOVERY] Retrying %d unclassified document(s) in %d smaller group(s)",
            len(missing), len(groups),
        )
        for group in groups:
            result_map.update(_run_batch_semantic_llm_filter(group, user_query, _retry_split=False))

    return result_map


# Reuse versioned semantic decisions and classify only uncached candidates.
# Cache reuse is versioned and keyed to avoid unnecessary model calls without silently changing old
#   decisions.
# Cache hits are version-scoped; unavailable classifications do not prove irrelevance.
def _cached_semantic_filter(candidates: List[Dict[str, Any]], user_query: str) -> Dict[str, Dict[str, Any]]:
    # Reuse available cached classifications and classify the remaining documents.
    if not candidates:
        return {}

    catalog_context = build_catalog_prompt_context(user_query)
    kit = " ".join(user_query.lower().split())

    # Build a stable cache key for a document and the active KIT.
    def stable_key(doc: Dict[str, Any]) -> str:
        payload = {
            "version": _SEMANTIC_CACHE_VERSION,
            "prompt_version": PROMPT_VERSION,
            "kit": kit,
            "catalog_context": catalog_context,
            "source_id": doc.get("source_id") or "",
            "source_type": doc.get("source_type") or "",
            "url": (doc.get("url") or "").strip(),
            "title": doc.get("title") or "",
            "text": doc.get("text") or "",
            "published_at": doc.get("published_at") or "",
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

    semantic_map, cache_keys, missing = {}, {}, []

    try:
        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS semantic_filter_cache (cache_key TEXT PRIMARY KEY, decision_json TEXT NOT NULL)"
            )
            for doc in candidates:
                doc_id = str(doc["doc_id"]).upper()
                key = stable_key(doc)
                cache_keys[doc_id] = key

                row = conn.execute("SELECT decision_json FROM semantic_filter_cache WHERE cache_key = ?", (key,)).fetchone()
                if row:
                    try:
                        decision = json.loads(row[0])
                        if isinstance(decision, dict) and type(decision.get("is_relevant")) is bool:
                            decision["doc_id"] = doc_id
                            semantic_map[doc_id] = decision
                            continue
                    except (ValueError, TypeError):
                        pass
                missing.append(doc)
    except sqlite3.Error as exc:
        logger.warning("[FILTER CACHE] Unavailable: %s; using live filter", exc)
        missing = list(candidates)
        cache_keys = {str(d["doc_id"]).upper(): stable_key(d) for d in candidates}

    if missing:
        ordered = sorted(
            missing,
            key=lambda d: (str(d.get("url") or ""), str(d.get("title") or ""), str(d.get("doc_id") or "")),
        )
        new_decisions = _run_batch_semantic_llm_filter(ordered, user_query)
        semantic_map.update(new_decisions)

        try:
            with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
                for doc_id, decision in new_decisions.items():
                    if doc_id not in cache_keys or type(decision.get("is_relevant")) is not bool:
                        continue
                    payload = {k: v for k, v in decision.items() if k != "doc_id"}
                    conn.execute(
                        "INSERT OR REPLACE INTO semantic_filter_cache (cache_key, decision_json) VALUES (?, ?)",
                        (cache_keys[doc_id], json.dumps(payload, ensure_ascii=False)),
                    )
        except sqlite3.Error as exc:
            logger.warning("[FILTER CACHE] Could not save decisions: %s", exc)

    logger.info(
        "[FILTER CACHE] cached=%d fresh=%d total=%d",
        len(candidates) - len(missing),
        len(missing),
        len(candidates)
    )
    return semantic_map


# Persist accept/reject decisions for later false-negative and recall review.
# Keep both accepted and excluded classifications available for reproducible review.
def _save_filter_audit_records(audit_records: List[Dict[str, Any]], run_id: str, run_workspace: str) -> None:
    # Save audit records to the run workspace and available persistence backend.
    if not audit_records:
        return
    if run_workspace and os.path.isdir(run_workspace):
        try:
            with open(os.path.join(run_workspace, "semantic_filter_audit.json"), "w", encoding="utf-8") as f:
                json.dump(audit_records, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"[SEMANTIC FILTER] Could not write workspace audit JSON: {e}")

    if not run_id:
        return
    with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
        conn.executemany(
            """
            INSERT OR REPLACE INTO document_filter_log (
                run_id, doc_id, source_id, url, title, filter_stage,
                is_accepted, signal_type, entities_models_tech, matched_kiq_id,
                decision_rationale, evaluated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id, rec["doc_id"], rec.get("source_id", ""), rec.get("url", ""), rec.get("title", ""),
                    rec["filter_stage"], 1 if rec["is_accepted"] else 0, rec["signal_type"],
                    rec.get("entities_models_tech", ""), rec.get("matched_kiq_id", ""),
                    rec["decision_rationale"], rec["evaluated_at"],
                )
                for rec in audit_records
            ],
        )
        conn.commit()


# Apply two-stage relevance gates and arrange surviving source records into Analyst batches.
# All exclusion paths feed the filter audit so that rejected candidates remain reviewable.
# Store the reason behind every exclusion decision, including unavailable source content.
def prioritize_and_batch_documents(
    docs: List[Dict[str, Any]],
    user_query: str,
    max_chars_per_batch: int = 24000,
    run_id: str = "",
    run_workspace: str = "",
    filter_diagnostics: Dict[str, Any] | None = None,
) -> Tuple[List[str], int, int]:
    # Prepare counters, audit records, and bounded text budgets for this filtering run.
    """Apply deterministic and semantic filters, then batch retained documents."""
    if filter_diagnostics is not None:
        filter_diagnostics.clear()
        filter_diagnostics.update({
            "semantic_filter_missing_ids": [],
            "semantic_filter_unavailable_count": 0,
        })

    if not docs:
        return [], 0, 0

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    query_families = _detect_aircraft_families(user_query)
    q_words = [w.lower() for w in re.findall(r"\b\w{3,}\b", user_query)]

    seen_urls: set[str] = set()
    seen_fingerprints: set[str] = set()
    stage1_survivors: List[Dict[str, Any]] = []
    audit_records: List[Dict[str, Any]] = []
    rejected_count = 0

    # Record this source’s decision without losing its provenance.
    def _record_audit(
        d: Dict[str, Any], stage: str, accepted: bool, sig_type: str,
        rationale: str, entities: str = "", kiq: str = "", **extra: Any,
    ) -> None:
        audit_records.append({
            "doc_id": d.get("doc_id", "DOC_UNK"),
            "source_id": d.get("source_id", ""),
            "url": (d.get("url") or "").strip() if stage.startswith("STAGE_1") else d.get("url", ""),
            "title": (d.get("title") or "").strip() if stage.startswith("STAGE_1") else d.get("title", ""),
            "filter_stage": stage,
            "is_accepted": accepted,
            "signal_type": sig_type,
            "entities_models_tech": entities,
            "matched_kiq_id": kiq,
            "decision_rationale": rationale,
            "evaluated_at": now_iso,
            "content_status": d.get("content_status", "TEXT_COMPLETENESS_UNVERIFIED"),
            "content_limit_reason": d.get("content_limit_reason", ""),
            **extra,
        })


    # Stage 1: exclude structurally unusable, duplicated, stale, or clearly mismatched source records.
    for d in docs:
        url = (d.get("url") or "").strip()
        fp = (d.get("syndication_fingerprint") or "").strip()
        title = (d.get("title") or "").strip()
        text = (d.get("text") or "").strip()
        pub_date = d.get("published_at") or "DATE_UNKNOWN"
        combined_text = f"{title} {text}"

        if len(combined_text) < 45 or (d.get("prompt_injection_flagged") and len(text) < 80):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "EMPTY_OR_INJECTION",
                "Rejected in Stage 1: Document text is empty, too short, or flagged for prompt injection.",
            )
            continue

        if d.get("content_status") == "METADATA_ONLY" or d.get("document_type") in {
            "SEC_FILING_METADATA_ONLY", "ESEF_FILING_METADATA_ONLY",
            "STATISTICAL_METADATA_UPDATE",
        }:
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_CONTENT_QUALITY", False, "SOURCE_METADATA_ONLY",
                "Metadata establish record identity/publication only; substantive KIT claims require source text.",
                content_status="METADATA_ONLY", retained_as_context=True,
            )
            continue

        if (url and url in seen_urls) or (fp and fp in seen_fingerprints):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "DUPLICATE",
                "Rejected in Stage 1: Duplicate URL or identical syndication fingerprint.",
            )
            continue

        if not is_date_within_scope(pub_date):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "OUT_OF_SCOPE",
                f"Rejected in Stage 1: Publication date ({pub_date}) is outside the active time window.",
            )
            continue

        if OBVIOUS_NOISE_REGEX.search(combined_text):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "GENERAL_NOISE",
                "Rejected in Stage 1: Hobbyist scale model or flight simulator content.",
            )
            continue

        doc_families = _detect_aircraft_families(combined_text)
        if query_families and doc_families and not query_families.intersection(doc_families):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_DETERMINISTIC", False, "MODEL_MISMATCH",
                f"Rejected in Stage 1: Document concerns aircraft family {sorted(doc_families)} "
                f"which does not match queried family {sorted(query_families)}.",
                entities=", ".join(sorted(doc_families)),
            )
            continue

        title_key, text_key = _alnum_norm(title), _alnum_norm(text)
        if title_key and (not text_key or text_key == title_key):
            rejected_count += 1
            _record_audit(
                d, "STAGE_1_CONTENT_QUALITY", False, "SOURCE_METADATA_ONLY",
                "Title-only source record; no source-backed event can be verified.",
            )
            if url:
                seen_urls.add(url)
            if fp:
                seen_fingerprints.add(fp)
            continue

        if url:
            seen_urls.add(url)
        if fp:
            seen_fingerprints.add(fp)
        stage1_survivors.append(d)


    # Stage 2: classify surviving documents against the full KIT using cached or fresh model decisions.
    logger.info(
        f"[SEMANTIC FILTER FR03] Stage 1 passed {len(stage1_survivors)}/{len(docs)} docs "
        f"(rejected {rejected_count}). Running Stage 2 batch LLM semantic check..."
    )
    # The second stage classifies the survivors; cache reuse does not bypass the deterministic stage.
    semantic_map = _cached_semantic_filter(stage1_survivors, user_query)
    missing_semantic_ids = [d["doc_id"] for d in stage1_survivors if d["doc_id"] not in semantic_map]

    if filter_diagnostics is not None:
        filter_diagnostics["semantic_filter_missing_ids"] = missing_semantic_ids
        filter_diagnostics["semantic_filter_unavailable_count"] = len(missing_semantic_ids)

    kit_terms = {
        word for word in re.findall(r"\b[a-z0-9]{5,}\b", user_query.lower())
        if word not in {"aircraft", "aviation", "aerospace", "industry", "commercial"}
    }

    # General factual match to an official regulatory notice. This admits
    # issue-specific evidence without claiming aircraft installation or impact.
    def verified_direct_faa(d: Dict[str, Any]) -> bool:
        return assess_official_faa_fact(user_query, d) is not None

    accepted_docs: List[Dict[str, Any]] = []
    valid_kiq_ids = {item["kiq_id"] for item in get_active_kiq_catalog()}

    for d in stage1_survivors:
        doc_id = d["doc_id"]
        sem = semantic_map.get(doc_id)
        is_faa_direct = verified_direct_faa(d)

        if sem is not None:
            is_rel = sem["is_relevant"]
            sig_type = str(sem.get("signal_type") or ("RELEVANT_EVENT" if is_rel else "GENERAL_NOISE")).upper()
            entities_tech = str(sem.get("entities_models_tech") or d.get("supplier_registry_match") or "")
            matched_kiq = str(sem.get("matched_kiq_id") or "")
            if matched_kiq not in valid_kiq_ids:
                matched_kiq = ""
            rationale = str(sem.get("rationale") or "Evaluated by batch semantic LLM filter.")

            if is_faa_direct:
                is_rel = True
                sig_type = "REGULATORY_PRIMARY_ISSUE"
                rationale = "Verified FAA issue-level match; program applicability and impacts remain subject to Harness validation."
                logger.info("[FILTER FAA OVERRIDE] Accepted %s", doc_id)

            context_reason = kit_direct_relevance_gap(
                user_query, f"{d.get('title') or ''} {d.get('text') or ''}"
            )
            if not context_reason and not is_faa_direct:
                context_reason = _kit_context_reason(user_query, d)
            # Apply technical-context guards so matching brand names do not imply the requested defect.
            if context_reason:
                is_rel = False
                sig_type = "RELATED_CONTEXT"
                rationale = context_reason
                d["semantic_signal_type"] = sig_type
                d["semantic_rationale"] = rationale
                logger.info("[KIT CONTEXT] %s moved to RELATED_CONTEXT", doc_id)

            title_norm, body_norm = _alnum_norm(d.get("title")), _alnum_norm(d.get("text"))
            if (not body_norm or body_norm == title_norm) and not is_faa_direct:
                is_rel = False
                sig_type = "SOURCE_METADATA_ONLY"
                rationale = (
                    "Source contains only a headline or insufficient article content. "
                    "No concrete KIT event can be established from this evidence."
                )
                logger.info("[FILTER CONTENT GATE] %s: title-only source rejected", doc_id)

            # Keep an audited rejection record even when the source shares generic KIT vocabulary.
            if not is_rel or sig_type == "GENERAL_NOISE":
                doc_text = f"{d.get('title', '')} {d.get('text', '')}".lower()
                matched_terms = sorted(term for term in kit_terms if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", doc_text))
                # Generic brand overlap alone is not a potential false negative.
                # Escalate only substantive, issue-specific documents without a known identity conflict.
                manual_review = (
                    len(matched_terms) >= 2
                    and len(str(d.get("text") or "").strip()) >= 250
                    and not context_reason
                    and (
                        not _detect_engine_models(user_query)
                        or _engine_models_match(user_query, doc_text)
                    )
                    and bool(re.search(
                        r"\b(?:defect\w*|failur\w*|shortag\w*|inspect\w*|"
                        r"ground\w*|disrupt\w*|delay\w*|recall\w*)\b", doc_text,
                    ))
                )

                # Record rejected decisions, including potential false-negative review flags.
                kit_variants = _detect_exact_variants(user_query)
                doc_variants = _detect_exact_variants(doc_text)

                if (
                    kit_variants
                    and doc_variants
                    and not kit_variants.intersection(doc_variants)
                ):
                    manual_review = False

                if manual_review:
                    logger.warning(
                        "[FILTER REVIEW] Potential false negative: %s | KIT matches: %s",
                        doc_id, matched_terms,
                    )

                rejected_count += 1
                _record_audit(
                    d, "STAGE_2_SEMANTIC", False, sig_type,
                    f"Excluded from direct analysis: {rationale}" if context_reason else f"Rejected in Stage 2 (LLM): {rationale}",
                    entities=entities_tech, kiq=matched_kiq,
                    manual_review_candidate=manual_review, matched_kit_terms=matched_terms,
                )
                continue

            d["semantic_signal_type"] = sig_type
            d["semantic_entities"] = entities_tech
            d["semantic_kiq_id"] = matched_kiq
            d["semantic_rationale"] = rationale
            _record_audit(
                d, "STAGE_2_SEMANTIC", True, sig_type,
                f"Accepted in Stage 2 (LLM): {rationale}",
                entities=entities_tech, kiq=matched_kiq,
            )
            accepted_docs.append(d)
        else:
            context_reason = kit_direct_relevance_gap(
                user_query, f"{d.get('title') or ''} {d.get('text') or ''}"
            ) or _kit_context_reason(user_query, d)
            if context_reason:
                d["semantic_signal_type"] = "RELATED_CONTEXT"
                d["semantic_rationale"] = context_reason
                rejected_count += 1
                # Keep semantically related context out of direct-event analysis while retaining its
                #   rationale.
                _record_audit(d, "STAGE_2_CONTEXT_FALLBACK", False, "RELATED_CONTEXT", context_reason)
                continue

            direct_primary = is_faa_direct or _official_easa_interim_direct_match(d, user_query)
            d["semantic_signal_type"] = "REGULATORY_PRIMARY_FALLBACK" if direct_primary else "FILTER_UNAVAILABLE"
            d["semantic_entities"] = d.get("supplier_registry_match") or ""
            d["semantic_kiq_id"] = ""
            d["semantic_rationale"] = (
                "Deterministic direct match to official regulatory metadata; technical claims still require Harness validation."
                if direct_primary else
                "Semantic LLM classification missing or invalid. Direct KIT relevance was not established. Manual review required."
            )
            _record_audit(
                d, "STAGE_2_DETERMINISTIC_FALLBACK", direct_primary,
                d["semantic_signal_type"], d["semantic_rationale"],
                entities=d["semantic_entities"], manual_review_candidate=not direct_primary,
            )
            if direct_primary:
                accepted_docs.append(d)
            else:
                rejected_count += 1

    # Invariant: every Analyst input must have one corresponding accepted audit decision.
    accepted_ids = [str(doc["doc_id"]).upper() for doc in accepted_docs]
    audited_accepted_ids = [
        str(rec["doc_id"]).upper() for rec in audit_records if rec["is_accepted"]
    ]
    if len(set(accepted_ids)) != len(accepted_ids) or set(accepted_ids) != set(audited_accepted_ids):
        raise RuntimeError(
            f"FR03_AUDIT_INTEGRITY: Analyst inputs {accepted_ids!r} "
            f"do not equal accepted audit records {audited_accepted_ids!r}"
        )
    if filter_diagnostics is not None:
        filter_diagnostics["accepted_document_ids"] = sorted(accepted_ids)
        filter_diagnostics["accepted_document_count"] = len(accepted_docs)
        filter_diagnostics["rejection_review_candidates"] = sum(
            bool(rec.get("manual_review_candidate")) and not rec["is_accepted"]
            for rec in audit_records
        )
        filter_diagnostics["rejection_stage_counts"] = {
            stage: sum(not rec["is_accepted"] and rec["filter_stage"] == stage for rec in audit_records)
            for stage in sorted({rec["filter_stage"] for rec in audit_records})
        }

    # Retain accepted and rejected decisions for later independent relevance review.
    _save_filter_audit_records(audit_records, run_id, run_workspace)
    if run_id:
        with DB_LOCK, sqlite3.connect(SQLITE_DB) as conn:
            stored = {
                row[0].upper() for row in conn.execute(
                    "SELECT doc_id FROM document_filter_log WHERE run_id=? AND is_accepted=1", (run_id,)
                ).fetchall()
            }
        if stored != set(accepted_ids):
            raise RuntimeError(
                f"FR03_PERSISTENCE_INTEGRITY: accepted={set(accepted_ids)!r} stored={stored!r}"
            )
    unavailable = sum(rec.get("signal_type") == "FILTER_UNAVAILABLE" for rec in audit_records)
    logger.info(
        "[SEMANTIC FILTER COMPLETE] Accepted %d documents, excluded %d documents "
        "(%d FILTER_UNAVAILABLE; their irrelevance is NOT established).",
        len(accepted_docs), rejected_count, unavailable,
    )

    # Compute the priority score used to order accepted source documents.
    def doc_priority_score(d: Dict[str, Any]) -> int:
        score = _SOURCE_TYPE_SCORES.get(d.get("source_type", ""), 20)
        if d.get("semantic_signal_type") == "RELEVANT_EVENT":
            score += 30
        hay = f"{d.get('title', '')} {d.get('text', '')}".lower()
        score += sum(10 for w in q_words if w in hay)
        if d.get("supplier_registry_match"):
            score += 15
        return score

    sorted_docs = sorted(
        accepted_docs,
        key=lambda d: (-doc_priority_score(d), str(d.get("url") or ""), str(d.get("title") or "")),
    )

    batches: List[str] = []
    current_batch_lines: List[str] = []
    current_len = 0
    analyzed_count = 0

    for d in sorted_docs:
        block = (
            f"<untrusted_osint_document id=\"{d['doc_id']}\" source_id=\"{d['source_id']}\" "
            f"origin=\"{d.get('origin_type', 'SECONDARY')}\">\n"
            f"DOC_ID: {d['doc_id']} | SOURCE_ID: {d['source_id']} ({d.get('connector_name', '')})\n"
            f"DATE: {d.get('published_at', 'DATE_UNKNOWN')} | COLLECTED_AT: {d.get('collected_at', '')}\n"
            f"CONTENT_STATUS: {d.get('content_status', 'SUMMARY_ONLY')} | "
            f"CONTENT_SHA256: {d.get('content_sha256', '')}\n"
            f"SEMANTIC_CLASSIFICATION: {d.get('semantic_signal_type', 'RELEVANT_EVENT')} | "
            f"KIQ: {d.get('semantic_kiq_id', 'KIQ_1_1')} | ENTITIES/MODELS: {d.get('semantic_entities') or 'N/A'}\n"
            f"SEMANTIC_RATIONALE: {d.get('semantic_rationale', '')}\n"
            f"TITLE: {d.get('title', '')}\n"
            f"SOURCE: {d.get('url', '')}\n"
            f"CONTENT: {relevant_excerpt(d.get('text', ''), user_query)}\n"
            f"</untrusted_osint_document>\n"
        )
        if current_len + len(block) > max_chars_per_batch and current_batch_lines:
            batches.append("\n".join(current_batch_lines))
            current_batch_lines = [block]
            current_len = len(block)
        else:
            current_batch_lines.append(block)
            current_len += len(block)
        analyzed_count += 1

    if current_batch_lines:
        batches.append("\n".join(current_batch_lines))

    return batches, analyzed_count, rejected_count
