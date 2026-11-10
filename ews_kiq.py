# =============================================================================
# aviation_ci_app | Strategic KIT/KIQ mapping and runtime evidence coverage
#
# Responsibility: Map concrete intelligence findings to catalog questions and account for answered,
#   unresolved, or weakly evidenced KIQs.
# Design boundary: Issue-specific source evidence is required; generic aircraft or company overlap is
#   insufficient.
# =============================================================================


"""KIT/KIQ catalog mapping, evidence traceability, and question coverage."""

from collections import Counter
from typing import Optional

from ews_database import get_active_kiq_catalog
from ews_evidence_contract import assess_official_faa_fact
from ews_state import (
    Any, ConfidenceLevel, Dict, EWSReport, KIQAnswer, KIQPlan,
    List, RiskType, ThreatAssessment, ValidationStatus, re,
)
from tools import news_api_search_key

# Term extraction and conservative strategic-KIQ matching vocabulary.
_WORD_RE = re.compile(r"[a-z0-9]{4,}")
_QUERY_STOPWORDS = {"airbus", "boeing", "aviation", "aircraft", "aerospace", "industry"}
_DISTINCTIVE_TERMS = {
    "orders", "order", "contract", "contracts", "partnership", "shortage",
    "shortages", "production", "technology", "emissions", "regulation",
    "certification", "innovation", "materials",
}

_GENERIC_REG_TERMS = {
    "airbus", "boeing", "engine", "engines", "aircraft", "aviation", "faa", "easa",
    "directive", "directives", "airworthiness", "inspection", "inspections",
    "regulatory", "production", "supplier", "constraints", "airline", "impacts",
    "fleet", "requirements", "compliance",
}

_KIQ_ISSUE_GROUPS = (
    r"\b(?:engine\w*|gtf|pw1100g?|turbine\w*)\b",
    r"\b(?:airworthiness|directive\w*|inspect\w*|regulator\w*)\b",
    r"\b(?:certif\w*|approv\w*)\b",
    r"\b(?:order\w*|purchas\w*|contract\w*|leas\w*)\b",
    r"\b(?:shortag\w*|outage\w*|constraint\w*|production\s+delay\w*)\b",
    r"\b(?:accident\w*|crash\w*|runway\w*|incident\w*)\b",
)

_HISTORICAL_AGE_WARNING_RE = re.compile(
    r"Verification required: Source published \d+ days before reference date; "
    r"historical source alone does not prove a new event or current disruption; "
    r"Classified as HISTORICAL_CONTEXT \(older event referenced in recent source\)\.?",
    re.I,
)


# Compile strict word-boundary matching for strategic KIQ topic vocabulary.
def _compile_terms(*terms: str) -> re.Pattern:
    joined = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"(?<![a-z0-9])(?:{joined})(?![a-z0-9])")


# Explicit KIQ issue patterns and required risk-domain combinations.
_KIQ_MATCH_RULES = [
    (
        "KIQ_1_1",
        {RiskType.SUPPLY_CHAIN, RiskType.TECHNICAL_QUALITY},
        _compile_terms(
            "production delay", "production delays", "delivery delay", "delivery delays",
            "delivery postponement", "manufacturing disruption", "factory shutdown",
            "production halt", "assembly disruption", "supplier production",
        ),
    ),
    (
        "KIQ_1_2",
        {RiskType.SUPPLY_CHAIN, RiskType.TECHNICAL_QUALITY},
        _compile_terms(
            "component shortage", "engine shortage", "material shortage", "raw material",
            "titanium shortage", "forging shortage", "supplier insolvency", "supplier strike",
            "industrial strike", "supply shortage", "critical components",
        ),
    ),
    (
        "KIQ_2_1",
        {RiskType.COMPETITIVE, RiskType.ENVIRONMENTAL_TECHNOLOGICAL},
        _compile_terms(
            "strategic partnership", "strategic alliance", "product launch",
            "new aircraft", "new technology", "innovation partnership", "joint venture",
        ),
    ),
    (
        "KIQ_2_2",
        {RiskType.COMPETITIVE},
        _compile_terms(
            "aircraft order", "fleet order", "firm order", "order cancellation",
            "purchase agreement", "fleet contract", "aircraft contract", "orderbook",
            "orders totaling",
        ),
    ),
    (
        "KIQ_3_1",
        {RiskType.REGULATORY, RiskType.TECHNICAL_QUALITY, RiskType.ENVIRONMENTAL_TECHNOLOGICAL},
        _compile_terms(
            "sustainable aviation fuel", "saf certification", "saf technology",
            "emissions standard", "emissions regulation", "technology certification",
            "hydrogen propulsion", "electric propulsion", "alternative propulsion",
            "technology regulation", "environmental regulation",
        ),
    ),
]


# Normalize a KIT/KIQ question for conservative lexical comparison.
def _norm_q(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower()).strip()


# Select only catalog context that materially matches the current KIT.
def build_catalog_prompt_context(user_query: str) -> str:
    # Include catalog instructions only when they apply to the user’s explicit KIT.
    """Present catalog context only where it matches the user's actual KIT."""
    query_words = set(_WORD_RE.findall(user_query.lower())) - _QUERY_STOPWORDS
    lines = []
    for item in get_active_kiq_catalog():
        item_text = f"{item['question']} {' '.join(item['indicators'])}".lower()
        core_overlap = query_words & set(_WORD_RE.findall(item_text))
        if len(core_overlap) >= 2 or bool(core_overlap & _DISTINCTIVE_TERMS):
            lines.append(f"- [{item['kiq_id']}] {item['question']} | Indicators: {'; '.join(item['indicators'])}")

    return "\n".join(lines) if lines else (
        "No direct match in the strategic KIQ catalog. Preserve the user-defined "
        "ad-hoc KIT without assigning an unrelated catalog identifier."
    )


# Associate a validated event with specific strategic KIQ topic rules.
def match_kiqs_for_threat(threat: ThreatAssessment, catalog: List[Dict[str, Any]]) -> List[str]:
    """Conservative mapping to the thesis-aligned 5-KIQ strategic catalog."""
    evidence = f"{threat.threat_description or ''} {threat.confirmed_facts or ''} {threat.fact_check_quote or ''}".lower()
    allowed = {item["kiq_id"] for item in catalog}
    return [
        kiq_id
        for kiq_id, risk_types, pattern in _KIQ_MATCH_RULES
        if kiq_id in allowed and threat.risk_type in risk_types and pattern.search(evidence)
    ]


# Require evidence of the KIQ issue, not mere mention of the aircraft.
def _kiq_evidence_matches_topic(query: str, threat: ThreatAssessment) -> bool:
    """Require evidence of the specific issue, not generic aircraft overlap."""
    evidence = f"{threat.fact_check_quote or ''} {threat.confirmed_facts or ''}"

    from ews_validation import (
        _detect_engine_models,
        _engine_models_match,
    )

    if (
        _detect_engine_models(query)
        and not _engine_models_match(query, evidence)
    ):
        return False

    ad_numbers = re.findall(r"\b20\d{2}-\d{4}(?:-[A-Z])?\b", query, re.I)
    if ad_numbers and not all(re.search(rf"\b{re.escape(num)}\b", evidence, re.I) for num in ad_numbers):
        return False

    requested = [pat for pat in _KIQ_ISSUE_GROUPS if re.search(pat, query, re.I)]
    return not requested or any(re.search(pat, evidence, re.I) for pat in requested)


# Check whether an official FAA source materially answers a regulatory KIQ.
def _is_matching_official_faa_doc(doc: Optional[Dict[str, Any]], specific_terms: set[str]) -> bool:
    if not doc or not specific_terms or doc.get("source_id") != "SRC_001":
        return False
    url = str(doc.get("url") or "")
    text = str(doc.get("text") or "")
    if (
        not url.startswith("https://www.federalregister.gov/documents/")
        or "Regulatory Lifecycle Check: VERIFIED" not in text
        or not re.search(r"(?m)^FAA Docket: FAA-\d{4}-\d+\s*$", text)
    ):
        return False
    combined_low = f"{doc.get('title') or ''} {text}".lower()
    return any(re.search(rf"\b{re.escape(tok)}\b", combined_low) for tok in specific_terms)


# Separate effective regulatory action from proposed or unresolved notices.
def _is_effective_faa_threat(t: ThreatAssessment) -> bool:
    summary = t.corroboration_summary or {}
    return (
        summary.get("FAA Lifecycle Verified") == "YES"
        and summary.get("Regulatory Stage") == "EFFECTIVE"
    )

# Assess official FAA certification evidence for an individual KIQ.
def _official_faa_certification_for_kiq(
    query: str,
    docs: List[Dict[str, Any]],
):
    if not re.search(
        r"\bcertif\w*\b",
        query,
        re.I,
    ):
        return None

    if re.search(
        r"\b(?:passenger service|commercial service|"
        r"in service|delivery schedule|production impact)\b",
        query,
        re.I,
    ):
        return None

    from urllib.parse import urlparse
    from ews_validation import (
        _detect_exact_variants,
        _is_snippet_only,
    )

    variants = _detect_exact_variants(query)

    if not variants:
        return None

    for doc in docs:
        host = (
            urlparse(
                str(doc.get("url") or "")
            ).hostname or ""
        ).lower()

        if (
            host != "faa.gov"
            and not host.endswith(".faa.gov")
        ):
            continue

        if doc.get("source_id") not in {
            "SRC_001",
            "SRC_004",
        }:
            continue

        if (
            _is_snippet_only(doc)
            or "RSS_METADATA_ONLY" in str(
                doc.get("origin_type") or ""
            )
        ):
            continue

        title = str(doc.get("title") or "")

        if not (
            variants & _detect_exact_variants(title)
        ):
            continue

        if not re.search(
            r"\b(?:FAA|Federal Aviation Administration)\b",
            title,
            re.I,
        ):
            continue

        if not re.search(
            r"\b(?:certif(?:ies|ied)|"
            r"certification\s+(?:issued|granted|completed)|"
            r"issues?\s+(?:type\s+)?certification)\b",
            title,
            re.I,
        ):
            continue

        if re.search(
            r"\b(?:expects?|awaits?|propos\w*|"
            r"pending|imminent|plans?|seeks?|"
            r"denied|revoked|suspended)\b",
            title,
            re.I,
        ):
            continue

        if not re.fullmatch(
            r"20\d{2}-\d{2}-\d{2}",
            str(doc.get("published_at") or ""),
        ):
            continue

        return doc

    return None

# Trace planned questions to documents and retained events with explicit unanswered states.
# No direct source support must remain visible as an intelligence gap.
# A related event alone does not establish that a planned KIQ has been answered.
# Evidence IDs provide traceability from each response to its source records.
def build_runtime_kiq_answers(
    report: EWSReport,
    kiq_plan: KIQPlan,
    collected_docs: List[Dict[str, Any]],
    selected_platforms: List[str] | None = None,
) -> List[KIQAnswer]:
    # Build evidence-backed answers for each planned question, retaining unanswered gaps.
    """Trace runtime KIQs to collected source documents and assessed intelligence events."""
    groups = [
        (
            "MEDIA",
            kiq_plan.media_and_pr_queries,
            {"SRC_004", "SRC_005"},
            {"news", "news api", "pr", "official pr releases"}
        ),
        (
            "REG",
            kiq_plan.regulatory_and_ntsb_queries,
            {"SRC_001", "SRC_002", "SRC_003", "SRC_019", "SRC_020", "SRC_021", "SRC_022", "SRC_023", "SRC_026"},
            {"regulatory", "faa", "easa", "faa & easa regulations", "ntsb", "ntsb investigations"}
        ),
        (
            "SOCIAL",
            kiq_plan.social_and_video_queries,
            {"SRC_007", "SRC_008"},
            {"bluesky", "bluesky social network", "youtube", "youtube videos"}
        ),
        ("AIRSHOW", [kiq_plan.airshow_query], {"SRC_006"}, {"airshow", "airshow websites"}),
    ]

    doc_index = [
        (
            doc.get("source_id"),
            _norm_q(doc.get("query_used", "")),
            doc["doc_id"],
            news_api_search_key(doc.get("query_used", "")) if doc.get("source_id") == "SRC_004" else "",
        )
        for doc in collected_docs
        if doc.get("doc_id")
    ]
    documents_by_id = {doc["doc_id"]: doc for doc in collected_docs if doc.get("doc_id")}
    all_report_threats = list(report.threats) + list(report.related_program_watchlist or [])
    enabled_names = {str(v).strip().lower() for v in (selected_platforms or [])}

    catalog_answers = [a for a in report.kiq_answers if not a.kiq_id.startswith("RKIQ_")]
    runtime_answers = []

    for group_name, queries, allowed_sources, platform_keys in groups:
        group_enabled = selected_platforms is None or bool(enabled_names & platform_keys)

        for index, query in enumerate(queries, start=1):
            kiq_id = f"RKIQ_{group_name}_{index:02d}"
            query_norm = _norm_q(query)
            query_news_key = news_api_search_key(query)

            sources_for_query = set(allowed_sources)

            if group_name == "REG":
                requested = {
                    name
                    for name in ("faa", "easa", "ntsb")
                    if re.search(
                        rf"\b{name}\b",
                        query,
                        re.I,
                    )
                }

                regulator_sources = {
                    "faa": {"SRC_001"},
                    "easa": {
                        "SRC_002",
                        "SRC_019",
                        "SRC_020",
                        "SRC_021",
                        "SRC_022",
                        "SRC_023",
                    },
                    "ntsb": {"SRC_003", "SRC_026"},
                }

                if requested:
                    sources_for_query &= set().union(
                        *(
                            regulator_sources[name]
                            for name in requested
                        )
                    )

            document_ids = {
                doc_id
                for src_id, q_norm, doc_id, news_key in doc_index
                if group_enabled
                and src_id in sources_for_query
                and (q_norm == query_norm or (src_id == "SRC_004" and news_key == query_news_key))
            }

            # Documents are reusable across KIQs when their independently verified
            # factual claim answers this question. Search-query provenance is
            # preserved, but a second KIQ need not retrieve the same URL again.
            regulatory_facts = []
            if group_enabled and group_name == "REG":
                for doc in collected_docs:
                    if doc.get("source_id") not in sources_for_query:
                        continue
                    fact = assess_official_faa_fact(query, doc)
                    if fact and fact["document_id"]:
                        regulatory_facts.append(fact)
                        document_ids.add(fact["document_id"])

            related_threats = [
                t for t in all_report_threats
                if document_ids.intersection(t.evidence_ids) and _kiq_evidence_matches_topic(query, t)
            ]
            for threat in related_threats:
                if kiq_id not in threat.kiq_ids:
                    threat.kiq_ids.append(kiq_id)

            supported = [
                t for t in related_threats
                if t.validation_status == ValidationStatus.SUPPORTED
                and t.technical_grounding_status == "PASS"
                and t.program_relevance == "DIRECT_KIT_MATCH"
            ]
            supported_document_ids = {
                eid for t in supported for eid in t.evidence_ids if eid in document_ids
            }

            partially_supported = [
                t for t in related_threats
                if t.validation_status == ValidationStatus.PARTIALLY_SUPPORTED
                and t.program_relevance == "DIRECT_KIT_MATCH"
                and t.technical_grounding_status == "PASS"
                and t.claim_support_status in {"STATED_IN_SOURCE", "PARTIALLY_STATED_IN_SOURCE"}
            ]

            specific_terms = {tok for tok in _WORD_RE.findall(query.lower()) if tok not in _GENERIC_REG_TERMS}
            official_regulatory_docs = (
                [
                    documents_by_id[did]
                    for did in sorted(document_ids)
                    if _is_matching_official_faa_doc(documents_by_id.get(did), specific_terms)
                ]
                if group_name == "REG" else []
            )

            related_supported = [
                t for t in related_threats
                if t.validation_status == ValidationStatus.SUPPORTED
                and t.technical_grounding_status == "PASS"
                and t.program_relevance != "DIRECT_KIT_MATCH"
            ]

            contextual_ids = (
                {d["doc_id"] for d in official_regulatory_docs}
                | {eid for t in related_supported for eid in t.evidence_ids if eid in document_ids}
            )
            official_confirmation = (
                _official_faa_certification_for_kiq(
                    query,
                    collected_docs,
                )
                if group_enabled and group_name == "REG"
                else None
            )

            official_confirmation_ids = (
                {official_confirmation["doc_id"]}
                if official_confirmation
                else set()
            )

            # Media coverage can partially address a KIQ without certifying the claim.
            preliminary_media_docs = []
            if (
                group_name == "MEDIA"
                and group_enabled
                and not (supported or partially_supported or related_supported)
            ):
                from ews_validation import _detect_exact_variants, _is_snippet_only

                required_variants = _detect_exact_variants(query)
                issue_patterns = [
                    pattern for pattern in _KIQ_ISSUE_GROUPS
                    if re.search(pattern, query, re.I)
                ]
                for doc_id in sorted(document_ids):
                    doc = documents_by_id.get(doc_id)
                    if not doc or doc.get("source_id") not in {"SRC_004", "SRC_005"}:
                        continue
                    if _is_snippet_only(doc):
                        continue
                    source_text = f"{doc.get('title') or ''} {doc.get('text') or ''}"
                    if len(source_text.strip()) < 120:
                        continue
                    if required_variants and not (
                        required_variants & _detect_exact_variants(source_text)
                    ):
                        continue
                    if issue_patterns and not all(
                        re.search(pattern, source_text, re.I)
                        for pattern in issue_patterns
                    ):
                        continue
                    preliminary_media_docs.append(doc)
                preliminary_media_docs = preliminary_media_docs[:2]

            preliminary_media_ids = {
                doc["doc_id"] for doc in preliminary_media_docs
            }

            if official_confirmation_ids:
                document_ids.update(official_confirmation_ids)
            retrieved_document_count = len(document_ids)

            validated_document_count = len(
                supported_document_ids
                | contextual_ids
                | official_confirmation_ids
                | {fact["document_id"] for fact in regulatory_facts}
            )

            if supported or any(fact["complete"] for fact in regulatory_facts):
                evidence_coverage = "SUPPORTED"
            elif partially_supported or official_regulatory_docs or related_supported or regulatory_facts:
                evidence_coverage = "PARTIAL"
            elif related_threats:
                evidence_coverage = "UNVERIFIED"
            else:
                evidence_coverage = "NONE"

            freshness_values = {getattr(t.event_freshness, "value", t.event_freshness) for t in related_threats}
            # Associate accepted evidence with the exact KIQ topic and source trace.
            if freshness_values == {"HISTORICAL_CONTEXT"}:
                temporal_relevance = "HISTORICAL_ONLY"
            elif freshness_values & {"NEW_EVENT", "NEW_DEVELOPMENT", "ONGOING_ISSUE"}:
                temporal_relevance = "CURRENT_OR_ONGOING"
            else:
                temporal_relevance = "UNKNOWN"

            if any(t.risk_type == RiskType.REGULATORY and _is_effective_faa_threat(t) for t in supported):
                temporal_relevance = "CURRENT_OR_ONGOING"

            if not group_enabled:
                answer_status = "NOT_SEARCHED"
                answer_text = "This source group was not enabled for the current run."
                uncertainty = ConfidenceLevel.HIGH

            elif regulatory_facts:
                # A verified FAA lifecycle statement can answer a narrow factual
                # question even when the Analyst finds no reportable threat.
                # Scope and downstream impacts remain independent uncertainties.
                regulatory_facts.sort(key=lambda f: (not f["complete"], f["document_id"]))
                fact = regulatory_facts[0]
                fully_answered = bool(
                    fact["complete"] and (
                        fact["stage"] != "PROPOSED"
                        or bool(re.search(r"\bpropos\w*\b", query, re.I))
                    )
                )
                answer_status = "ANSWERED" if fully_answered else "PARTIALLY_ANSWERED"
                evidence_coverage = "SUPPORTED" if fully_answered else "PARTIAL"
                temporal_relevance = "CURRENT_OR_ONGOING" if fact["stage"] == "EFFECTIVE" else "UNKNOWN"
                answer_text = fact["answer"]
                uncertainty = ConfidenceLevel.LOW if fully_answered else ConfidenceLevel.HIGH

            elif official_confirmation:
                answer_status = "ANSWERED"

                evidence_coverage = "SUPPORTED"

                temporal_relevance = "CURRENT_OR_ONGOING"

                answer_text = (
                    "The FAA has publicly confirmed the "
                    "certification milestone for the "
                    "requested aircraft variant. "
                    f"Official statement: "
                    f"{official_confirmation['title']} "
                    f"(published "
                    f"{official_confirmation['published_at']}; "
                    f"source {official_confirmation['url']}). "
                    "This confirms certification, "
                    "NOT aircraft deliveries or "
                    "commercial passenger service."
                )

                uncertainty = ConfidenceLevel.LOW

            elif supported:
                regulatory_status_question = (
                    group_name == "REG"
                    and "airworthiness directive" in query.lower()
                    and not re.search(
                        r"\b(?:impact|production|delivery|grounding|operational|disruption|consequence)\b",
                        query, re.I,
                    )
                )

                # Avoid repeating a historical-age warning when the marker is already present.
                def _only_historical_age_warning(t: ThreatAssessment) -> bool:
                    return bool(
                        regulatory_status_question
                        and t.risk_type == RiskType.REGULATORY
                        and _is_effective_faa_threat(t)
                        and (t.corroboration_summary or {}).get("FAA Effective Date")
                        and _HISTORICAL_AGE_WARNING_RE.fullmatch(str(t.missing_data or "").strip())
                    )

                verified_for_answer = [
                    t for t in supported
                    if (
                        t.confidence_level == ConfidenceLevel.HIGH
                        and (not t.missing_data or _only_historical_age_warning(t))
                    ) or (
                        regulatory_status_question
                        and _is_effective_faa_threat(t)
                        and t.technical_grounding_status == "PASS"
                        and t.claim_support_status == "STATED_IN_SOURCE"
                    )
                ]

                fully_verified = bool(verified_for_answer)
                answer_status = "ANSWERED" if fully_verified else "PARTIALLY_ANSWERED"
                target_list = (verified_for_answer if fully_verified else supported)[:3]

                answer_parts = []
                for t in target_list:
                    eff_date = (t.corroboration_summary or {}).get("FAA Effective Date")
                    eff_suffix = f" FAA regulation effective {eff_date}." if (_is_effective_faa_threat(t) and eff_date) else ""
                    answer_parts.append(f"{t.company_affected} ({t.affected_program}): {t.confirmed_facts}{eff_suffix}")

                answer_text = " ".join(answer_parts)
                uncertainty = ConfidenceLevel.LOW if fully_verified else ConfidenceLevel.MEDIUM

            elif partially_supported:
                answer_status = "PARTIALLY_ANSWERED"
                preview = " | ".join(
                    f"{t.company_affected}: {(t.fact_check_quote or t.threat_description or '')[:180]} "
                    f"[PARTIALLY_SUPPORTED, {t.event_id}]"
                    for t in partially_supported[:2]
                )
                answer_text = f"Preliminary evidence (not a verified answer): {preview}"
                uncertainty = ConfidenceLevel.HIGH

            elif official_regulatory_docs or related_supported:
                answer_status = "PARTIALLY_ANSWERED"
                verified_observations = []

                for doc in official_regulatory_docs[:2]:
                    source_text = str(doc.get("text") or "")
                    docket = re.search(r"(?m)^FAA Docket:\s*(FAA-\d{4}-\d+)", source_text)
                    stage = re.search(r"(?m)^Regulatory Stage:\s*([A-Z_]+)", source_text)
                    model_ids = list(dict.fromkeys(
                        re.findall(
                            r"\b(?:"
                            r"PW\d{4}[A-Z0-9-]*"
                            r"|LEAP[\s-]*1[ABC][0-9A-Z]*"
                            r"|GE9X"
                            r"|GE90(?:-[0-9A-Z]+)?"
                            r"|Trent[\s-]*(?:1000|7000|900|XWB)"
                            r")\b",
                            source_text,
                            re.I,
                        )
                    ))[:5]
                    models = ", ".join(model_ids) if model_ids else "NOT SPECIFIED"

                    verified_observations.append(
                        f"RELATED OFFICIAL REGULATORY CONTEXT [{doc['doc_id']}]: "
                        f"{doc.get('title') or 'Untitled'}; "
                        f"publication {doc.get('published_at') or 'DATE_UNKNOWN'}; "
                        f"docket {docket.group(1) if docket else 'UNKNOWN'}; "
                        f"stage {stage.group(1) if stage else 'UNKNOWN'}; "
                        f"models named in record: {models}. "
                        "The official notice's existence and stated lifecycle were checked. "
                        "Its applicability to the exact KIT configuration, effective requirements, "
                        "and fleet effects have NOT been established. "
                        f"Source URL: {doc.get('url') or 'NOT AVAILABLE'}."
                    )

                for t in related_supported[:2]:
                    verified_observations.append(
                        f"Related-program context {t.event_id}: {t.company_affected} / {t.affected_program}; "
                        f"source quotation: {(t.fact_check_quote or '')[:180]}. "
                        "Direct relevance to the requested KIT is not established."
                    )

                answer_text = " ".join(verified_observations)
                uncertainty = ConfidenceLevel.HIGH

            elif preliminary_media_docs:
                answer_status = "PARTIALLY_ANSWERED"
                evidence_coverage = "UNVERIFIED"
                answer_text = "Preliminary media coverage, not a confirmed event: " + " | ".join(
                    f"[{doc['doc_id']}] {doc.get('title') or 'Untitled'}; "
                    f"published {doc.get('published_at') or 'DATE_UNKNOWN'}; "
                    f"source {doc.get('url') or 'NOT AVAILABLE'}"
                    for doc in preliminary_media_docs
                ) + ". The reported claims and regulatory status still require independent primary-source verification."
                uncertainty = ConfidenceLevel.HIGH

            else:
                answer_status = "UNANSWERED"
                if related_threats:
                    status_counts = Counter(t.validation_status.value for t in related_threats)
                    unique_docs = sorted({eid for t in related_threats for eid in t.evidence_ids})
                    breakdown = ", ".join(f"{st}={cnt}" for st, cnt in sorted(status_counts.items()))
                    answer_text = (
                        f"{len(related_threats)} candidate signal(s) linked to {len(unique_docs)} unique document(s); "
                        f"evidence status: {breakdown}. Evidence IDs: {', '.join(unique_docs[:5]) or 'NONE'}. "
                        "No claim is sufficiently verified to answer this KIQ. "
                        "Seek independent primary-source corroboration."
                    )
                else:
                    answer_text = (
                        "No sufficiently verified KIT-specific evidence was linked to this KIQ. "
                        "This does not establish absence of the risk."
                    )
                uncertainty = ConfidenceLevel.HIGH

            if group_enabled:
                direct_count = len(supported_document_ids)
                contextual_count = len(
                    (contextual_ids | official_confirmation_ids)
                    - supported_document_ids
                )
                # Preserve unknown verification states instead of inventing an answer.
                coverage_note = (
                    f"Retrieved documents: {retrieved_document_count}. "
                    f"Direct-KIT supported source documents: {direct_count}. "
                    f"Additional verified contextual source documents: {contextual_count}. "
                )
                if retrieved_document_count > 0 and validated_document_count == 0 and answer_status == "UNANSWERED":
                    coverage_note += (
                        "Documents were collected, but no sufficiently supported analytical conclusion was established. "
                    )
                answer_text = coverage_note + answer_text

            next_step_map = {
                "MEDIA": "Seek a primary OEM/operator statement confirming the exact KIT entity, program and claimed impact.",
                "REG": (
                    "Check dated manufacturer and supplier statements for documented production "
                    "constraints, affected components, delivery schedules and direct KIT impact."
                    if re.search(
                        r"\b(?:supplier|production|deliver\w*|capacity|shortag\w*|constraint\w*)\b",
                        query,
                        re.I
                    )
                    else (
                        "Cross-check the exact model or variant and regulatory lifecycle in FAA/EASA "
                        "primary records. A proposed AD must not be treated as an effective obligation."
                    )
                ),
                "SOCIAL": "Verify the social/video claim against a traceable independent primary source and its original publication date.",
                "AIRSHOW": "Search official organizer/manufacturer releases for a specific dated announcement and its KIT applicability.",
            }

            runtime_answers.append(
                KIQAnswer(
                    kiq_id=kiq_id,
                    question=f"What evidence addresses: {query}?",
                    answer_status=answer_status,
                    evidence_coverage=evidence_coverage,
                    temporal_relevance=temporal_relevance,
                    answer=answer_text,
                    related_event_ids=list(dict.fromkeys(t.event_id for t in related_threats)),
                    evidence_ids=list(
                        dict.fromkeys(
                            [
                                eid
                                for t in related_threats
                                for eid in t.evidence_ids
                                if eid in document_ids
                            ]
                            + sorted(
                                contextual_ids
                                | official_confirmation_ids
                                | preliminary_media_ids
                                | {fact["document_id"] for fact in regulatory_facts}
                            )
                        )
                    ),
                    retrieved_evidence_count=retrieved_document_count,
                    validated_evidence_count=validated_document_count,
                    retrieved_document_ids=sorted(document_ids),
                    verification_status=(
                        "Evidence-backed answer"
                        if answer_status == "ANSWERED"
                        else (
                            (
                                "Preliminary media evidence; claims and impact unverified"
                                if preliminary_media_docs and not (
                                    supported or partially_supported or official_regulatory_docs or related_supported
                                )
                                else "Verified limited context; KIT relevance unresolved"
                            )
                            if answer_status == "PARTIALLY_ANSWERED"
                            else "Further verification required"
                        )
                    ),
                    uncertainty_level=uncertainty,
                    recommended_next_step=(
                        "No immediate follow-up required; monitor for new developments."
                        if answer_status == "ANSWERED"
                        else next_step_map[group_name]
                    ),
                    missing_information=(
                        None
                        if answer_status == "ANSWERED"
                        else (
                            "Evidence for the exact KIT configuration or downstream impact remains missing."
                            if answer_status == "PARTIALLY_ANSWERED"
                            else "No sufficiently verified KIT-specific claim was found in the collected evidence."
                        )
                    ),
                )
            )

    return catalog_answers + runtime_answers


# Aggregate the verification states of runtime KIQ answers.
# Status counts are used to report unanswered intelligence requirements transparently.
def runtime_kiq_status_counts(answers: List[KIQAnswer]) -> Dict[str, int]:
    """Count runtime KIQ answers by verification status."""
    statuses = [a.answer_status for a in answers if str(a.kiq_id).startswith("RKIQ_")]
    return {
        "runtime_kiq_answered": statuses.count("ANSWERED"),
        "runtime_kiq_partially_answered": statuses.count("PARTIALLY_ANSWERED"),
        "runtime_kiq_unanswered": statuses.count("UNANSWERED"),
        "runtime_kiq_not_searched": statuses.count("NOT_SEARCHED"),
    }
