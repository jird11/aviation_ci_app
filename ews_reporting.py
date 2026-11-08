# =============================================================================
# aviation_ci_app | Evidence-aware executive reporting and action governance
#
# Responsibility: Build decision-ready summaries, reconcile action/event references, and sanitize audit
#   information displayed on the dashboard.
# Design boundary: Unsupported claims are never promoted to confirmed critical alerts by reporting or
#   editorial formatting.
# =============================================================================


"""Evidence-aware report synthesis, action alignment, and scoring presentation."""

from collections import Counter
from datetime import date, timedelta

from ews_state import (
    ActionItem, Any, ConfidenceLevel, Dict, EWSReport, List,
    ThreatAssessment, ThreatReport, TripleAPillar, ValidationStatus, logger, re,
)
from ews_validation import _source_age_days, is_confirmed_critical, is_unverified_signal

# Management-action guards and false-certainty detection patterns.
_DISRUPTIVE_ACTION_RE = re.compile(
    r"\b(?:diversify\s+supply|supplier\s+diversification|replace\s+supplier|"
    r"halt\s+operations|cancel\s+orders|terminate\s+contract|"
    r"(?:build|increase)\s+buffer|adjust\s+inventory|inventory\s+buffers?|"
    r"change\s+supplier|switch\s+supplier|6-month\s+strategic\s+buffer|"
    r"(?:secure|reserve|expand|increase|add|boost)\s+(?:additional\s+)?"
    r"(?:mro|maintenance|inspection|production)\s+(?:capacity|slots?)|"
    r"(?:sign|execute|finali[sz]e|enter\s+into)\s+(?:(?:a|new|binding)\s+)?"
    r"(?:contracts?|agreements?|partnerships?)|"
    r"(?:contract|partner)\s+with\s+(?:a\s+)?(?:new\s+)?supplier)\b",
    re.I,
)
_PROS_CONS_SPLIT_RE = re.compile(
    r"\b(?:Owner|Deadline|KPI|Related_event_ids|Related_threat_companies|Triple_a_impact)\s*:",
    re.I,
)
_FALSE_CERTAINTY_RE = re.compile(r"\b(?:high[- ]confidence|critical|confirmed)\b", re.I)
_KPI_HIGH_CONF_RE = re.compile(r"\bconfidence(?:\s+levels?)?\b.{0,40}\bHIGH\b", re.I | re.S)
_DEFAULT_MITIGATION = "No validated mitigation recommendation available."


# Remove excluded events and unlink stale management actions.
# The dashboard must never refer to evidence records removed by QA or HITL review.
def synchronize_report_consistency(report_dict: Dict[str, Any], removed_ids: List[str]) -> Dict[str, Any]:
    """Remove rejected events and orphaned actions, then refresh report projections."""
    if not removed_ids:
        return report_dict

    removed_set = set(removed_ids)
    remaining_threats = [t for t in report_dict.get("threats", []) if t.get("event_id") not in removed_set]
    report_dict["threats"] = remaining_threats
    valid_ids = {t.get("event_id") for t in remaining_threats}

    updated_actions = []
    for act in report_dict.get("action_plan", []):
        rel_ids = [eid for eid in act.get("related_event_ids", []) if eid in valid_ids]
        if rel_ids:
            act["related_event_ids"] = rel_ids
            updated_actions.append(act)

    report_dict["action_plan"] = updated_actions if remaining_threats else []
    report_dict["version"] = int(report_dict.get("version", 1)) + 1
    return refresh_threat_reports_dict(report_dict)


# Construct an evidence-qualified executive briefing from validated events.
# Never convert tentative or unverified source claims into confirmed operational findings.
def build_final_executive_summary(report: EWSReport, user_query: str) -> str:
    # Build the executive summary from the retained event evidence and verification states.
    """Evidence-grounded executive intelligence briefing."""
    threats = list(report.threats or [])
    watchlist = list(report.related_program_watchlist or [])
    runtime_kiqs = [a for a in (report.kiq_answers or []) if str(a.kiq_id).startswith("RKIQ_")]

    direct = [t for t in threats if t.program_relevance == "DIRECT_KIT_MATCH"]
    confirmed = [t for t in direct if t.validation_status == ValidationStatus.SUPPORTED]
    partial_direct = [t for t in direct if t.validation_status == ValidationStatus.PARTIALLY_SUPPORTED]
    indirect_supported = [
        t for t in threats
        if t.validation_status == ValidationStatus.SUPPORTED and t.program_relevance != "DIRECT_KIT_MATCH"
    ]
    unverified = [t for t in threats if is_unverified_signal(t)]

    sections = []
    kit = " ".join(str(user_query or "Not specified").split()).rstrip(".")

    sections.append((
        "MONITORING OBJECTIVE AND OVERALL ASSESSMENT",
        f"Monitoring concerned the KIT: {kit}. "
        f"The run retained {len(threats)} candidate signals and {len(watchlist)} related-program "
        f"{'observation' if len(watchlist) == 1 else 'observations'}. "
        f"Direct-KIT candidates: {len(direct)}; source-supported: {len(confirmed)}; "
        f"partially supported: {len(partial_direct)}. "
        "Source support, program relevance and potential severity are assessed separately.",
    ))

    if confirmed:
        t = max(confirmed, key=lambda event: event.threat_score)

        priority = (
            f"The strongest source-supported direct finding is {t.event_id} "
            f"({t.company_affected}; {t.affected_program}). "
            f"Potential severity is {t.threat_score}/10 with "
            f"{t.confidence_level.value.lower()} evidence confidence. "
            "See the event record for exact claims and citations."
        )

        # Include source-documented facts only after technical grounding has passed.
        if t.confirmed_facts and t.technical_grounding_status == "PASS":
            facts = " ".join(t.confirmed_facts.split())[:240].rstrip(" .;")
            priority += f" Source-documented facts: {facts}."

    elif partial_direct:
        t = max(partial_direct, key=lambda event: event.threat_score)
        priority = (
            "No fully supported direct warning was established. "
            f"Candidate {t.event_id} ({t.company_affected}) is partially supported; "
            "unverified details and consequences require further evidence."
        )
    else:
        priority = (
            "No adequately supported direct warning was established from the retrieved material. "
            "This does not demonstrate that the monitored risk is absent."
        )
    sections.append(("PRIORITY INTELLIGENCE FINDINGS", priority))

    if indirect_supported:
        mentions = "; ".join(
            f"{t.event_id} ({t.company_affected}, {t.publication_time or 'date unknown'})"
            for t in indirect_supported[:2]
        )
        sections.append((
            "VERIFIED SOURCES WITH UNCONFIRMED KIT RELEVANCE",
            f"Source-supported observations outside confirmed direct KIT scope: {mentions}. "
            "Their documentary facts must not be presented as proven effects on the monitored program.",
        ))

    if watchlist:
        related_names = "; ".join(
            f"{t.company_affected} / {t.affected_program} ({t.event_id})"
            for t in watchlist[:2]
        )
        sections.append((
            "RELATED-PROGRAM MONITORING",
            f"The related-program watchlist contains {related_names}. "
            "Shared-supplier impact remains hypothetical unless independently documented.",
        ))

    # Separate supported findings from tentative monitoring context in executive presentation.
    risk_counts = Counter(t.risk_type.value for t in threats)
    categories = ", ".join(f"{risk} ({count})" for risk, count in sorted(risk_counts.items())) or "none"
    sections.append((
        "RISK AND SUPPLY-CHAIN INTERPRETATION",
        f"Candidate categories: {categories}. "
        "Impact scores estimate possible consequences; they do not prove that a disruption occurred. "
        "Proposed or pending regulatory notices are not automatically effective obligations.",
    ))

    if unverified:
        cases = ", ".join(t.event_id for t in unverified[:3])
        gap_message = (
            f"Unverified claims requiring source-level follow-up include {cases}. "
            "Their quoted statements, causal interpretation and program applicability must be checked before escalation."
        )
    else:
        gap_message = (
            "The retrieved evidence does not establish complete source coverage or exclude undetected developments."
        )
    sections.append(("EVIDENCE LIMITATIONS AND INTELLIGENCE GAPS", gap_message))

    metadata = report.run_metadata or {}
    collected = int(metadata.get("documents_collected") or 0)
    analyzed = int(metadata.get("documents_analyzed") or 0)
    failed = int(metadata.get("documents_failed") or 0)
    rejected = int(metadata.get("documents_rejected") or 0)
    coverage_issues = metadata.get("source_coverage_issues") or []

    coverage_note = (
        "The run records limitations in external source coverage. "
        "These limitations reduce the completeness of the resulting assessment."
        if coverage_issues
        else "No additional source-coverage limitation was recorded, although undetected developments remain possible."
    )
    sections.append((
        "SOURCE COVERAGE AND FILTERING",
        f"The collection stage registered {collected} source records. Of these, {analyzed + failed} passed "
        f"relevance screening; {analyzed} were analyzed, {failed} could not be analyzed, "
        f"and {rejected} were excluded by filtering. "
        "The dataset combines source metadata with available article and regulatory text, "
        f"which can vary considerably in depth. {coverage_note}",
    ))

    sections.append((
        "EVIDENCE ASSURANCE AND RELEVANCE",
        "The assessment distinguishes documentary facts from inferred consequences through "
        "quotation traceability, technical compatibility, causal support, independent "
        "source verification and event freshness. A supported regulatory fact may concern "
        "a different aircraft or engine model. Likewise, a related supplier announcement "
        "or an information-rich headline does not independently establish fleet groundings, "
        "production constraints or causal effects for the monitored KIT. These distinctions "
        "are retained in the detailed event records and intelligence requirements.",
    ))

    counts = Counter(a.answer_status for a in runtime_kiqs)
    kiq_message = (
        f"Of {len(runtime_kiqs)} runtime KIQs, {counts['ANSWERED']} were answered, "
        f"{counts['PARTIALLY_ANSWERED']} partially answered, "
        f"{counts['UNANSWERED']} unanswered and {counts['NOT_SEARCHED']} not searched."
    )
    if partly := [a.kiq_id for a in runtime_kiqs if a.answer_status == "PARTIALLY_ANSWERED"]:
        kiq_message += (
            f" Limited, source-linked context is available for {', '.join(partly[:3])}; "
            "it is not equivalent to an established direct KIT impact."
        )
    kiq_message += (
        " The KIQ register retains evidence IDs, explicit uncertainty and the next verification "
        "step for each unresolved question."
    )
    sections.append(("INTELLIGENCE REQUIREMENTS COVERAGE", kiq_message))

    actions = list(report.action_plan or [])
    if actions:
        act = actions[0]
        action_text = (
            f"First proposed step: {str(act.action).strip().rstrip('.')}. "
            f"Owner: {act.owner}; target: {act.deadline}. "
            "Other assigned tasks and KPIs remain in the action plan."
        )
    else:
        action_text = "Continue proportional monitoring; no validated event-specific operational action was retained."
    sections.append(("RECOMMENDED MANAGEMENT RESPONSE", action_text))

    sections.append((
        "DECISION BOUNDARIES",
        "Unsupported signals require verification, not immediate intervention. "
        "Safety-critical, regulatory and supply-chain decisions require independent evidence "
        "and authorized human review.",
    ))

    mandatory = {
        "MONITORING OBJECTIVE AND OVERALL ASSESSMENT",
        "PRIORITY INTELLIGENCE FINDINGS",
        "INTELLIGENCE REQUIREMENTS COVERAGE",
        "RECOMMENDED MANAGEMENT RESPONSE",
        "DECISION BOUNDARIES",
    }

    while sum(len(f"{h} {b}".split()) for h, b in sections) > 450:
        optional = next((i for i, (h, _) in enumerate(sections) if h not in mandatory), None)
        if optional is None:
            break
        sections.pop(optional)

    return "\n\n".join(f"{heading}\n{body}" for heading, body in sections)


# Normalize action ownership, deadlines, and references to surviving events.
# Actions without adequate evidence must not imply authorization for disruptive steps.
def _finalize_aligned_actions(report, aligned_actions, threat_map, event_count):
    # Finalize action deadlines, affected events, and duplicate proposals.
    """FAA validation, deadline normalization and action deduplication."""
    try:
        reference_date = date.fromisoformat(str((report.run_metadata or {}).get("analysis_reference_date", ""))[:10])
    except ValueError:
        reference_date = date.today()

    unique_actions = {}

    for act in aligned_actions:
        linked = [threat_map[eid] for eid in act.related_event_ids if eid in threat_map]

        faa_supported = bool(linked) and all(
            t.validation_status == ValidationStatus.SUPPORTED
            and t.program_relevance == "DIRECT_KIT_MATCH"
            and (t.corroboration_summary or {}).get("FAA Lifecycle Verified") == "YES"
            and any("federalregister.gov/documents/" in u for u in t.source_urls)
            for t in linked
        )

        if faa_supported:
            # Preserve the Editor action and rationale rather than replacing them with a stock FAA action.
            # Add a regulator-stage caveat; a verified docket is not proof of an effective obligation.
            caveat = (
                "FAA record verified; confirm regulatory stage, exact applicability, "
                "compliance deadlines and operational effects in the complete docket."
            )

            current = (act.uncertainty_assumptions or "").strip()

            if caveat not in current:
                act.uncertainty_assumptions = f"{current} {caveat}".strip()

            if max(t.threat_score for t in linked) < 8:
                act.priority = "MEDIUM"

        original_deadline = (act.deadline or "").strip()
        if relative := re.fullmatch(r"(?:within\s+|in\s+)?(\d{1,3})\s+days?", original_deadline, re.I):
            act.deadline = (reference_date + timedelta(days=int(relative.group(1)))).isoformat()
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", original_deadline):
            try:
                if date.fromisoformat(original_deadline) < reference_date:
                    act.deadline = "Pending analyst scheduling"
            except ValueError:
                act.deadline = "Pending analyst scheduling"
        elif re.search(r"\b(?:from|after|following|upon)\b", original_deadline, re.I):
            act.deadline = "Pending analyst scheduling"

        if act.deadline == "Pending analyst scheduling":
            act.uncertainty_assumptions = (
                f"{act.uncertainty_assumptions or ''} Original deadline: {original_deadline}. "
                "Analyst must assign a valid future date."
            )

        faa_for_dedup = bool(linked) and all(
            (t.corroboration_summary or {}).get("FAA Lifecycle Verified") == "YES" for t in linked
        )
        key = (
            act.action.strip().casefold(),
            () if faa_for_dedup else tuple(sorted(act.related_event_ids)),
        )

        if key in unique_actions:
            existing = unique_actions[key]
            existing.related_event_ids = list(dict.fromkeys(existing.related_event_ids + act.related_event_ids))
            existing.related_threat_companies = list(
                dict.fromkeys(existing.related_threat_companies + act.related_threat_companies)
            )
            logger.info("[ACTION DEDUP] Merged duplicate action %s", act.action_id)
        else:
            unique_actions[key] = act

    report.action_plan = list(unique_actions.values())[: (3 if event_count <= 2 else 5)]
    return report


# Constrain recommended interventions according to observed evidence and severity.
# Proposed disruptive interventions must be proportionate to confidence and verification status.
# An action cannot become safer solely because an Editor gave it a high priority.
def _align_and_sanitize_action_plan(report: EWSReport) -> EWSReport:
    # Check each recommended action against linked event evidence and escalation constraints.
    """Align management actions with retained events and constrain unsupported escalation."""
    all_events = list(report.threats) + list(report.related_program_watchlist or [])
    if not all_events:
        report.action_plan = []
        return report

    threat_map = {t.event_id: t for t in all_events}
    aligned_actions: List[ActionItem] = []
    unverified_statuses = {
        ValidationStatus.UNVERIFIED_COMMUNITY,
        ValidationStatus.UNSUPPORTED,
        ValidationStatus.PARTIALLY_SUPPORTED,
    }

    for act in report.action_plan:
        valid_eids = list(dict.fromkeys(eid for eid in (act.related_event_ids or []) if eid in threat_map))
        if not valid_eids:
            logger.warning("[ACTION ALIGN] Dropping action %s: no valid event_id linkage", act.action_id)
            continue

        act.related_event_ids = valid_eids
        linked_threats = [threat_map[eid] for eid in valid_eids]
        act.related_threat_companies = list(dict.fromkeys(t.company_affected for t in linked_threats))

        if (
            not any(t.program_relevance == "DIRECT_KIT_MATCH" for t in linked_threats)
            and any(t.program_relevance == "PROGRAM_UNVERIFIED" for t in linked_threats)
        ):
            exemplar = linked_threats[0]
            act.action = (
                f"Verify direct applicability of event {exemplar.event_id} to the monitored KIT "
                "using aircraft and engine variant evidence."
            )
            act.rationale = (
                "The publication may be genuine, but a direct relationship to the target "
                "program and engine is not established."
            )
            act.priority = "MEDIUM"
            act.kpi = (
                "Traceable primary-source verification of engine and aircraft variant relevance, "
                "or a documented non-match."
            )
            act.uncertainty_assumptions = (
                "Do not infer direct program applicability, maintenance duty or fleet impact from "
                "a manufacturer name alone."
            )
            act.pros_and_cons = "PRO: Avoids off-topic operations; CON: Requires evidence review."

        if all(is_unverified_signal(t) for t in linked_threats):
            steps = (
                "Check official OEM/regulatory records",
                "Seek independent source corroboration",
                "Monitor authoritative sources for new evidence",
            )
            step = steps[len(aligned_actions) % 3]
            act.action = f"{step} regarding {linked_threats[0].company_affected} ({linked_threats[0].affected_program})."
            act.priority = "MEDIUM"
            act.kpi = "Record verification status, source URLs and exact citations."
            act.uncertainty_assumptions = "Incident existence, causes and operational impacts remain unverified."
            act.pros_and_cons = "PRO: Reduces false-positive escalation; CON: Additional verification time."

        act.pros_and_cons = _PROS_CONS_SPLIT_RE.split(act.pros_and_cons or "", maxsplit=1)[0].rstrip(" ;,.")

        if len(linked_threats) == 1 and linked_threats[0].technical_grounding_status == "FAIL":
            st = linked_threats[0]
            act.action = (
                f"Verify the reported {st.risk_type.value.lower()} development involving "
                f"{st.company_affected} ({st.affected_program}) against an official source "
                "before assessing operational or strategic consequences."
            )
            act.kpi = (
                f"Record a source-backed verification decision for {st.event_id}, "
                "including a traceable URL and exact quotation."
            )
            act.uncertainty_assumptions = "The source claim and its consequences remain unconfirmed."

        all_unverified = all(
            lt.confidence_level == ConfidenceLevel.LOW or lt.validation_status in unverified_statuses
            for lt in linked_threats
        )
        weak_evidence = any(
            t.validation_status != ValidationStatus.SUPPORTED or t.confidence_level != ConfidenceLevel.HIGH
            for t in linked_threats
        )

        if weak_evidence and _DISRUPTIVE_ACTION_RE.search(act.action or ""):
            original_action = act.action
            primary_lt = linked_threats[0]
            act.action = (
                f"Verify source evidence and actual operational need for "
                f"{primary_lt.company_affected} ({primary_lt.affected_program}) "
                "before proposing contracts, MRO capacity expansion or other binding procurement decisions."
            )
            act.rationale = (
                "Operational intervention is not justified solely by current "
                "partially supported, unsupported or LOW-confidence evidence."
            )
            act.priority = "MEDIUM"
            act.kpi = (
                "Document primary-source corroboration, actual capacity need "
                "and human go/no-go decision before commitment."
            )
            act.pros_and_cons = "PRO: Avoids premature spending; CON: Requires additional verification before intervention."
            act.uncertainty_assumptions = (
                f"Proposed but not authorized: {original_action[:300]}. "
                "Actual capacity and supplier constraints remain unverified."
            )
            # Replace disruptive actions that are not justified by validated findings.
            logger.warning("[ACTION EVIDENCE GATE] Replaced unsupported intervention in %s", act.action_id)

        evidence_not_fully_confirmed = any(
            t.validation_status != ValidationStatus.SUPPORTED or t.confidence_level == ConfidenceLevel.LOW
            for t in linked_threats
        )
        false_certainty_claim = bool(
            _FALSE_CERTAINTY_RE.search(act.rationale or "")
            and not any(is_confirmed_critical(t) for t in linked_threats)
        )

        if all_unverified or (evidence_not_fully_confirmed and false_certainty_claim):
            evidence_details = "; ".join(
                f"{t.event_id}: {t.validation_status.value}, confidence {t.confidence_level.value}"
                for t in linked_threats
            )
            act.rationale = (
                "Proposed action is based on a monitored intelligence signal requiring proportional "
                f"verification or further monitoring. Evidence status: {evidence_details}. "
                "No unverified causal relationship is treated as an established fact."
            )
            if all_unverified:
                act.priority = "MEDIUM"

        if all_unverified and _KPI_HIGH_CONF_RE.search(act.kpi or ""):
            act.kpi = (
                "Dashboard displays the actual validated confidence level and evidence status for "
                f"events {', '.join(act.related_event_ids)}. "
                "No LOW-confidence event is labeled HIGH or presented as verified."
            )

        if any(t.causal_support_status != "EVIDENCED_IN_VERIFIED_SOURCE" for t in linked_threats) and _DISRUPTIVE_ACTION_RE.search(act.action or ""):
            t = linked_threats[0]
            act.action = (
                f"Verify the proposed supplier dependency involving {t.company_affected} "
                "before any operational or procurement intervention."
            )
            act.rationale = "The specific causal or supplier relationship has not been established by validated evidence."
            act.priority = "MEDIUM"
            act.kpi = "Verified supplier relationship supported by traceable evidence."

        if any(t.program_relevance != "DIRECT_KIT_MATCH" for t in linked_threats):
            primary = linked_threats[0]
            if primary.program_relevance == "RELATED_PROGRAM_WATCHLIST":
                check = "Test whether any evidenced cross-program dependency exists"
            elif primary.technical_grounding_status == "FAIL":
                check = "Retrieve and verify an exact source quotation"
            elif primary.risk_type.value == "REGULATORY":
                check = "Check the official regulatory lifecycle and applicability"
            else:
                check = "Identify the affected entity and validate KIT relevance"

            act.action = f"{check} for {primary.event_id} before considering operational intervention."
            act.rationale = "The available evidence does not establish direct applicability to the monitored KIT."
            act.priority = "MEDIUM"
            act.kpi = "Document verified KIT relevance using traceable source evidence."
            act.uncertainty_assumptions = "Direct operational, regulatory or supply-chain impact remains unconfirmed."

        if any(
            existing.action.strip().casefold() == act.action.strip().casefold()
            and set(existing.related_event_ids) == set(act.related_event_ids)
            for existing in aligned_actions
        ):
            # Suppress duplicate management tasks while preserving evidence-linked coverage.
            logger.info("[ACTION DEDUP] Skipping duplicate action %s", act.action_id)
            continue

        aligned_actions.append(act)

    if not aligned_actions and all_events:
        top_t = max(all_events, key=lambda x: x.threat_score)
        is_direct_verified = (
            top_t.program_relevance == "DIRECT_KIT_MATCH"
            and top_t.confidence_level == ConfidenceLevel.HIGH
            and top_t.validation_status == ValidationStatus.SUPPORTED
        )
        if is_direct_verified:
            aligned_actions.append(
                ActionItem(
                    related_event_ids=[top_t.event_id],
                    related_threat_companies=[top_t.company_affected],
                    action=(
                        "Conduct targeted supply chain exposure audit and MRO slot review for "
                        f"{top_t.company_affected} ({top_t.affected_program} - {top_t.affected_component})."
                    ),
                    rationale=f"Directly mitigates confirmed {top_t.risk_type.value} signal ({top_t.event_id}).",
                    pros_and_cons="PRO: Early mitigation of confirmed delivery/operational bottleneck; CON: Requires dedicated engineering and procurement review.",
                    triple_a_impact=TripleAPillar.AGILITY,
                    owner="VP Supply Chain & Fleet Operations",
                    deadline="Within 14 days",
                    kpi=f"100% impact assessment completed for {top_t.affected_program} schedule exposure.",
                    priority="HIGH" if top_t.threat_score >= 8 else "MEDIUM",
                )
            )
        else:
            aligned_actions.append(
                ActionItem(
                    related_event_ids=[top_t.event_id],
                    related_threat_companies=[top_t.company_affected],
                    action=(
                        f"Verify unconfirmed signal on {top_t.company_affected} ({top_t.affected_program}) "
                        "against official FAA/EASA dockets and OEM disclosures before operational escalation."
                    ),
                    rationale=f"Signal {top_t.event_id} is currently {top_t.validation_status.value} (Confidence: {top_t.confidence_level.value}).",
                    pros_and_cons="PRO: Prevents false-positive executive panic and unnecessary capex; CON: Brief delay if rumor turns out to be an early crisis.",
                    triple_a_impact=TripleAPillar.ALIGNMENT,
                    owner="Lead OSINT & Aviation Safety Analyst",
                    deadline="Within 7 days",
                    kpi=f"Primary source corroboration status resolved for {top_t.event_id}.",
                    priority="MEDIUM",
                )
            )

    return _finalize_aligned_actions(report, aligned_actions, threat_map, len(all_events))


# Rebuild dashboard-facing event projections after review modifications.
# Rebuild projections without promoting unsupported events into confirmed findings.
def refresh_threat_reports_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    # Rebuild projections after event removal or HITL decisions.
    """Keep presentation projections consistent after HITL/feedback edits."""
    action_map: Dict[str, str] = {}
    for action in data.get("action_plan", []):
        for event_id in action.get("related_event_ids", []):
            action_map.setdefault(event_id, action.get("action", ""))

    projections = []
    for row in data.get("threats", []):
        try:
            event = ThreatAssessment.model_validate(row)
            is_unknown_meta = (
                "NEWSAPI_METADATA_ONLY" in (event.verification_status or "")
                or (
                    event.company_affected.strip().lower() == "unknown"
                    and event.affected_program.lower().startswith("unknown")
                )
            )

            if event.program_relevance == "RELATED_PROGRAM_WATCHLIST":
                row["presentation_category"] = "RELATED_PROGRAM"
            elif event.program_relevance == "DIRECT_KIT_MATCH" and event.validation_status == ValidationStatus.SUPPORTED:
                row["presentation_category"] = "CONFIRMED_INTELLIGENCE"
            elif (
                (event.program_relevance == "PROGRAM_UNVERIFIED" and is_unknown_meta)
                or event.validation_status in {ValidationStatus.UNSUPPORTED, ValidationStatus.CONTRADICTED}
            ):
                row["presentation_category"] = "INSUFFICIENT_EVIDENCE"
            else:
                row["presentation_category"] = "VERIFICATION_REQUIRED"

            projection = ThreatReport.from_assessment(
                event,
                mitigation_advice=action_map.get(event.event_id, _DEFAULT_MITIGATION),
            ).model_dump(mode="json")
            projection["presentation_category"] = row["presentation_category"]
            projections.append(projection)
        except Exception as err:
            logger.warning("[THREAT REPORT] Projection unavailable for one event: %s", err)

    data["threat_reports"] = projections
    return data


# Project evidence assessments into the simplified presentation schema.
def build_threat_reports(report: EWSReport) -> List[ThreatReport]:
    action_map: Dict[str, str] = {}
    for action in report.action_plan:
        for eid in action.related_event_ids:
            action_map.setdefault(eid, action.action)

    return [
        ThreatReport.from_assessment(
            threat,
            mitigation_advice=action_map.get(threat.event_id, _DEFAULT_MITIGATION),
        )
        for threat in report.threats
    ]


# Prevent provisional scoring rationales from implying validated certainty.
# The displayed scoring audit must reflect final post-validation limits.
# Make the final displayed scoring explanation consistent with post-validation severity limits.
def sanitize_scoring_audit(
    scoring_audit: List[Dict[str, Any]],
    threats: List[ThreatAssessment],
    as_of_date: str = "",
) -> List[Dict[str, Any]]:
    # Align scoring commentary to post-Harness severity caps.
    """Expose only post-Harness evidence-aligned scoring commentary to the dashboard."""
    by_id = {t.event_id: t for t in threats}

    for row in scoring_audit:
        threat = by_id.get(row.get("event_id"))
        if threat is None:
            logger.warning("[SCORING AUDIT] Unknown event_id: %s", row.get("event_id"))
            continue

        if row.get("final_score") != threat.threat_score:
            row["agent_score"] = row.get("final_score")
            row["final_score"] = threat.threat_score
            row["post_harness_score_adjustment"] = "Evidence-based severity cap applied after independent scoring."

        row["scm_tier"] = threat.scm_tier.value
        if "Unknown" in threat.scm_tier.value:
            row["supplier_criticality"] = (
                "UNVERIFIED: Supplier tier, criticality and substitutability have not been established."
            )

        age = _source_age_days(threat.publication_time, as_of_date)
        if age is None:
            date_context = "Source publication date unavailable; temporal urgency not established."
        elif age < 0:
            date_context = "Source is later than the analysis reference date; manual temporal verification required."
        elif age > 90:
            date_context = (
                f"Historical source ({age} days before reference date). "
                "Current operational urgency is not established by this document."
            )
        else:
            date_context = (
                f"Source publication was {age} day(s) before the reference date. "
                "Publication recency alone does not prove a new incident or immediate urgency."
            )

        row.update({
            "temporal_urgency": date_context,
            "source_publication_time": threat.publication_time,
            "source_age_days": age,
            "score_rationale": threat.score_rationale,
        })

        if (
            threat.validation_status != ValidationStatus.SUPPORTED
            or threat.causal_support_status != "EVIDENCED_IN_VERIFIED_SOURCE"
        ):
            row.update({
                "impact_assessment": (
                    "POTENTIAL IMPACT ONLY. Specific operational and causal impacts were "
                    "not established by the validated evidence."
                ),
                "supplier_criticality": (
                    "Supplier dependency / substitutability assessment remains unverified "
                    "unless independently supported by a source."
                ),
                "post_harness_evidence_warning": (
                    "PROVISIONAL ASSESSMENT: Do not interpret potential severity as a "
                    "verified incident or established causal effect."
                ),
            })

    return scoring_audit