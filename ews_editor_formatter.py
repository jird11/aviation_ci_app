"""Convert Editor Agent's plain-text recommendations to typed editorial data."""

import hashlib
import re

from typing import List, Tuple

from tasks import (
    ActionItem,
    EditorialOutput,
    ThreatAssessment,
    TripleAPillar,
    ValidationStatus,
)


_EVENT_LINE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:EVENT|EVENT_ID)\s*:\s*(EVT_[A-Z0-9_]+)\s*$"
)

_FIELD_LINE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?"
    r"(ACTION|RATIONALE|PRO|CON|TRIPLE_A)\s*:\s*(.+?)\s*$"
)

_SUMMARY_LINE = re.compile(
    r"(?im)^\s*SUMMARY\s*:\s*(.+?)\s*$"
)

_SAFE_VERBS = re.compile(
    r"(?i)^(?:verify|validate|check|review|assess|monitor|"
    r"compare|document|trace|investigate)\b"
)


def build_editorial_from_text(
    raw_text: str,
    threats: List[ThreatAssessment],
) -> Tuple[EditorialOutput, int, int]:

    """
    Convert LLM editorial text into a typed Pydantic object.

    Returns:
        EditorialOutput
        number_of_recognized_action_sections
        number_of_fallback_actions
    """

    text = str(raw_text or "")[:16000]

    matches = list(_EVENT_LINE.finditer(text))
    sections = {}

    # Segment the unstructured Editor response by stable event IDs before extracting fields.
    for index, match in enumerate(matches):

        event_id = match.group(1)

        if event_id in sections:
            continue

        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(text)
        )

        sections[event_id] = {
            name.upper(): value.strip()
            for name, value in _FIELD_LINE.findall(
                text[match.end():end]
            )
        }

    # The management summary is regenerated downstream after QA, Scoring, and Harness checks.
    summary_region = (
        text[:matches[0].start()]
        if matches
        else text
    )

    summary_match = _SUMMARY_LINE.search(summary_region)

    summary = (
        summary_match.group(1).strip()[:1400]
        if summary_match
        else ""
    )

    if len(summary) < 20:
        summary = (
            "The Editor prepared a management-oriented review "
            "of retained intelligence signals. All event facts "
            "remain subject to independent QA and human oversight."
        )

    actions = []
    recognized = 0
    fallbacks = 0

    for threat in threats[:3]:

        event_id = threat.event_id
        fields = sections.get(event_id, {})

        proposal = re.sub(
            r"\s+",
            " ",
            fields.get("ACTION", ""),
        ).strip()[:600]

        if len(proposal) >= 10:
            recognized += 1

        # Discard or replace operationally disruptive proposals when their evidence is insufficient.
        # Fallback text must not imply that any real-world intervention has been approved.
        limited = (
            threat.validation_status != ValidationStatus.SUPPORTED
            or threat.program_relevance != "DIRECT_KIT_MATCH"
        )

        if limited:

            if (
                len(proposal) >= 10
                and _SAFE_VERBS.match(proposal)
            ):
                action = proposal
            else:
                action = (
                    f"Verify the source claims and direct KIT relevance "
                    f"of {event_id} before considering operational action."
                )

        else:

            action = (
                proposal
                if len(proposal) >= 10
                else (
                    f"Review documented evidence and proportionate "
                    f"risk mitigation for {event_id}."
                )
            )

        if action != proposal:
            fallbacks += 1

        # Assign a provisional owner based on risk type; human reviewers confirm ownership.
        risk = threat.risk_type.value

        if risk == "REGULATORY":
            owner = "Regulatory Affairs Analyst"

        elif risk in {"SUPPLY_CHAIN", "TECHNICAL_QUALITY"}:
            owner = "Supply Chain Risk Analyst"

        else:
            owner = "Competitive Intelligence Analyst"

        # Map the supplied Triple-A label to controlled categories; other labels use the fallback.
        pillar_name = fields.get("TRIPLE_A", "").lower()

        if "agil" in pillar_name:
            pillar = TripleAPillar.AGILITY

        elif "align" in pillar_name:
            pillar = TripleAPillar.ALIGNMENT

        else:
            pillar = TripleAPillar.ADAPTABILITY

        pro = re.sub(
            r"\s+",
            " ",
            fields.get("PRO", ""),
        ).strip()[:220]

        con = re.sub(
            r"\s+",
            " ",
            fields.get("CON", ""),
        ).strip()[:220]

        if not pro:
            pro = "Clarifies possible next steps."

        if not con:
            con = "Requires evidence verification and analyst time."

        # Reuse editorial reasoning only for supported, directly relevant and technically grounded events.
        # Editor interpretation is advisory and is not additional independent source evidence.
        editor_rationale = re.sub(
            r"\s+", " ", fields.get("RATIONALE", "")
        ).strip()[:350]

        rationale = (
            f"Evidence state: {threat.validation_status.value}; "
            f"KIT relevance: {threat.program_relevance}. "
        )

        if (
                threat.validation_status == ValidationStatus.SUPPORTED
                and threat.program_relevance == "DIRECT_KIT_MATCH"
                and threat.technical_grounding_status == "PASS"
                and editor_rationale
        ):
            rationale += (
                f"Editor reasoning (not independent evidence): {editor_rationale}"
            )
        else:
            rationale += (
                "Verification or monitoring is required "
                "before operational conclusions."
            )

        # Stable action IDs are derived from the event ID, not generated randomly per report.
        action_id = "ACT_" + hashlib.sha256(
            ("EDITOR_TEXT_V1:" + event_id).encode("utf-8")
        ).hexdigest()[:8].upper()

        # Construct typed actions using the existing Pydantic validation contract.
        # JSON serialization occurs later in the report pipeline.
        actions.append(
            ActionItem(
                action_id=action_id,

                related_event_ids=[event_id],

                related_threat_companies=[
                    threat.company_affected
                ],

                action=action,

                rationale=rationale,

                pros_and_cons=(
                    f"PRO: {pro}; CON: {con}"
                ),

                triple_a_impact=pillar,

                uncertainty_assumptions=(
                    "Editorial proposals require source-level "
                    "verification and human approval."
                ),

                owner=owner,

                deadline="Within 7 days",

                kpi=(
                    "Source-backed applicability and verification "
                    f"decision recorded for {event_id}."
                ),

                priority="MEDIUM",

                status="PROPOSED",

                decision="PENDING",
            )
        )

    return (
        EditorialOutput(
            executive_summary=summary,

            qa_audit_summary=(
                "Editor commentary converted to Pydantic actions "
                "by Python; independent evidence QA remains authoritative."
            ),

            action_plan=actions,
        ),
        recognized,
        fallbacks,
    )