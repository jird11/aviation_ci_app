# =============================================================================
# aviation_ci_app | AI governance and legal-assessment metadata
#
# Responsibility: Summarize technical safeguards, human oversight, model traceability, and open
#   legal-review obligations.
# Design boundary: A governance record documents controls; it does not certify AI Act, GDPR, or copyright
#   compliance.
# =============================================================================

"""AI governance evidence and legal-assessment support for aviation_ci_app."""

from datetime import datetime, timezone


# Assemble a transparent safeguard record without making legal-conformity claims.
# These records document observed controls; a legal conformity determination requires separate review.
# An applicable legal duty cannot be inferred from a technical safeguard flag alone.
def build_ai_governance_record(report):
    """Document technical safeguards without asserting legal compliance."""
    metadata = report.run_metadata or {}
    threats = list(report.threats or [])

    citations_complete = (
        all(t.evidence_ids and t.source_urls for t in threats)
        if threats else None
    )

    return {
        "regulatory_reference": "Regulation (EU) 2024/1689, as amended",
        "assessment_timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "intended_purpose": (
            "Competitive Intelligence decision support using "
            "publicly available aerospace information."
        ),

        "prohibited_uses": [
            "Autonomous aircraft operation",
            "Autonomous safety-critical decisions",
            "Automated regulatory certification",
            "Unreviewed operational interventions",
        ],

        "ai_system_provider": "Externally hosted LLM provider",
        "model_identifier": metadata.get("model_id"),
        "run_id": report.run_id,

        "risk_classification": "REQUIRES_LEGAL_ASSESSMENT",
        "legal_compliance_status": "NOT_CERTIFIED",

        "ai_generated_content": True,
        "human_oversight_available": True,
        "human_review_status": report.hitl_status,

        "controls": {
            "source_traceability": citations_complete,
            "independent_qa": (
                None
                if not metadata.get("qa_performed", False)
                else not metadata.get("qa_failed", True)
            ),

            "deterministic_validation": (
                True
                if metadata.get("harness_performed", False)
                else None
            ),
            "human_review_gate": True,
            "critical_alert_requires_verified_evidence": True,
            "model_and_run_logging": bool(
                metadata.get("model_id") and report.run_id
            ),
        },

        "legal_review_items": {
            "article_4_ai_literacy": "ORGANIZATIONAL_REVIEW_REQUIRED",
            "article_50_transparency": "APPLICABILITY_REVIEW_REQUIRED",
            "article_6_high_risk_classification": "LEGAL_REVIEW_REQUIRED",
            "personal_data_processing": "GDPR_REVIEW_REQUIRED",
            "copyright_and_tdm": "SOURCE_SPECIFIC_REVIEW_REQUIRED",
        },

        "limitations": (
            "These records document implemented safeguards. "
            "They are not a legal conformity assessment, "
            "certification or proof of compliance."
        ),
    }