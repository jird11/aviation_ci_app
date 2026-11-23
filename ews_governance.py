# =============================================================================
# aviation_ci_app | AI governance and legal-assessment metadata
#
# Responsibility: Summarize technical safeguards, human oversight, model
#   traceability, and open legal-review obligations.
# Design boundary: A governance record documents controls; it does not certify
#   AI Act, GDPR, or copyright compliance.
# =============================================================================

"""AI governance evidence and legal-assessment support for aviation_ci_app."""

from datetime import datetime, timezone

# Static governance declarations and open legal-review checklists (preserved verbatim).
_PROHIBITED_USES = (
    "Autonomous aircraft operation", "Autonomous safety-critical decisions",
    "Automated regulatory certification", "Unreviewed operational interventions",
)
_LEGAL_REVIEW_ITEMS = {
    "article_4_ai_literacy": "ORGANIZATIONAL_REVIEW_REQUIRED",
    "article_50_transparency": "APPLICABILITY_REVIEW_REQUIRED",
    "article_6_high_risk_classification": "LEGAL_REVIEW_REQUIRED",
    "personal_data_processing": "GDPR_REVIEW_REQUIRED",
    "copyright_and_tdm": "SOURCE_SPECIFIC_REVIEW_REQUIRED",
}


def build_ai_governance_record(report):
    """Document observed technical safeguards without asserting legal compliance."""
    meta, threats = report.run_metadata or {}, list(report.threats or [])
    model_id = meta.get("model_id")
    # Derive runtime safeguard flags strictly from observed report state.
    return {
        "regulatory_reference": "Regulation (EU) 2024/1689, as amended",
        "assessment_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "intended_purpose": "Competitive Intelligence decision support using publicly available aerospace information.",
        "prohibited_uses": list(_PROHIBITED_USES),
        "ai_system_provider": "Externally hosted LLM provider",
        "model_identifier": model_id,
        "run_id": report.run_id,
        "risk_classification": "REQUIRES_LEGAL_ASSESSMENT",
        "legal_compliance_status": "NOT_CERTIFIED",
        "ai_generated_content": True,
        "human_oversight_available": True,
        "human_review_status": report.hitl_status,
        "controls": {
            "source_traceability": all(t.evidence_ids and t.source_urls for t in threats) if threats else None,
            "independent_qa": (not meta.get("qa_failed", True)) if meta.get("qa_performed", False) else None,
            "deterministic_validation": True if meta.get("harness_performed", False) else None,
            "human_review_gate": True,
            "critical_alert_requires_verified_evidence": True,
            "model_and_run_logging": bool(model_id and report.run_id),
        },
        "legal_review_items": dict(_LEGAL_REVIEW_ITEMS),
        "limitations": "These records document implemented safeguards. They are not a legal conformity assessment, certification or proof of compliance.",
    }