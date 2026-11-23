# =============================================================================
# aviation_ci_app | Evidence-gated outbound critical-alert notifications
#
# Responsibility: Send optional SMTP notifications for human-approved,
#   directly relevant, evidence-supported critical events.
# Design boundary: Alert state is stored locally (non-atomic with SMTP send).
# =============================================================================

"""Optional email notifications for confirmed critical intelligence events."""

import json
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

ALERT_STATE_FILE = Path("ews_alert_state.json")
_SMTP_ENV_KEYS = ("EWS_SMTP_HOST", "EWS_ALERT_FROM", "EWS_ALERT_TO", "EWS_SMTP_USER", "EWS_SMTP_PASSWORD")


def send_verified_critical_alerts(report: dict) -> int:
    """Send deduplicated SMTP alerts only for human-approved, evidence-supported critical events."""
    # Gate outbound notifications on explicit opt-in, HITL+QA approval, and complete SMTP credentials.
    if os.getenv("EWS_ALERTS_ENABLED", "0") != "1" or report.get("hitl_status") != "APPROVED_BY_HITL_AND_QA":
        return 0
    host, sender, recipient, username, password = (os.getenv(k) for k in _SMTP_ENV_KEYS)
    if not all((host, sender, recipient, username, password)):
        return 0

    port = int(os.getenv("EWS_SMTP_PORT", "465"))
    try:
        seen = set(json.loads(ALERT_STATE_FILE.read_text("utf-8")))
    except (OSError, ValueError):
        seen = set()

    sent_count = 0
    for event in report.get("threats", []):
        # Enforce full evidence, relevance, and critical-escalation criteria before alerting.
        if not (
            int(event.get("threat_score", 0)) >= 8
            and event.get("validation_status") == "SUPPORTED"
            and event.get("confidence_level") == "HIGH"
            and event.get("program_relevance") == "DIRECT_KIT_MATCH"
            and event.get("escalation_level") == "CRITICAL_CONFIRMED_ALERT"
            and event.get("is_critical") is True
        ):
            continue

        # Deduplicate by event_id + publication_time against locally persisted alert state.
        alert_key = f"{event['event_id']}:{event.get('publication_time', 'UNKNOWN')}"
        if alert_key in seen:
            continue

        message = EmailMessage()
        message["Subject"], message["From"], message["To"] = f"aviation_ci_app Critical Alert: {event['company_affected']}", sender, recipient
        message.set_content(
            f"Confirmed critical intelligence event\n\n"
            f"Event ID: {event['event_id']}\nCompany: {event['company_affected']}\n"
            f"Program: {event.get('affected_program', 'Unknown')}\nSeverity: {event['threat_score']}/10\n"
            f"Evidence status: {event['validation_status']}\n\nAssessment:\n{event.get('threat_description', '')}\n\n"
            f"Sources:\n" + "\n".join(event.get("source_urls", []))
            + "\n\nHuman review completed. Verify source evidence before operational action."
        )

        # Dispatch via SMTP_SSL and persist updated deduplication state immediately after send.
        with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
            smtp.login(username, password)
            smtp.send_message(message)
        seen.add(alert_key)
        ALERT_STATE_FILE.write_text(json.dumps(sorted(seen), indent=2), encoding="utf-8")
        sent_count += 1

    return sent_count