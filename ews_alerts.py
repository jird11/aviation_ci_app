# =============================================================================
# aviation_ci_app | Evidence-gated outbound critical-alert notifications
#
# Responsibility: Send optional SMTP notifications for human-approved, directly relevant,
#   evidence-supported critical events.
# Design boundary: Alert state is stored locally; it is not a distributed delivery guarantee.
# The SMTP call and state-file update are not a single atomic transaction.
# =============================================================================

"""Optional email notifications for confirmed critical intelligence events."""

import json
import os
import smtplib

from email.message import EmailMessage
from pathlib import Path


ALERT_STATE_FILE = Path("ews_alert_state.json")


# Email only confirmed, human-approved critical alerts that have not already been sent.
# Alert deduplication is keyed by event ID and publication timestamp; it is not a global incident ID.
def send_verified_critical_alerts(report: dict) -> int:
    """Send alerts only for approved, evidence-supported critical events."""
    if os.getenv("EWS_ALERTS_ENABLED", "0") != "1":
        return 0

    if report.get("hitl_status") != "APPROVED_BY_HITL_AND_QA":
        return 0

    host = os.getenv("EWS_SMTP_HOST")
    sender = os.getenv("EWS_ALERT_FROM")
    recipient = os.getenv("EWS_ALERT_TO")
    username = os.getenv("EWS_SMTP_USER")
    password = os.getenv("EWS_SMTP_PASSWORD")

    if not all([host, sender, recipient, username, password]):
        return 0

    port = int(os.getenv("EWS_SMTP_PORT", "465"))

    try:
        seen = set(json.loads(ALERT_STATE_FILE.read_text("utf-8")))
    except (OSError, ValueError):
        seen = set()

    sent_count = 0

    for event in report.get("threats", []):
        confirmed = (
            int(event.get("threat_score", 0)) >= 8
            and event.get("validation_status") == "SUPPORTED"
            and event.get("confidence_level") == "HIGH"
            and event.get("program_relevance") == "DIRECT_KIT_MATCH"
            and event.get("escalation_level") == "CRITICAL_CONFIRMED_ALERT"
            and event.get("is_critical") is True
        )

        if not confirmed:
            continue

        alert_key = (
            f"{event['event_id']}:"
            f"{event.get('publication_time', 'UNKNOWN')}"
        )

        if alert_key in seen:
            continue

        message = EmailMessage()
        message["Subject"] = (
            f"aviation_ci_app Critical Alert: {event['company_affected']}"
        )
        message["From"] = sender
        message["To"] = recipient

        message.set_content(
            f"Confirmed critical intelligence event\n\n"
            f"Event ID: {event['event_id']}\n"
            f"Company: {event['company_affected']}\n"
            f"Program: {event.get('affected_program', 'Unknown')}\n"
            f"Severity: {event['threat_score']}/10\n"
            f"Evidence status: {event['validation_status']}\n\n"
            f"Assessment:\n{event.get('threat_description', '')}\n\n"
            f"Sources:\n"
            + "\n".join(event.get("source_urls", []))
            + "\n\nHuman review completed. "
              "Verify source evidence before operational action."
        )

        with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
            smtp.login(username, password)
            smtp.send_message(message)

        seen.add(alert_key)
        ALERT_STATE_FILE.write_text(
            json.dumps(sorted(seen), indent=2),
            encoding="utf-8",
        )
        sent_count += 1

    return sent_count