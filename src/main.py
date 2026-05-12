"""
Main entry point for the Entra Monitoring Program.

This file ties together the full monitoring pipeline:
1. Load configuration from environment variables and optional .env file
2. Pull data (currently sample data, later Microsoft Graph API)
3. Run detection rules against sign-in and audit events
4. Deduplicate alerts
5. Send alerts to the console
6. Optionally send alerts to Microsoft Teams

Important:
- The program is still a single-run monitor.
- It does NOT run forever by itself.
- Later, we will run this repeatedly using systemd or cron.
"""

"""
Main entry point for the Entra Monitoring Program.
"""

from clients.entra_client import EntraClient
from detectors.signin_detector import detect_signin_events
from detectors.audit_detector import detect_audit_events
from core.deduplicator import deduplicate_alerts
from core.state_manager import (
    load_state,
    save_state,
    filter_new_events,
    mark_events_processed,
)
from notifiers.console_notifier import send_alerts as send_console_alerts
from notifiers.teams_notifier import send_alerts as send_teams_alerts
from config.settings import load_settings
from core.logger import setup_logger
from clients.m365_audit_client import M365AuditClient
from detectors.email_detector import detect_email_events
from detectors.correlation_detector import detect_correlations


def main():
    logger = setup_logger()
    logger.info("Starting Entra monitoring run.")
    
    settings = load_settings()
    state = load_state()

    client = EntraClient(settings)
    m365_client = M365AuditClient(settings)

    signins = client.get_signins()
    audits = client.get_audits()
    email_events = m365_client.get_email_audit_events()

    new_signins = filter_new_events(
        signins,
        state.get("processed_signin_ids", []),
    )

    new_audits = filter_new_events(
        audits,
        state.get("processed_audit_ids", []),
    )
    
    new_email_events = filter_new_events(
    email_events,
    state.get("processed_email_event_ids", []),
)

    print(f"New sign-in event(s): {len(new_signins)}")
    print(f"New audit event(s): {len(new_audits)}")
    print(f"New email audit event(s): {len(new_email_events)}")
    logger.info(f"New email audit event(s): {len(new_email_events)}")

    alerts = []
    alerts += detect_signin_events(new_signins)
    alerts += detect_audit_events(new_audits)
    alerts += detect_email_events(new_email_events)
    alerts += detect_correlations(new_signins, new_email_events)

    alerts = deduplicate_alerts(alerts)

    send_console_alerts(alerts)
    send_teams_alerts(alerts, settings)

    state = mark_events_processed(
        state,
        "processed_signin_ids",
        new_signins,
    )

    state = mark_events_processed(
        state,
        "processed_audit_ids",
        new_audits,
    )
    
    state = mark_events_processed(
    state,
    "processed_email_event_ids",
    new_email_events,
)

    save_state(state)

    logger.info("Finished Entra monitoring run.")

if __name__ == "__main__":
    main()
