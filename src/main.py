"""
Main entry point for the Entra Monitoring Program.

This file ties together the full monitoring pipeline:

1. Load configuration from .env / environment variables
2. Load persistent state so already-processed events are skipped
3. Pull live data from:
   - Microsoft Entra sign-in logs
   - Microsoft Entra directory audit logs
   - Microsoft 365 / Exchange audit logs
4. Filter down to only new events
5. Run individual detectors
6. Run correlation detectors
7. Deduplicate alerts
8. Send alerts to console and Microsoft Teams
9. Save updated state
10. Save/update the suspicious sign-in cache for future correlation

Important:
- This script performs one monitoring run and then exits.
- It is intended to be executed every 15 minutes by systemd.
"""

from collections import Counter

from clients.entra_client import EntraClient
from clients.m365_audit_client import M365AuditClient

from config.settings import load_settings

from core.deduplicator import deduplicate_alerts
from core.logger import setup_logger
from core.state_manager import (
    load_state,
    save_state,
    filter_new_events,
    mark_events_processed,
)
from core.correlation_cache import (
    load_suspicious_signin_cache,
    save_suspicious_signin_cache,
    add_suspicious_signins_to_cache,
)

from detectors.signin_detector import detect_signin_events
from detectors.audit_detector import detect_audit_events
from detectors.email_detector import detect_email_events
from detectors.correlation_detector import (
    detect_correlations,
    get_suspicious_signins,
)

from notifiers.console_notifier import send_alerts as send_console_alerts
from notifiers.teams_notifier import send_alerts as send_teams_alerts


def print_email_operation_summary(email_events):
    """
    Print the most common Microsoft 365 / Exchange audit operations.

    This is useful while tuning detections because it shows what types of
    mailbox events are actually appearing in your tenant.
    """
    operation_counts = Counter(
        event.get("operation", "Unknown")
        for event in email_events
    )

    print("Top email audit operations:")

    if not operation_counts:
        print("No new email audit operations.")
        return

    for operation, count in operation_counts.most_common(15):
        print(f"{operation}: {count}")


def main():
    """
    Run one full monitoring cycle.
    """
    logger = setup_logger()
    logger.info("Starting Entra monitoring run.")

    # Load settings and persistent state.
    settings = load_settings()
    state = load_state()

    # Initialize API clients.
    entra_client = EntraClient(settings)
    m365_client = M365AuditClient(settings)

    # Pull current data from Microsoft APIs.
    signins = entra_client.get_signins()
    audits = entra_client.get_audits()
    email_events = m365_client.get_email_audit_events()

    # Filter out events that were already processed in previous runs.
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

    # Load suspicious sign-ins from previous runs.
    # This allows correlation across time, not just within the current run.
    cached_suspicious_signins = load_suspicious_signin_cache()

    # Identify suspicious sign-ins from this run and add them to cache later.
    new_suspicious_signins = get_suspicious_signins(new_signins)

    # Print/log run summary.
    print_email_operation_summary(new_email_events)

    print(f"New sign-in event(s): {len(new_signins)}")
    print(f"New audit event(s): {len(new_audits)}")
    print(f"New email audit event(s): {len(new_email_events)}")

    logger.info(f"New sign-in event(s): {len(new_signins)}")
    logger.info(f"New audit event(s): {len(new_audits)}")
    logger.info(f"New email audit event(s): {len(new_email_events)}")

    # Run detectors.
    alerts = []
    alerts += detect_signin_events(new_signins)
    alerts += detect_audit_events(new_audits)
    alerts += detect_email_events(new_email_events)

    # Run correlation detector using both current and cached suspicious sign-ins.
    alerts += detect_correlations(
        signin_events=new_signins,
        email_events=new_email_events,
        cached_signins=cached_suspicious_signins,
    )

    # Remove duplicate alerts from this run.
    alerts = deduplicate_alerts(alerts)

    logger.info(f"Alert count: {len(alerts)}")

    # Send alerts.
    send_console_alerts(alerts)
    send_teams_alerts(alerts, settings)

    # Mark current events as processed so they are not alerted on again.
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

    # Update rolling suspicious sign-in cache for future correlation.
    updated_cache = add_suspicious_signins_to_cache(
        existing_events=cached_suspicious_signins,
        new_events=new_suspicious_signins,
    )

    save_suspicious_signin_cache(updated_cache)

    logger.info("Finished Entra monitoring run.")


if __name__ == "__main__":
    main()