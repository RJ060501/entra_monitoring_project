"""
Main entry point for the Entra Monitoring Program.

This file ties together the full monitoring pipeline:

1. Load configuration from .env / environment variables
2. Load persistent state so already-processed events are skipped
3. Pull live data from:
   - Microsoft Entra sign-in logs
   - Microsoft Entra directory audit logs
   - Microsoft 365 / Exchange audit logs
4. Apply location baseline context
5. Filter down to only new events
6. Load rolling caches used for cross-run correlation
7. Run individual detectors
8. Run cross-run / cross-source correlation detectors
9. Deduplicate alerts
10. Save readable medium/high/critical alert history
11. Send alerts to console and Microsoft Teams
12. Save updated state
13. Update location baseline
14. Update rolling caches

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
from core.location_baseline import (
    load_location_baseline,
    save_location_baseline,
    apply_location_baseline,
    update_location_baseline,
)
from core.alert_history import (
    load_alert_history,
    save_alert_history,
    add_alerts_to_history,
)
from core.new_location_cache import (
    load_new_location_cache,
    save_new_location_cache,
    add_new_location_events_to_cache,
)

from detectors.signin_detector import (
    detect_signin_events,
    detect_new_location_burst,
)
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

    # Load known sign-in locations per user.
    location_baseline = load_location_baseline()

    # Apply new_location flags before detections run.
    signins = apply_location_baseline(signins, location_baseline)

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

    # Load rolling suspicious sign-in cache.
    # This allows mailbox-rule correlation across runs.
    cached_suspicious_signins = load_suspicious_signin_cache()

    # Load rolling new-location activity cache.
    # This allows new-location burst detection across runs.
    cached_new_location_events = load_new_location_cache()

    # Identify suspicious sign-ins from this run for future correlation.
    new_suspicious_signins = get_suspicious_signins(new_signins)

    # Combine cached and new new-location activity for cross-run burst detection.
    combined_new_location_events = cached_new_location_events + new_signins

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
    alerts += detect_new_location_burst(combined_new_location_events)
    alerts += detect_audit_events(new_audits)
    alerts += detect_email_events(new_email_events)

    # Run correlation detector using both current and cached suspicious sign-ins.
    alerts += detect_correlations(
        signin_events=new_signins,
        email_events=new_email_events,
        cached_signins=cached_suspicious_signins,
    )

    # Remove duplicate or near-duplicate alerts from this run.
    alerts = deduplicate_alerts(alerts)

    logger.info(f"Alert count: {len(alerts)}")

    # Save readable medium/high/critical alert history.
    alert_history = load_alert_history()

    alert_history = add_alerts_to_history(
        existing_history=alert_history,
        alerts=alerts,
    )

    save_alert_history(alert_history)

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

    # Update location baseline with latest sign-ins.
    location_baseline = update_location_baseline(
        signins,
        location_baseline,
    )

    save_location_baseline(location_baseline)

    # Update rolling suspicious sign-in cache for future mailbox correlation.
    updated_suspicious_signin_cache = add_suspicious_signins_to_cache(
        existing_events=cached_suspicious_signins,
        new_events=new_suspicious_signins,
    )

    save_suspicious_signin_cache(updated_suspicious_signin_cache)

    # Update rolling new-location cache for future burst detection.
    updated_new_location_cache = add_new_location_events_to_cache(
        existing_cache=cached_new_location_events,
        events=new_signins,
    )

    save_new_location_cache(updated_new_location_cache)

    logger.info("Finished Entra monitoring run.")


if __name__ == "__main__":
    main()