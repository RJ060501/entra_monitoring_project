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
6. Load rolling caches used for cross-run detection and correlation
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
- Rolling caches are used because suspicious behavior may span multiple runs.
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
from core.mailbox_activity_cache import (
    load_mailbox_activity_cache,
    save_mailbox_activity_cache,
    add_mailbox_activity_events_to_cache,
)

from core.failed_signin_cache import (
    load_failed_signin_cache,
    save_failed_signin_cache,
    add_failed_signins_to_cache,
    clear_failed_signins_for_users,
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

    This function is informational only. It does not affect detections.
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

    # Load configuration and persistent processing state.
    settings = load_settings()
    state = load_state()

    # Initialize Microsoft API clients.
    entra_client = EntraClient(settings)
    m365_client = M365AuditClient(settings)

    # Pull current data from Microsoft APIs.
    signins = entra_client.get_signins()
    audits = entra_client.get_audits()
    email_events = m365_client.get_email_audit_events()

    # Load known sign-in locations per user.
    location_baseline = load_location_baseline()

    # Apply new_location flags before detections run.
    signins = apply_location_baseline(
        events=signins,
        baseline=location_baseline,
    )

    # Filter out events that were already processed in previous runs.
    new_signins = filter_new_events(
        events=signins,
        processed_ids=state.get("processed_signin_ids", []),
    )

    new_audits = filter_new_events(
        events=audits,
        processed_ids=state.get("processed_audit_ids", []),
    )

    new_email_events = filter_new_events(
        events=email_events,
        processed_ids=state.get("processed_email_event_ids", []),
    )

    # Load rolling caches.
    #
    # These caches solve the 15-minute run-window problem:
    # suspicious behavior may be split across scheduled runs.
    cached_suspicious_signins = load_suspicious_signin_cache()
    cached_new_location_events = load_new_location_cache()
    cached_mailbox_activity_events = load_mailbox_activity_cache()
    cached_failed_signins = load_failed_signin_cache()

    # Identify suspicious sign-ins from this run for future mailbox correlation.
    new_suspicious_signins = get_suspicious_signins(new_signins)

    # Combine cached and new new-location events for cross-run burst detection.
    #
    # This allows:
    # Run 1: several new-location successes
    # Run 2: more new-location successes
    # Alert: New Location Sign-in Burst
    combined_new_location_events = cached_new_location_events + new_signins

    # Print/log run summary.
    print_email_operation_summary(new_email_events)

    print(f"New sign-in event(s): {len(new_signins)}")
    print(f"New audit event(s): {len(new_audits)}")
    print(f"New email audit event(s): {len(new_email_events)}")

    logger.info(f"New sign-in event(s): {len(new_signins)}")
    logger.info(f"New audit event(s): {len(new_audits)}")
    logger.info(f"New email audit event(s): {len(new_email_events)}")

    # Run single-source detectors.
    alerts = []
    alerts += detect_signin_events(
        events=new_signins,
        cached_failed_signins=cached_failed_signins,
    )

    alerts += detect_new_location_burst(
        events=combined_new_location_events,
        failed_signin_events=cached_failed_signins + new_signins,
        mailbox_events=cached_mailbox_activity_events + new_email_events,
    )

    alerts += detect_audit_events(new_audits)
    alerts += detect_email_events(new_email_events)

    # Correlation pass 1:
    # Cached suspicious sign-ins + new mailbox activity.
    #
    # This handles:
    # Run 1: suspicious sign-in
    # Run 2: mailbox rule / forwarding / hide-delete activity
    alerts += detect_correlations(
        signin_events=new_signins,
        email_events=new_email_events,
        cached_signins=cached_suspicious_signins,
    )

    # Correlation pass 2:
    # New suspicious sign-ins + cached mailbox activity.
    #
    # This handles the reverse order:
    # Run 1: mailbox rule / forwarding / hide-delete activity
    # Run 2: suspicious sign-in
    #
    # Important:
    # We intentionally do not pass cached_signins here.
    # That prevents cached sign-ins from correlating with cached mailbox events
    # repeatedly on every run.
    alerts += detect_correlations(
        signin_events=new_signins,
        email_events=[],
        cached_email_events=cached_mailbox_activity_events,
    )

    # Remove duplicate or near-duplicate alerts from this run.
    alerts = deduplicate_alerts(alerts)
    
    failed_cache_clear_users = {
        alert.get("cache_clear_user")
        for alert in alerts
        if alert.get("cache_clear_user")
    }
    
    logger.info(f"Alert count: {len(alerts)}")

    # Save readable medium/high/critical alert history.
    #
    # This is separate from state.json.
    # state.json prevents duplicate processing.
    # security_alert_history.json is for review and investigation.
    alert_history = load_alert_history()

    alert_history = add_alerts_to_history(
        existing_history=alert_history,
        alerts=alerts,
    )

    save_alert_history(alert_history)

    # Send alerts to console and Teams.
    #
    # The Teams notifier filters out low severity alerts.
    send_console_alerts(alerts)
    send_teams_alerts(alerts, settings)

    # Mark current events as processed so they are not processed again.
    state = mark_events_processed(
        state=state,
        key="processed_signin_ids",
        events=new_signins,
    )

    state = mark_events_processed(
        state=state,
        key="processed_audit_ids",
        events=new_audits,
    )

    state = mark_events_processed(
        state=state,
        key="processed_email_event_ids",
        events=new_email_events,
    )

    save_state(state)

    # Update location baseline with latest sign-ins.
    #
    # Note:
    # This currently uses all sign-ins. Later, we may want to update baseline
    # only from trusted/successful/low-risk sign-ins to avoid learning attacker
    # locations too quickly.
    location_baseline = update_location_baseline(
        events=signins,
        baseline=location_baseline,
    )

    save_location_baseline(location_baseline)

    # Update rolling suspicious sign-in cache.
    #
    # This lets future mailbox activity correlate with suspicious sign-ins from
    # previous monitoring runs.
    updated_suspicious_signin_cache = add_suspicious_signins_to_cache(
        existing_events=cached_suspicious_signins,
        new_events=new_suspicious_signins,
    )

    save_suspicious_signin_cache(updated_suspicious_signin_cache)

    # Update rolling new-location activity cache.
    #
    # This lets future runs detect repeated new-location activity that spans
    # multiple scheduled runs.
    updated_new_location_cache = add_new_location_events_to_cache(
        existing_cache=cached_new_location_events,
        events=new_signins,
    )

    save_new_location_cache(updated_new_location_cache)

    # Update rolling mailbox activity cache.
    #
    # This lets future suspicious sign-ins correlate with mailbox activity from
    # previous monitoring runs.
    updated_mailbox_activity_cache = add_mailbox_activity_events_to_cache(
        existing_cache=cached_mailbox_activity_events,
        events=new_email_events,
    )

    save_mailbox_activity_cache(updated_mailbox_activity_cache)
    
    updated_failed_signin_cache = add_failed_signins_to_cache(
        existing_cache=cached_failed_signins,
        events=new_signins,
    )

    updated_failed_signin_cache = clear_failed_signins_for_users(
        cache=updated_failed_signin_cache,
        users=failed_cache_clear_users,
    )

    save_failed_signin_cache(updated_failed_signin_cache)

    logger.info("Finished Entra monitoring run.")


if __name__ == "__main__":
    main()