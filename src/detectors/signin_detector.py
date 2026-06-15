"""
Sign-in detector module.

This module inspects Entra sign-in events and generates alerts for patterns
that may indicate suspicious login activity.

It currently detects:
- logins at unusual hours
- sign-ins from a new location
- multiple failed sign-ins followed by a success
"""

from config.settings import SUPPRESSED_USERS

from collections import defaultdict


def detect_signin_events(events, cached_failed_signins=None):
    """
    Main sign-in detector entry point.

    cached_failed_signins:
        Recent failed sign-ins from previous runs.

        This lets failed-then-success detection work even when failures and
        successes are split across scheduled monitoring runs.
    """
    alerts = []

    alerts += detect_unusual_login_time(events)
    alerts += detect_new_location(events)
    alerts += detect_failed_then_success(
        events=events,
        cached_failed_signins=cached_failed_signins,
    )

    return alerts


def detect_unusual_login_time(events):
    """Detect sign-ins that happen outside normal business hours."""
    alerts = []

    for event in events:
        user = event["user"]

        # Ignore users that are intentionally suppressed from alerting.
        if user in SUPPRESSED_USERS:
            continue

        hour = event.get("hour")

        # Treat logins before 1 AM or after 4:59M as unusual.
        if hour is not None and (1 <= hour <= 4):
            alerts.append({
                "severity": "medium",
                "type": "Unusual Login Time",
                "user": user,
                "detail": f"Login at hour {hour} UTC",
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
            })

    return alerts


def detect_new_location(events):
    """Detect sign-ins that are marked as coming from a new location."""
    alerts = []

    for event in events:
        user = event["user"]

        if user in SUPPRESSED_USERS:
            continue

        # The normalized sign-in event includes a boolean new_location flag.
        if event.get("new_location"):
            alerts.append({
                "severity": "low",
                "type": "New Location",
                "user": user,
                "detail": f"New location detected: {event.get('location', 'Unknown')}",
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
            })

    return alerts


def detect_failed_then_success(events, cached_failed_signins=None):
    """
    Detect failed sign-ins followed by a successful sign-in.

    This detector uses:
    - current run events
    - cached failed sign-ins from previous runs

    Important:
    Alerts are only generated on successes from the current run.

    This prevents old cached data from repeatedly generating alerts without a
    new success event.
    """
    alerts = []
    cached_failed_signins = cached_failed_signins or []

    current_success_ids = {
        event.get("id")
        for event in events
        if event.get("status") == "success" and event.get("id")
    }

    combined_events = cached_failed_signins + events

    events_by_user = {}

    for event in combined_events:
        user = event.get("user")

        if not user:
            continue

        if user in SUPPRESSED_USERS:
            continue

        events_by_user.setdefault(user, []).append(event)

    for user, user_events in events_by_user.items():
        user_events.sort(key=lambda x: x.get("created_datetime", ""))

        failures_before_success = []

        for event in user_events:
            status = event.get("status")

            if status == "failure":
                failures_before_success.append(event)
                continue

            if status != "success":
                continue

            event_id = event.get("id")

            # Only alert on a success from this current run.
            if event_id not in current_success_ids:
                continue

            if len(failures_before_success) < 3:
                continue

            failure_count = len(failures_before_success)

            latest_failure = failures_before_success[-1]

            # Severity logic:
            # - 3+ failures followed by success = medium
            # - 5+ failures followed by success = high
            # - success from new location = high
            if failure_count >= 5 or event.get("new_location"):
                severity = "high"
            else:
                severity = "medium"

            alerts.append({
                "severity": severity,
                "type": "Failed Sign-ins Followed by Success",
                "user": user,
                "detail": (
                    f"{failure_count} failed sign-in(s) followed by success. "
                    f"Successful app: {event.get('app_display_name', 'Unknown')}. "
                    f"IP: {event.get('ip_address', 'Unknown')}. "
                    f"Last failure reason: {latest_failure.get('failure_reason', 'Unknown')}"
                ),
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
                # Internal metadata used by main.py to clear cache after alerting.
                "cache_clear_user": user,
            })

            # Reset so multiple successes in the same run do not all alert from
            # the same failure group.
            failures_before_success = []

    return alerts

def detect_new_location_burst(events):
    """
    Detect repeated successful sign-ins from new locations.

    This is stronger than a single new-location alert.

    Severity logic:
    - 3+ successful new-location sign-ins for same user = medium
    - 2+ distinct new locations or 2+ distinct IPs = high
    """
    alerts = []
    events_by_user = defaultdict(list)

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        if event.get("status") != "success":
            continue

        if not event.get("new_location"):
            continue

        events_by_user[user].append(event)

    for user, user_events in events_by_user.items():
        if len(user_events) < 3:
            continue

        locations = {
            event.get("location", "Unknown")
            for event in user_events
        }

        ip_addresses = {
            event.get("ip_address", "Unknown")
            for event in user_events
        }

        apps = {
            event.get("app_display_name", "Unknown")
            for event in user_events
        }

        if len(locations) >= 2 or len(ip_addresses) >= 2:
            severity = "high"
            reason = "multiple new locations or IP addresses"
        else:
            severity = "medium"
            reason = "repeated successful sign-ins from a new location"

        alerts.append({
            "severity": severity,
            "type": "New Location Sign-in Burst",
            "user": user,
            "detail": (
                f"{len(user_events)} successful sign-in(s) from new location activity. "
                f"Reason: {reason}. "
                f"Locations: {', '.join(sorted(locations))}. "
                f"IP address(es): {', '.join(sorted(ip_addresses))}. "
                f"Apps: {', '.join(sorted(apps))}."
            ),
            "location": ", ".join(sorted(locations)),
            "source": "Entra Sign-In Logs",
        })

    return alerts