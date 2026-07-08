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
from core.security_constants import (
    MAILBOX_CONFIGURATION_OPERATIONS,
    SUSPICIOUS_SIGNIN_TEXT_INDICATORS,
    RISKY_SIGNIN_LEVELS,
)
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
    """
    Detect sign-ins that happen outside normal business hours.

    V1 tuning:
    - Unusual login time by itself is LOW.
    - Unusual login time from a new location is MEDIUM.
    - Unusual login time with suspicious risk/client context is HIGH.

    This keeps the signal available in console/history without spamming Teams
    for normal after-hours Microsoft 365 activity.
    """
    alerts = []

    for event in events:
        user = str(event.get("user", "")).lower().strip()

        if not user:
            continue

        # Ignore users that are intentionally suppressed from alerting.
        if user in SUPPRESSED_USERS:
            continue

        # Only alert on successful sign-ins.
        if event.get("status") != "success":
            continue

        hour = event.get("hour")

        # Treat sign-ins between 1:00 AM and 4:59 AM UTC as unusual.
        if hour is None or not (1 <= hour <= 4):
            continue

        has_new_location = bool(event.get("new_location"))
        has_suspicious_context = has_suspicious_signin_context([event])

        if has_suspicious_context:
            severity = "high"
            reason = "unusual login time with suspicious sign-in context"
        elif has_new_location:
            severity = "medium"
            reason = "unusual login time from a new location"
        else:
            severity = "low"
            reason = "unusual login time only"

        alerts.append({
            "severity": severity,
            "type": "Unusual Login Time",
            "user": user,
            "detail": (
                f"Login at hour {hour} UTC. "
                f"Reason: {reason}. "
                f"App: {event.get('app_display_name', 'Unknown')}. "
                f"IP: {event.get('ip_address', 'Unknown')}."
            ),
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

            # Why:
            # Repeated Microsoft sign-in failures can happen during normal
            # prompts such as "Keep me signed in", expired passwords, or MFA
            # registration. Those should be visible, but should only become
            # HIGH when the eventual success happens from a new location.
            if event.get("new_location"):
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
                "cache_clear_user": user,
            })

            # Reset so multiple successes in the same run do not all alert from
            # the same failure group.
            failures_before_success = []

    return alerts

def detect_new_location_burst(
    events,
    failed_signin_events=None,
    mailbox_events=None,
):
    """
    Detect repeated successful sign-ins from new locations.

    This detector is context-aware but still intentionally simple.

    It does not replace the dedicated detectors for:
    - failed sign-ins followed by success
    - mailbox rules
    - forwarding
    - hide/delete rules
    - sign-in/mailbox correlation

    Instead, it uses nearby context to decide whether a new-location burst is
    just LOW context or should be Teams-visible.

    Severity logic:

    LOW:
    - 3+ successful new-location sign-ins
    - same user
    - same location
    - same IP
    - no failed sign-in context
    - no mailbox activity context
    - no suspicious client/risk context

    MEDIUM:
    - same location/IP burst, but high volume
    - OR same location/IP burst with failed sign-in context
    - OR same location/IP burst with suspicious client/risk context

    HIGH:
    - burst from multiple new locations
    - OR burst from multiple IP addresses
    - OR burst paired with mailbox activity context

    Why:
    Microsoft 365 often creates several successful sign-ins close together from
    normal apps such as Office, SharePoint, Teams, OneDrive, and Outlook.
    That should not page Teams by itself.

    But when new-location burst activity overlaps with failures, mailbox rule
    activity, suspicious client behavior, or multiple IPs/locations, it becomes
    much more useful as a security alert.
    """
    alerts = []

    failed_signin_events = failed_signin_events or []
    mailbox_events = mailbox_events or []

    events_by_user = {}

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        if event.get("status") != "success":
            continue

        if not event.get("new_location"):
            continue

        events_by_user.setdefault(user, []).append(event)

    failed_users = {
        str(event.get("user", "")).lower().strip()
        for event in failed_signin_events
        if event.get("status") == "failure"
    }

    mailbox_context_users = {
        str(event.get("user", "")).lower().strip()
        for event in mailbox_events
        if event.get("operation") in MAILBOX_CONFIGURATION_OPERATIONS
    }

    for user, user_events in events_by_user.items():
        if len(user_events) < 3:
            continue

        normalized_user = str(user).lower().strip()

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

        event_count = len(user_events)
        location_count = len(locations)
        ip_count = len(ip_addresses)

        has_failed_context = normalized_user in failed_users
        has_mailbox_context = normalized_user in mailbox_context_users
        has_suspicious_context = has_suspicious_signin_context(user_events)

        if has_mailbox_context:
            severity = "high"
            reason = "new-location burst paired with mailbox activity"

        elif location_count >= 2 or ip_count >= 2:
            severity = "high"
            reason = "multiple new locations or IP addresses"

        elif has_suspicious_context:
            severity = "medium"
            reason = "new-location burst paired with suspicious sign-in context"

        elif has_failed_context:
            severity = "medium"
            reason = "new-location burst paired with failed sign-in context"

        else:
            severity = "low"
            reason = "repeated successful sign-ins from one new location and one IP"

        alerts.append({
            "severity": severity,
            "type": "New Location Sign-in Burst",
            "user": user,
            "detail": (
                f"{event_count} successful sign-in(s) from new location activity. "
                f"Reason: {reason}. "
                f"Locations: {', '.join(sorted(locations))}. "
                f"IP address(es): {', '.join(sorted(ip_addresses))}. "
                f"Apps: {', '.join(sorted(apps))}."
            ),
            "location": ", ".join(sorted(locations)),
            "source": "Entra Sign-In Logs",
        })

    return alerts

def has_suspicious_signin_context(events):
    """
    Return True if any sign-in event has suspicious client or risk context.

    This is intentionally conservative.

    Current signals:
    - Python Requests / automation-style user agent
    - device code flow
    - medium/high risk level
    - conditional access failure
    - risky sign-in details present

    This helps elevate single-IP new-location bursts when the sign-in itself has
    stronger compromise indicators.
    """

    for event in events:
        raw_text = str(event.get("raw", "")).lower()

        for indicator in SUSPICIOUS_SIGNIN_TEXT_INDICATORS:
            if indicator in raw_text:
                return True

        risk_level = str(
            event.get("risk_level_aggregated")
            or event.get("risk_level")
            or ""
        ).lower()

        if risk_level in RISKY_SIGNIN_LEVELS:
            return True

        conditional_access_status = str(
            event.get("conditional_access_status", "")
        ).lower()

        if conditional_access_status == "failure":
            return True

        risk_detail = str(event.get("risk_detail", "")).lower()

        if risk_detail and risk_detail not in {
            "none",
            "hidden",
            "unknown",
        }:
            return True

    return False