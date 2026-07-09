"""
Correlation Detector

This detector looks for suspicious combinations of activity across different
Microsoft 365 data sources.

The main V1 use case is:

1. Suspicious Entra sign-in activity
2. Mailbox rule or forwarding activity
3. Both events happening close enough together to suggest possible email
   account compromise

Why this matters:
Attackers commonly create inbox rules after compromising a mailbox. These rules
may hide, delete, move, mark-as-read, or forward security warnings and phishing
replies.

This file does not fetch data directly. It expects normalized events from:
- Entra sign-in logs
- Microsoft 365 / Exchange audit logs
"""

from datetime import datetime, timezone

from core.security_constants import (
    MAILBOX_CONFIGURATION_OPERATIONS,
    FORWARDING_KEYWORDS,
    HIDE_OR_DELETE_KEYWORDS,
    RISKY_SIGNIN_LEVELS,
    SUSPICIOUS_SIGNIN_TEXT_INDICATORS,
)

from utils.time_utils import format_mountain_time


def parse_datetime(value):
    """
    Parse a Microsoft datetime value into a timezone-aware datetime object.

    Microsoft timestamps are usually UTC and often end with Z.

    Some normalized events may have timestamps without timezone information.
    When that happens, we assume UTC because Microsoft Graph and M365 audit logs
    are UTC-based.

    Returns None if the timestamp is missing or invalid.
    """
    if not value:
        return None

    try:
        parsed_datetime = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        # If the datetime has no timezone info, treat it as UTC.
        if parsed_datetime.tzinfo is None:
            parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)

        return parsed_datetime

    except ValueError:
        return None


def minutes_between(first_time, second_time):
    """
    Return the absolute number of minutes between two datetime values.

    This is used to calculate how close a suspicious sign-in was to mailbox
    rule or forwarding activity.
    """
    if not first_time or not second_time:
        return None

    return abs((second_time - first_time).total_seconds()) / 60


def normalize_user(value):
    """
    Normalize a username or email address for reliable comparisons.
    """
    return str(value or "").lower().strip()


def get_event_text(event):
    """
    Convert an event into lowercase searchable text.

    This lets the detector search across the full normalized event for important
    terms like forwarding, delete, mark-as-read, move-to-folder, device code,
    python-requests, and other indicators.
    """
    return str(event or "").lower()


def get_suspicious_signins(signin_events):
    """
    Return sign-in events that have suspicious context.

    This function is intentionally broader than a single detector rule because
    correlation needs context. A sign-in may be suspicious because it failed,
    came from a new location, used a risky sign-in level, had a conditional
    access issue, or included suspicious text indicators.
    """
    suspicious_signins = []

    for event in signin_events or []:
        if is_suspicious_signin(event):
            suspicious_signins.append(event)

    return suspicious_signins


def is_suspicious_signin(event):
    """
    Decide whether a sign-in event is suspicious enough to use in correlation.

    This does not necessarily mean the sign-in is malicious by itself. It means
    the sign-in has enough risk context that it should be correlated with
    mailbox activity.
    """
    event_text = get_event_text(event)

    status = str(event.get("status", "")).lower().strip()
    conditional_access_status = str(
        event.get("conditional_access_status", "")
    ).lower().strip()
    risk_level = str(event.get("risk_level", "")).lower().strip()
    risk_level_aggregated = str(
        event.get("risk_level_aggregated", "")
    ).lower().strip()

    if status == "failure":
        return True

    if event.get("new_location"):
        return True

    if risk_level in RISKY_SIGNIN_LEVELS:
        return True

    if risk_level_aggregated in RISKY_SIGNIN_LEVELS:
        return True

    if conditional_access_status in {"failure", "reportonlyfailure"}:
        return True

    for indicator in SUSPICIOUS_SIGNIN_TEXT_INDICATORS:
        if indicator.lower() in event_text:
            return True

    return False


def get_email_event_behavior(email_event):
    """
    Classify the mailbox activity behavior.

    The returned behavior is used to determine alert severity.

    Possible return values:
    - external_forwarding
    - hide_delete_rule
    - generic_mailbox_rule
    - removed_mailbox_rule
    - None
    """
    operation = str(email_event.get("operation", "")).strip()
    event_text = get_event_text(email_event)

    if operation not in MAILBOX_CONFIGURATION_OPERATIONS:
        return None

    for keyword in FORWARDING_KEYWORDS:
        if keyword.lower() in event_text:
            return "external_forwarding"

    for keyword in HIDE_OR_DELETE_KEYWORDS:
        if keyword.lower() in event_text:
            return "hide_delete_rule"

    if operation == "Remove-InboxRule":
        return "removed_mailbox_rule"

    if operation in {"New-InboxRule", "Set-InboxRule", "Set-Mailbox"}:
        return "generic_mailbox_rule"

    return None


def is_mailbox_rule_or_forwarding_event(email_event):
    """
    Return True when an Exchange audit event is relevant for mailbox compromise
    correlation.
    """
    return get_email_event_behavior(email_event) is not None


def get_correlation_result(mailbox_behavior, time_difference_minutes):
    """
    Decide whether a suspicious sign-in and mailbox event should create an alert.

    The closer the mailbox rule activity happens to suspicious sign-in activity,
    the more severe the alert.

    V1 severity logic:
    - External forwarding within 24 hours: CRITICAL
    - Hide/delete rule within 60 minutes: CRITICAL
    - Hide/delete rule within 24 hours: HIGH
    - Generic mailbox rule within 60 minutes: HIGH
    - Generic mailbox rule within 24 hours: MEDIUM
    - Removed inbox rule within 60 minutes: MEDIUM
    """
    if time_difference_minutes is None:
        return None

    if mailbox_behavior == "external_forwarding":
        if time_difference_minutes <= 1440:
            return {
                "severity": "critical",
                "reason": "Suspicious sign-in + mailbox forwarding activity within 24 hours",
            }

    if mailbox_behavior == "hide_delete_rule":
        if time_difference_minutes <= 60:
            return {
                "severity": "critical",
                "reason": "Suspicious sign-in + mailbox hide/delete rule within 60 minutes",
            }

        if time_difference_minutes <= 1440:
            return {
                "severity": "high",
                "reason": "Suspicious sign-in + mailbox hide/delete rule within 24 hours",
            }

    if mailbox_behavior == "generic_mailbox_rule":
        if time_difference_minutes <= 60:
            return {
                "severity": "high",
                "reason": "Suspicious sign-in + mailbox rule activity within 60 minutes",
            }

        if time_difference_minutes <= 1440:
            return {
                "severity": "medium",
                "reason": "Suspicious sign-in + mailbox rule activity within 24 hours",
            }

    if mailbox_behavior == "removed_mailbox_rule":
        if time_difference_minutes <= 60:
            return {
                "severity": "medium",
                "reason": "Suspicious sign-in + inbox rule removal within 60 minutes",
            }

    return None


def detect_signin_email_correlation(signin_events, email_events):
    """
    Correlate suspicious sign-ins with mailbox rule/forwarding activity.

    This function compares suspicious sign-ins and suspicious mailbox events for
    the same user. If the events are close enough together, it creates a
    compromise-style alert.

    Mountain Time display:
    - Microsoft timestamps stay UTC internally.
    - The alert detail also includes Mountain Time for readability.
    """
    alerts = []

    suspicious_signins = get_suspicious_signins(signin_events)

    mailbox_events = [
        event
        for event in email_events or []
        if is_mailbox_rule_or_forwarding_event(event)
    ]

    for signin_event in suspicious_signins:
        signin_user = normalize_user(signin_event.get("user"))
        signin_datetime = parse_datetime(signin_event.get("created_datetime"))

        if not signin_user or not signin_datetime:
            continue

        for email_event in mailbox_events:
            email_user = normalize_user(email_event.get("user"))
            email_datetime = parse_datetime(email_event.get("created_datetime"))

            if not email_user or not email_datetime:
                continue

            if signin_user != email_user:
                continue

            mailbox_behavior = get_email_event_behavior(email_event)

            if not mailbox_behavior:
                continue

            time_difference_minutes = minutes_between(
                signin_datetime,
                email_datetime,
            )

            correlation_result = get_correlation_result(
                mailbox_behavior=mailbox_behavior,
                time_difference_minutes=time_difference_minutes,
            )

            if not correlation_result:
                continue

            rounded_time_difference = round(time_difference_minutes, 1)

            signin_time_utc = signin_event.get("created_datetime", "Unknown")
            mailbox_time_utc = email_event.get("created_datetime", "Unknown")

            signin_time_mountain = format_mountain_time(signin_time_utc)
            mailbox_time_mountain = format_mountain_time(mailbox_time_utc)

            signin_app = signin_event.get("app_display_name", "Unknown")
            signin_ip = signin_event.get("ip_address", "Unknown")
            signin_location = signin_event.get("location", "Unknown")

            email_operation = email_event.get("operation", "Unknown")
            email_target = email_event.get("target", "Unknown")

            alerts.append({
                "severity": correlation_result["severity"],
                "type": "Possible Email Account Compromise",
                "user": signin_user,
                "location": signin_location,
                "source": "Correlation: Entra Sign-In Logs + M365 Audit Logs",

                # Human-readable alert detail for Teams.
                "detail": (
                    "Suspicious sign-in activity was correlated with mailbox "
                    "rule/forwarding activity. "
                    f"Correlation window: {correlation_result['reason']}. "
                    f"Time difference: {rounded_time_difference} minutes. "
                    f"Suspicious sign-in time: {signin_time_mountain} Mountain Time "
                    f"({signin_time_utc} UTC). "
                    f"Mailbox activity time: {mailbox_time_mountain} Mountain Time "
                    f"({mailbox_time_utc} UTC). "
                    f"Sign-in app: {signin_app}. "
                    f"Sign-in IP: {signin_ip}. "
                    f"Sign-in location: {signin_location}. "
                    f"Email operation: {email_operation}. "
                    f"Mailbox behavior: {mailbox_behavior}. "
                    f"Target: {email_target}."
                ),

                # Structured fields for security_alert_history.json and future V2 use.
                "correlation_reason": correlation_result["reason"],
                "time_difference_minutes": rounded_time_difference,
                "signin_time_mountain": signin_time_mountain,
                "mailbox_activity_time_mountain": mailbox_time_mountain,
                "signin_time_utc": signin_time_utc,
                "mailbox_activity_time_utc": mailbox_time_utc,
                "signin_app": signin_app,
                "signin_ip": signin_ip,
                "signin_location": signin_location,
                "email_operation": email_operation,
                "mailbox_behavior": mailbox_behavior,
                "email_target": email_target,
            })

    return alerts


def detect_correlations(
    signin_events,
    email_events,
    cached_signins=None,
    cached_email_events=None,
):
    """
    Run all correlation detections.

    This supports both same-run and cross-run correlation.

    Same-run correlation:
    - New sign-ins compared with new email audit events.

    Cross-run correlation:
    - Cached suspicious sign-ins compared with new email audit events.
    - New sign-ins compared with cached mailbox events.

    We intentionally avoid cached-signins to cached-email-events because that can
    repeatedly alert on old activity every scheduled run.
    """
    alerts = []

    signin_events = signin_events or []
    email_events = email_events or []
    cached_signins = cached_signins or []
    cached_email_events = cached_email_events or []

    # Same-run correlation.
    alerts.extend(
        detect_signin_email_correlation(
            signin_events=signin_events,
            email_events=email_events,
        )
    )

    # Cross-run correlation:
    # suspicious sign-ins from a previous run + newly arrived mailbox activity.
    alerts.extend(
        detect_signin_email_correlation(
            signin_events=cached_signins,
            email_events=email_events,
        )
    )

    # Cross-run correlation:
    # newly arrived sign-ins + mailbox activity from a previous run.
    alerts.extend(
        detect_signin_email_correlation(
            signin_events=signin_events,
            email_events=cached_email_events,
        )
    )

    return alerts