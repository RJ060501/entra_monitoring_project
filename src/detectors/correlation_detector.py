"""
Correlation Detector

Detects suspicious combinations of events across multiple data sources.

Why correlation matters:
- A suspicious sign-in alone may be noisy.
- A mailbox rule alone may be legitimate.
- But a suspicious sign-in near mailbox rule, forwarding, or hide/delete
  activity is much more concerning and may indicate account compromise.

Current correlation logic:
- Same user
- Suspicious sign-in
- Mailbox rule / forwarding / hide-delete event
- Severity based on mailbox behavior and time distance

Important:
This file does not decide whether a single sign-in or single mailbox event is
bad by itself. It only correlates events that become more meaningful together.
"""

from datetime import datetime, timezone

from core.security_constants import (
    MAILBOX_CONFIGURATION_OPERATIONS,
    FORWARDING_KEYWORDS,
    HIDE_OR_DELETE_KEYWORDS,
    RISKY_SIGNIN_LEVELS,
    SUSPICIOUS_SIGNIN_TEXT_INDICATORS,
)


CRITICAL_CORRELATION_WINDOW_MINUTES = 60
HIGH_CONFIDENCE_CORRELATION_WINDOW_MINUTES = 1440


def parse_datetime(value):
    """
    Convert a Microsoft timestamp string into a timezone-aware UTC datetime.

    Microsoft APIs may return timestamps in slightly different formats:
    - 2026-05-14T20:00:00Z
    - 2026-05-14T20:00:00
    - 2026-05-14T20:00:00+00:00

    Python cannot compare or subtract timezone-aware and timezone-naive
    datetimes. This function normalizes everything to timezone-aware UTC.
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def minutes_between(first_time, second_time):
    """
    Return the absolute time difference between two datetime objects in minutes.
    """
    return abs((second_time - first_time).total_seconds()) / 60


def normalize_user(value):
    """
    Normalize a user identifier for same-user comparisons.
    """
    return str(value or "").lower().strip()


def get_event_text(event):
    """
    Build lowercase searchable text from an event.

    Some normalized events may have only raw payload text, while others may
    expose fields such as app_display_name, user_agent, or client_app. Combining
    these makes suspicious indicator checks more reliable without needing every
    client normalizer to expose identical fields.
    """
    searchable_parts = [
        event.get("raw", ""),
        event.get("app_display_name", ""),
        event.get("user_agent", ""),
        event.get("client_app", ""),
        event.get("original_transfer_method", ""),
        event.get("risk_detail", ""),
    ]

    return " ".join(str(part) for part in searchable_parts).lower()


def get_suspicious_signins(signin_events):
    """
    Return only sign-in events that are suspicious enough for correlation.
    """
    return [
        event for event in signin_events
        if is_suspicious_signin(event)
    ]


def is_suspicious_signin(event):
    """
    Decide whether a sign-in event is suspicious enough to use in correlation.

    This does not create an alert by itself.
    It only marks a sign-in as suspicious context for mailbox-related activity.
    """
    status = str(event.get("status", "")).lower()
    hour = event.get("hour")

    risk_level = str(
        event.get("risk_level_aggregated")
        or event.get("risk_level")
        or ""
    ).lower()

    conditional_access_status = str(
        event.get("conditional_access_status", "")
    ).lower()

    event_text = get_event_text(event)

    if status == "failure":
        return True

    if event.get("new_location"):
        return True

    # Microsoft Graph sign-in timestamps are UTC.
    # This roughly maps to suspicious overnight activity for many U.S. users.
    if status == "success" and hour is not None and (7 <= hour <= 10):
        return True

    if risk_level in RISKY_SIGNIN_LEVELS:
        return True

    if conditional_access_status == "failure":
        return True

    for indicator in SUSPICIOUS_SIGNIN_TEXT_INDICATORS:
        if indicator in event_text:
            return True

    return False


def get_email_event_behavior(email_event):
    """
    Classify mailbox configuration events for correlation.

    Important:
    Only mailbox rule/configuration operations should be correlated.

    Normal mailbox activity like MailItemsAccessed, Send, Update, Create,
    AttachmentAccess, MoveToDeletedItems, etc. should not become correlation
    alerts here. Those should be handled by separate detectors if needed.
    """
    operation = email_event.get("operation", "")
    raw_text = str(email_event.get("raw", "")).lower()

    if operation not in MAILBOX_CONFIGURATION_OPERATIONS:
        return "unknown"

    if any(term in raw_text for term in FORWARDING_KEYWORDS):
        return "external_forwarding"

    if any(term in raw_text for term in HIDE_OR_DELETE_KEYWORDS):
        return "hide_delete_rule"

    if operation in {"New-InboxRule", "Set-InboxRule", "Set-Mailbox"}:
        return "generic_mailbox_rule"

    if operation == "Remove-InboxRule":
        return "removed_mailbox_rule"

    return "unknown"


def is_mailbox_rule_or_forwarding_event(event):
    """
    Decide whether an email audit event is worth considering for correlation.

    Remove-InboxRule is kept as context, but it intentionally receives lower
    severity than forwarding or hide/delete behavior.
    """
    behavior = get_email_event_behavior(event)

    return behavior in {
        "external_forwarding",
        "hide_delete_rule",
        "generic_mailbox_rule",
        "removed_mailbox_rule",
    }


def get_correlation_result(signin_event, email_event, minutes_difference):
    """
    Determine correlation severity based on:
    - mailbox behavior type
    - time distance between sign-in and mailbox activity

    signin_event is accepted for future tuning. For example, later we may
    increase severity when a correlated sign-in used device code flow,
    suspicious automation clients, or impossible travel.
    """
    behavior = get_email_event_behavior(email_event)

    if behavior == "external_forwarding":
        if minutes_difference <= HIGH_CONFIDENCE_CORRELATION_WINDOW_MINUTES:
            return (
                "critical",
                "Suspicious sign-in + external forwarding within 24 hours",
            )

    if behavior == "hide_delete_rule":
        if minutes_difference <= CRITICAL_CORRELATION_WINDOW_MINUTES:
            return (
                "critical",
                "Suspicious sign-in + mailbox hide/delete rule within 60 minutes",
            )

        if minutes_difference <= HIGH_CONFIDENCE_CORRELATION_WINDOW_MINUTES:
            return (
                "high",
                "Suspicious sign-in + mailbox hide/delete rule within 24 hours",
            )

    if behavior == "generic_mailbox_rule":
        if minutes_difference <= CRITICAL_CORRELATION_WINDOW_MINUTES:
            return (
                "high",
                "Suspicious sign-in + mailbox rule within 60 minutes",
            )

        if minutes_difference <= HIGH_CONFIDENCE_CORRELATION_WINDOW_MINUTES:
            return (
                "medium",
                "Suspicious sign-in + mailbox rule within 24 hours",
            )

    if behavior == "removed_mailbox_rule":
        if minutes_difference <= CRITICAL_CORRELATION_WINDOW_MINUTES:
            return (
                "medium",
                "Suspicious sign-in + mailbox rule removal within 60 minutes",
            )

    return None, None


def detect_signin_email_correlation(signin_events, email_events):
    """
    Detect suspicious sign-in activity correlated with mailbox rule, forwarding,
    or hide/delete activity for the same user.

    The caller decides whether signin_events and email_events are current-run
    events or cached events. This function only correlates the lists it receives.
    """
    alerts = []

    suspicious_signins = [
        event for event in signin_events
        if is_suspicious_signin(event)
    ]

    suspicious_email_events = [
        event for event in email_events
        if is_mailbox_rule_or_forwarding_event(event)
    ]

    for signin in suspicious_signins:
        signin_user = normalize_user(signin.get("user"))
        signin_time = parse_datetime(signin.get("created_datetime"))

        if not signin_user or not signin_time:
            continue

        for email_event in suspicious_email_events:
            email_user = normalize_user(email_event.get("user"))
            email_time = parse_datetime(email_event.get("created_datetime"))

            if not email_user or not email_time:
                continue

            if signin_user != email_user:
                continue

            minutes_diff = minutes_between(signin_time, email_time)

            severity, window_label = get_correlation_result(
                signin_event=signin,
                email_event=email_event,
                minutes_difference=minutes_diff,
            )

            if not severity:
                continue

            alerts.append({
                "severity": severity,
                "type": "Possible Email Account Compromise",
                "user": signin.get("user", "Unknown"),
                "detail": (
                    f"Suspicious sign-in activity was correlated with mailbox "
                    f"rule/forwarding activity. "
                    f"Correlation window: {window_label}. "
                    f"Time difference: {round(minutes_diff, 1)} minutes. "
                    f"Sign-in app: {signin.get('app_display_name', 'Unknown')}. "
                    f"Sign-in IP: {signin.get('ip_address', 'Unknown')}. "
                    f"Sign-in location: {signin.get('location', 'Unknown')}. "
                    f"Email operation: {email_event.get('operation', 'Unknown')}. "
                    f"Mailbox behavior: {get_email_event_behavior(email_event)}. "
                    f"Target: {email_event.get('target', 'Unknown')}."
                ),
                "location": signin.get("location", "Unknown"),
                "source": "Correlation: Entra Sign-In Logs + M365 Audit Logs",
            })

    return alerts


def detect_correlations(
    signin_events,
    email_events,
    cached_signins=None,
    cached_email_events=None,
):
    """
    Main correlation detector entry point.

    signin_events:
        New sign-ins from this run.

    email_events:
        New email audit events from this run.

    cached_signins:
        Suspicious sign-ins from previous runs.

    cached_email_events:
        Mailbox rule / forwarding / hide-delete activity from previous runs.

    Important:
        To avoid repeated cached-to-cached alerts every run, main.py should
        call this in two passes:

        1. cached suspicious sign-ins + new email events
        2. new sign-ins + cached mailbox events

        Avoid calling it with both cached_signins and cached_email_events unless
        pair-level deduplication is added later.
    """
    cached_signins = cached_signins or []
    cached_email_events = cached_email_events or []

    combined_signins = cached_signins + signin_events
    combined_email_events = cached_email_events + email_events

    return detect_signin_email_correlation(
        signin_events=combined_signins,
        email_events=combined_email_events,
    )