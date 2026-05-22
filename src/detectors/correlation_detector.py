"""
Correlation Detector

This file detects suspicious combinations of events across multiple data sources.

Why correlation matters:
- A suspicious sign-in alone may be noisy.
- A mailbox rule alone may be legitimate.
- But a suspicious sign-in followed by mailbox rule/forwarding activity is much
  more concerning and may indicate account compromise.

Current correlation logic:
- Same user
- Suspicious sign-in
- Mailbox rule or forwarding event
- Severity based on time gap:
    - 0–60 minutes: critical
    - 1–24 hours: high
    - 1–7 days: medium / investigation context
"""

from datetime import datetime, timezone


SUSPICIOUS_EMAIL_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
}


FORWARDING_KEYWORDS = [
    "forward",
    "forwardto",
    "forwardasattachmentto",
    "redirectto",
    "delivertomailboxandforward",
    "forwardingaddress",
    "forwardingsmtpaddress",
]


def parse_datetime(value):
    """
    Convert a Microsoft timestamp string into a timezone-aware UTC datetime.

    Microsoft APIs may return timestamps in slightly different formats:
    - 2026-05-14T20:00:00Z
    - 2026-05-14T20:00:00
    - 2026-05-14T20:00:00+00:00

    Python cannot compare/subtract timezone-aware and timezone-naive datetimes.
    This function normalizes everything to timezone-aware UTC.
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        # If timestamp has no timezone, assume it is UTC.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        # Normalize any timezone-aware value to UTC.
        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def minutes_between(first_time, second_time):
    """
    Return the absolute time difference between two datetime objects in minutes.
    """
    return abs((second_time - first_time).total_seconds()) / 60

def get_suspicious_signins(signin_events):
    """
    Return only sign-in events that are suspicious enough for correlation.
    """
    return [
        event for event in signin_events
        if is_suspicious_signin(event)
    ]

def get_correlation_severity(minutes_difference):
    """
    Decide alert severity based on how close together the suspicious sign-in
    and mailbox activity occurred.

    Timeline:
    - 0–60 minutes: critical
    - 1–24 hours: high
    - 1–7 days: medium
    - over 7 days: no correlation alert
    """
    if minutes_difference <= 60:
        return "critical", "0–60 minute critical window"

    if minutes_difference <= 1440:
        return "high", "1–24 hour high-confidence window"

    if minutes_difference <= 10080:
        return "medium", "1–7 day investigation/context window"

    return None, None


def is_suspicious_signin(event):
    """
    Decide whether a sign-in event is suspicious enough to use in correlation.

    This does not create an alert by itself.
    It only marks a sign-in as suspicious context for mailbox-related activity.
    """
    status = event.get("status")
    hour = event.get("hour")
    risk_level = event.get("risk_level_aggregated")
    conditional_access_status = event.get("conditional_access_status")

    if status == "failure":
        return True

    # Microsoft Graph sign-in timestamps are UTC.
    # This roughly maps to overnight U.S. login hours.
    if status == "success" and hour is not None and (7 <= hour <= 10):
        return True

    if risk_level in {"medium", "high"}:
        return True

    if conditional_access_status == "failure":
        return True

    return False


def is_mailbox_rule_or_forwarding_event(event):
    """
    Decide whether an email audit event is strong enough for correlation.

    We intentionally do NOT correlate generic operations like Update, Create,
    MailItemsAccessed, Send, or MoveToDeletedItems by themselves because they are noisy.

    Correlation should focus on higher-confidence mailbox configuration behavior.
    """
    operation = event.get("operation", "")
    raw_text = str(event.get("raw", "")).lower()

    if operation in {"New-InboxRule", "Set-InboxRule", "Remove-InboxRule", "Set-Mailbox"}:
        return True

    forwarding_terms_found = any(
        keyword in raw_text
        for keyword in FORWARDING_KEYWORDS
    )

    if forwarding_terms_found and operation in {"New-InboxRule", "Set-InboxRule", "Set-Mailbox"}:
        return True

    return False


def detect_signin_email_correlation(signin_events, email_events):
    """
    Detect suspicious sign-in activity correlated with mailbox rule/forwarding
    activity for the same user.

    This version assigns severity based on the timeline between the two events.
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
        signin_user = signin.get("user", "").lower()
        signin_time = parse_datetime(signin.get("created_datetime"))

        if not signin_user or not signin_time:
            continue

        for email_event in suspicious_email_events:
            email_user = email_event.get("user", "").lower()
            email_time = parse_datetime(email_event.get("created_datetime"))

            if not email_user or not email_time:
                continue

            if signin_user != email_user:
                continue

            minutes_diff = minutes_between(signin_time, email_time)
            severity, window_label = get_correlation_severity(minutes_diff)

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
                    f"Target: {email_event.get('target', 'Unknown')}."
                ),
                "location": signin.get("location", "Unknown"),
                "source": "Correlation: Entra Sign-In Logs + M365 Audit Logs",
            })

    return alerts


def detect_correlations(signin_events, email_events, cached_signins=None):
    """
    Main correlation detector entry point.

    signin_events:
        New sign-ins from this run.

    email_events:
        New email audit events from this run.

    cached_signins:
        Suspicious sign-ins from previous runs.
    """
    alerts = []

    cached_signins = cached_signins or []

    combined_signins = cached_signins + signin_events

    alerts += detect_signin_email_correlation(
        signin_events=combined_signins,
        email_events=email_events,
    )

    return alerts