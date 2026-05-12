"""
Correlation Detector

This file detects suspicious combinations of events across multiple data sources.

Why correlation matters:
- A suspicious sign-in alone may be noisy.
- A mailbox rule alone may be legitimate.
- But a suspicious sign-in followed by a mailbox rule/forwarding change is much
  more concerning and may indicate account compromise.

Current correlation rule:
- Same user
- Suspicious sign-in
- Mailbox rule or forwarding event
- Within 60 minutes
"""

from datetime import datetime, timezone


# Set of email audit operations that are considered suspicious because they
# can be used to create or modify mailbox rules.
SUSPICIOUS_EMAIL_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Set-Mailbox",
}


# List of keywords that, if found in the raw audit event data, indicate
# potential forwarding or redirection behavior.
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
    Convert a Microsoft timestamp string into a Python datetime object.

    If parsing fails, return None so the detector can safely skip that event.
    """
    if not value:
        return None

    try:
        # Microsoft timestamps end with 'Z' for UTC; replace it with '+00:00'
        # to make it compatible with Python's fromisoformat method.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def minutes_between(first_time, second_time):
    """
    Return the absolute difference between two datetime objects in minutes.
    """
    # Calculate the total seconds between the times, take absolute value,
    # and convert to minutes.
    return abs((second_time - first_time).total_seconds()) / 60


def is_suspicious_signin(event):
    """
    Decide whether a sign-in event is suspicious enough to correlate.

    Current logic:
    - failed sign-in events are suspicious context
    - successful sign-ins outside business hours are suspicious context

    Later we can add:
    - new IP
    - new device
    - new location
    - risky sign-in
    - conditional access failure
    """
    status = event.get("status")
    hour = event.get("hour")

    # Any failed sign-in is considered suspicious.
    if status == "failure":
        return True

    # Successful sign-ins before 6 AM or after 10 PM are also suspicious.
    if status == "success" and hour is not None and (hour < 6 or hour > 22):
        return True
    
    if risk_level in {"medium", "high"}:
        return True

    # Conditional Access failure is suspicious context.
    if conditional_access_status == "failure":
        return True

    return False


def is_mailbox_rule_or_forwarding_event(event):
    """
    Decide whether an email audit event looks related to mailbox rules or forwarding.

    We check both:
    - the operation name
    - the raw event body for forwarding-related keywords
    """
    operation = event.get("operation", "")
    raw_text = str(event.get("raw", "")).lower()

    # If the operation is in our suspicious set, it's a match.
    if operation in SUSPICIOUS_EMAIL_OPERATIONS:
        return True

    # Also check if any forwarding keywords appear in the raw event data.
    if any(keyword in raw_text for keyword in FORWARDING_KEYWORDS):
        return True

    return False


def detect_signin_email_correlation(signin_events, email_events, window_minutes=60):
    """
    Detect suspicious sign-in activity followed by mailbox rule/forwarding activity.

    Args:
        signin_events: List of normalized Entra sign-in events.
        email_events: List of normalized Microsoft 365 email audit events.
        window_minutes: Maximum time difference allowed between events.

    Returns:
        A list of high-confidence correlation alerts.
    """
    alerts = []

    # Filter the sign-in events to only include those that are suspicious.
    # This uses a list comprehension: for each event in signin_events,
    # include it in the new list if is_suspicious_signin(event) returns True.
    suspicious_signins = [
        event for event in signin_events
        if is_suspicious_signin(event)
    ]

    # Similarly, filter the email events to only include those that involve
    # mailbox rules or forwarding changes.
    suspicious_email_events = [
        event for event in email_events
        if is_mailbox_rule_or_forwarding_event(event)
    ]

    # Now, for each suspicious sign-in, check if there's a matching suspicious
    # email event for the same user within the time window.
    for signin in suspicious_signins:
        # Extract and normalize the user and timestamp from the sign-in event.
        signin_user = signin.get("user", "").lower()
        signin_time = parse_datetime(signin.get("created_datetime"))

        # Skip this sign-in if we can't parse the user or time.
        if not signin_user or not signin_time:
            continue

        # Check each suspicious email event against this sign-in.
        for email_event in suspicious_email_events:
            # Extract and normalize the user and timestamp from the email event.
            email_user = email_event.get("user", "").lower()
            email_time = parse_datetime(email_event.get("created_datetime"))

            # Skip this email event if we can't parse the user or time.
            if not email_user or not email_time:
                continue

            # Only correlate events for the same user.
            if signin_user != email_user:
                continue

            # Check if the events are within the allowed time window.
            if minutes_between(signin_time, email_time) <= window_minutes:
                # Create an alert for this correlation.
                alerts.append({
                    "severity": "critical",
                    "type": "Possible Email Account Compromise",
                    "user": signin.get("user", "Unknown"),
                    "detail": (
                        "Suspicious sign-in activity was correlated with "
                        "mailbox rule or forwarding activity within "
                        f"{window_minutes} minutes. "
                        f"Sign-in app: {signin.get('app_display_name', 'Unknown')}. "
                        f"Sign-in IP: {signin.get('ip_address', 'Unknown')}. "
                        f"Email operation: {email_event.get('operation', 'Unknown')}. "
                        f"Target: {email_event.get('target', 'Unknown')}."
                    ),
                    "location": signin.get("location", "Unknown"),
                    "source": "Correlation: Entra Sign-In Logs + M365 Audit Logs",
                })

    return alerts


def detect_correlations(signin_events, email_events):
    """
    Main correlation detector entry point.

    main.py should call this function once and pass in the new sign-in and
    new email audit events from the current run.
    """
    alerts = []

    # Call the specific correlation function with the default 60-minute window.
    alerts += detect_signin_email_correlation(
        signin_events=signin_events,
        email_events=email_events,
        window_minutes=60,
    )

    return alerts