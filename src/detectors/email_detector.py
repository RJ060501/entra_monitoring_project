"""
Email detector module.

This module evaluates Microsoft 365 email audit events and generates alerts
for suspicious mailbox configuration changes.

It currently checks for:
- mailbox rule creation/modification/removal
- potential forwarding or redirect rule behavior

Suppressed users are excluded from detection so trusted service accounts or
known administrative users can be ignored.
"""

from config.settings import SUPPRESSED_USERS


# These are the audit operations that indicate mailbox rule or mailbox-level
# configuration changes. They are used by the detector functions below.
SUSPICIOUS_EMAIL_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Set-Mailbox",
    "New-TransportRule",
    "Set-TransportRule",
}


def detect_email_events(events):
    """Run all email event detectors and return combined alerts."""
    alerts = []

    # Detect changes to mailbox rules.
    alerts += detect_mailbox_rule_changes(events)

    # Detect changes that indicate forwarding or redirection behavior.
    alerts += detect_forwarding_changes(events)

    return alerts


def detect_mailbox_rule_changes(events):
    """Detect mailbox rule creation/modification/removal events."""
    alerts = []

    for event in events:
        user = event.get("user", "Unknown")

        # Skip suppressed users so trusted or known accounts do not generate alerts.
        if user in SUPPRESSED_USERS:
            continue

        operation = event.get("operation", "")

        # Only consider explicit mailbox rule operations here.
        if operation in {"New-InboxRule", "Set-InboxRule", "Remove-InboxRule"}:
            alerts.append({
                "severity": "high",
                "type": "Mailbox Rule Changed",
                "user": user,
                "detail": (
                    f"Mailbox rule operation detected: {operation}. "
                    f"Target: {event.get('target', 'Unknown')}"
                ),
                "location": event.get("location", "Unknown"),
                "source": "Microsoft 365 Audit Logs",
            })

    return alerts


def detect_forwarding_changes(events):
    """Detect operations that may indicate mailbox forwarding or redirect rules."""
    alerts = []

    # Keywords that often appear in rule payloads when forwarding is configured.
    forwarding_keywords = [
        "Forward",
        "ForwardTo",
        "ForwardAsAttachmentTo",
        "RedirectTo",
        "DeliverToMailboxAndForward",
        "ForwardingAddress",
        "ForwardingSmtpAddress",
    ]

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        operation = event.get("operation", "")
        raw_text = str(event.get("raw", ""))

        # Only inspect operations that are likely to contain forwarding configuration.
        if operation in {"New-InboxRule", "Set-InboxRule", "Set-Mailbox"}:
            if any(keyword.lower() in raw_text.lower() for keyword in forwarding_keywords):
                alerts.append({
                    "severity": "critical",
                    "type": "Mailbox Forwarding or Redirect Rule",
                    "user": user,
                    "detail": (
                        f"Potential forwarding/redirect behavior detected. "
                        f"Operation: {operation}. "
                        f"Target: {event.get('target', 'Unknown')}"
                    ),
                    "location": event.get("location", "Unknown"),
                    "source": "Microsoft 365 Audit Logs",
                })

    return alerts