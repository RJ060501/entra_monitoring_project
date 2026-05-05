from config.settings import SUPPRESSED_USERS


SUSPICIOUS_EMAIL_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Set-Mailbox",
    "New-TransportRule",
    "Set-TransportRule",
}


def detect_email_events(events):
    alerts = []

    alerts += detect_mailbox_rule_changes(events)
    alerts += detect_forwarding_changes(events)

    return alerts


def detect_mailbox_rule_changes(events):
    alerts = []

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        operation = event.get("operation", "")

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
    alerts = []

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