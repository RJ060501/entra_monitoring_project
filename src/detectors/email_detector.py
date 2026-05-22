"""
Email detector module.

This module evaluates Microsoft 365 / Exchange audit events and generates
alerts for mailbox behaviors commonly seen during account compromise.

Current focus:
- mailbox rule creation/modification/removal
- forwarding or redirect behavior
- forwarding to external domains
- rules targeting sensitive business/security keywords
- rules that hide, delete, archive, or mark messages as read
"""

import re

from config.settings import SUPPRESSED_USERS, INTERNAL_DOMAINS


# Mailbox and transport rule operations we care about.
SUSPICIOUS_EMAIL_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Set-Mailbox",
    "New-TransportRule",
    "Set-TransportRule",
}


# Forwarding/redirect fields commonly seen in Exchange audit payloads.
FORWARDING_KEYWORDS = [
    "forward",
    "forwardto",
    "forwardasattachmentto",
    "redirectto",
    "delivertomailboxandforward",
    "forwardingaddress",
    "forwardingsmtpaddress",
]


# Keywords tied to your common business/email compromise patterns.
SENSITIVE_KEYWORDS = [
    "mfa",
    "password",
    "security",
    "docusign",
    "sharepoint",
    "invoice",
    "payroll",
    "wire",
    "teams",
]


# Keywords that suggest rules are hiding, deleting, moving, or suppressing mail.
HIDE_OR_DELETE_KEYWORDS = [
    "deleted",
    "archive",
    "rss",
    "junk",
    "markasread",
    "move",
]


def detect_email_events(events):
    """Run all email event detectors and return combined alerts."""
    alerts = []

    # alerts += detect_mailbox_rule_changes(events)
    # alerts += detect_forwarding_changes(events)
    alerts += detect_external_forwarding(events)
    # alerts += detect_sensitive_keyword_rules(events)
    alerts += detect_hide_or_delete_rules(events)

    return alerts


def get_raw_text(event):
    """Return lowercased raw event text for easy keyword searching."""
    return str(event.get("raw", "")).lower()


def extract_email_addresses(text):
    """Extract email addresses from raw audit event text."""
    return re.findall(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        text,
    )


def is_external_email(address):
    """Return True if an email address is outside the internal domain list."""
    if not address or "@" not in address:
        return False

    domain = address.split("@")[-1].lower()
    return domain not in INTERNAL_DOMAINS


def matched_keywords(text, keywords):
    """Return all keywords found inside text."""
    return [
        keyword
        for keyword in keywords
        if keyword.lower() in text
    ]


def is_rule_related_operation(operation):
    """Return True if the audit operation is related to mailbox/transport rules."""
    return operation in SUSPICIOUS_EMAIL_OPERATIONS

def get_sensitive_keyword_matches(event):
    """
    Return sensitive keywords found inside the raw audit event.

    These keywords are not automatically malicious by themselves,
    but they add important context to mailbox rule detections.
    """
    raw_text = get_raw_text(event)

    return matched_keywords(raw_text, SENSITIVE_KEYWORDS)

# Use later for context and dashboard metrics
def detect_mailbox_rule_changes(events):
    """Detect mailbox rule creation/modification/removal events."""
    alerts = []

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        operation = event.get("operation", "")

        if operation in {"New-InboxRule", "Set-InboxRule", "Remove-InboxRule"}:
            alerts.append({
                "severity": "medium",
                "type": "Mailbox Rule Changed",
                "user": user,
                "detail": (
                    f"Mailbox rule operation detected: {operation}. "
                    f"Target: {event.get('target', 'Unknown')}"
                ),
                "location": "N/A - Exchange audit event",
                "source": "Microsoft 365 Audit Logs",
            })

    return alerts


def detect_forwarding_changes(events):
    """
    Deprecated / not currently used.

    This function alerts on any forwarding-related keyword, even if the rule
    only forwards internally. That created extra noise during testing.

    The active forwarding detector is detect_external_forwarding(), which checks
    whether the forwarding recipient is outside INTERNAL_DOMAINS.
    """
    return []


def detect_external_forwarding(events):
    """
    Detect forwarding/redirect behavior involving external email addresses.

    Severity:
    - Critical because external forwarding is a common account-compromise tactic.

    Sensitive keywords are included as extra context if present.
    """
    alerts = []

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        operation = event.get("operation", "")
        raw_text = get_raw_text(event)

        if operation not in {"New-InboxRule", "Set-InboxRule", "Set-Mailbox"}:
            continue

        forwarding_matches = matched_keywords(raw_text, FORWARDING_KEYWORDS)

        if not forwarding_matches:
            continue

        email_addresses = extract_email_addresses(raw_text)

        external_addresses = [
            address
            for address in email_addresses
            if is_external_email(address)
        ]

        if not external_addresses:
            continue

        keyword_matches = get_sensitive_keyword_matches(event)

        keyword_context = ""
        if keyword_matches:
            keyword_context = (
                f" Sensitive keyword(s): {', '.join(sorted(set(keyword_matches)))}."
            )

        alerts.append({
            "severity": "critical",
            "type": "External Mail Forwarding Detected",
            "user": user,
            "detail": (
                f"Mailbox rule forwards emails outside the organization to: "
                f"{', '.join(sorted(set(external_addresses)))}. "
                f"Forwarding term(s): {', '.join(sorted(set(forwarding_matches)))}. "
                f"Operation: {operation}. "
                f"Target: {event.get('target', 'Unknown')}."
                f"{keyword_context}"
            ),
            "location": "N/A - Exchange audit event",
            "source": "Microsoft 365 Audit Logs",
        })

    return alerts


def detect_sensitive_keyword_rules(events):
    """
    Deprecated / not currently used.

    Sensitive keywords alone are not considered suspicious.
    Keywords are now used as enrichment context inside stronger detections
    such as external forwarding or hide/delete mailbox rules.
    """
    return []


def detect_hide_or_delete_rules(events):
    """
    Detect rules that may hide, delete, archive, move, or suppress emails.

    Severity:
    - High by default.
    - Still high when sensitive keywords are present, but the detail becomes
      more useful because it shows what business/security topic was targeted.

    Examples:
    - Move DocuSign emails to Junk
    - Mark MFA emails as read
    - Move invoice emails to RSS
    """
    alerts = []

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        operation = event.get("operation", "")
        raw_text = get_raw_text(event)

        if not is_rule_related_operation(operation):
            continue

        hide_delete_matches = matched_keywords(raw_text, HIDE_OR_DELETE_KEYWORDS)

        if not hide_delete_matches:
            continue

        keyword_matches = get_sensitive_keyword_matches(event)

        keyword_context = ""
        if keyword_matches:
            keyword_context = (
                f" Sensitive keyword(s): {', '.join(sorted(set(keyword_matches)))}."
            )

        alerts.append({
            "severity": "high",
            "type": "Mailbox Rule May Hide or Delete Mail",
            "user": user,
            "detail": (
                f"Mailbox rule/configuration event contains hide/delete "
                f"term(s): {', '.join(sorted(set(hide_delete_matches)))}. "
                f"Operation: {operation}. "
                f"Target: {event.get('target', 'Unknown')}."
                f"{keyword_context}"
            ),
            "location": "N/A - Exchange audit event",
            "source": "Microsoft 365 Audit Logs",
        })

    return alerts