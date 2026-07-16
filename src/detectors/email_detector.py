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
from core.security_constants import (
    MAILBOX_CONFIGURATION_OPERATIONS,
    FORWARDING_KEYWORDS,
    SENSITIVE_EMAIL_KEYWORDS,
    HIDE_OR_DELETE_KEYWORDS,
)

def detect_email_events(events):
    """Run all email event detectors and return combined alerts."""
    alerts = []

    # alerts += detect_mailbox_rule_changes(events)
    # alerts += detect_forwarding_changes(events)
    alerts += detect_external_forwarding(events)
    # alerts += detect_sensitive_keyword_rules(events)
    alerts += detect_hide_or_delete_rules(events)

    return alerts

def clean_rule_target(target):
    """
    Return a cleaner rule name from the Exchange target value.

    Exchange audit targets can be very long, so this keeps Teams alerts readable.
    """
    if not target:
        return "Unknown"

    target = str(target)

    if "\\" in target:
        return target.split("\\")[-1]

    return target


def get_raw_text(event):
    """Return lowercased raw event text for easy keyword searching."""
    return str(event.get("raw", "")).lower()

#Remove later. For debugging if keywords are showing up in the right place inside the raw text.
def get_keyword_context(text, keywords, context_chars=80):
    """
    Return short snippets showing where sensitive keywords matched.

    This helps confirm whether a keyword appeared in the actual rule logic
    or somewhere else in the raw audit payload.
    """
    contexts = []

    lowered_text = str(text).lower()

    for keyword in keywords:
        keyword_lower = keyword.lower()
        index = lowered_text.find(keyword_lower)

        if index == -1:
            continue

        start = max(index - context_chars, 0)
        end = min(index + len(keyword_lower) + context_chars, len(text))

        snippet = str(text)[start:end].replace("\n", " ")

        contexts.append(f"{keyword}: ...{snippet}...")

    return contexts


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
    return operation in MAILBOX_CONFIGURATION_OPERATIONS

def get_sensitive_keyword_matches(event):
    """
    Return sensitive keywords found inside the raw audit event.

    These keywords are not automatically malicious by themselves,
    but they add important context to mailbox rule detections.
    """
    raw_text = get_raw_text(event)

    return matched_keywords(raw_text, SENSITIVE_EMAIL_KEYWORDS)

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
    Detect mailbox rules that may hide, delete, archive, move, or suppress emails.

    Severity logic:
    - move only = low/context
    - move + sensitive keyword = high
    - move + deleted/junk/archive/rss/markasread = high
    - hide/delete targeting sensitive keywords = high
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

        move_matches = matched_keywords(raw_text, ["move"])
        strong_matches = matched_keywords(raw_text, HIDE_OR_DELETE_KEYWORDS)
        sensitive_matches = get_sensitive_keyword_matches(event)
        #Temporary bug fix to confirm keywords are being pulled from the raw text in the right place. Remove later.
        keyword_context_snippets = get_keyword_context(
            str(event.get("raw", "")),
            sensitive_matches,
        )

        if not move_matches and not strong_matches:
            continue

        rule_name = clean_rule_target(event.get("target", "Unknown"))

        if strong_matches or (move_matches and sensitive_matches):
            severity = "low"
            severity_reason = ("standalone mailbox rule activity detected; severity reamins low  unless "
                               "correlated with suspicious sign-in activity"
                               )
        elif move_matches:
            severity = "low"
            severity_reason = "mailbox move rule detected without stronger compromise context"
        else:
            severity = "low"
            severity_reason = "mailbox rule activity detected without stronger compromise context"

        detail_parts = [
            f"Mailbox rule may move, hide, delete, archive, or suppress mail.",
            f"Rule: {rule_name}.",
            f"Operation: {operation}.",
        ]
        
        detail_parts.append(f"Severity reason: {severity_reason}.")

        if move_matches:
            detail_parts.append(
                f"Move term(s): {', '.join(sorted(set(move_matches)))}."
            )

        if strong_matches:
            detail_parts.append(
                f"Hide/delete term(s): {', '.join(sorted(set(strong_matches)))}."
            )

        if sensitive_matches:
            detail_parts.append(
                f"Sensitive keyword(s): {', '.join(sorted(set(sensitive_matches)))}."
            )
        #Temporary bug fix to confirm keywords are being pulled from the raw text in the right place. Remove later.
        if keyword_context_snippets:
            detail_parts.append(
                f"Keyword context: {' | '.join(keyword_context_snippets[:3])}."
            )

        alerts.append({
            "severity": severity,
            "type": "Mailbox Rule May Hide or Delete Mail",
            "user": user,
            "detail": " ".join(detail_parts),
            "location": "N/A - Exchange audit event",
            "source": "Microsoft 365 Audit Logs",
        })

    return alerts