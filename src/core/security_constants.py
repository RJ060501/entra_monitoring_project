"""
Security Detection Constants

Centralized constants used by detectors, caches, and correlators.

Why this file exists:
- Avoid duplicating operation names across multiple files
- Keep cache logic and detector logic aligned
- Make future tuning safer and easier
- Provide one place to document why an operation is security-relevant

These are deterministic V1 values. V2/ML can add scoring later, but these
high-confidence operation groups should remain useful.
"""


# Mailbox configuration operations that are useful for account-compromise
# correlation.
#
# These are intentionally narrow. Do not add noisy message-level operations
# like MailItemsAccessed, MoveToDeletedItems, Create, Update, Send, etc. here.
#
# Message access/send-volume behavior should be handled by separate detectors
# and rolling windows, not by mailbox-rule correlation.
MAILBOX_CONFIGURATION_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Set-Mailbox",
}


# Inbox rule operations only.
#
# Useful when we specifically want to distinguish rule creation/modification
# from broader mailbox configuration changes like Set-Mailbox forwarding.
INBOX_RULE_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
}


# Mailbox-level forwarding/configuration operations.
#
# Set-Mailbox can include forwarding-related changes depending on the audit
# payload. The detector still needs to inspect event details/raw data to decide
# whether it is actually suspicious.
MAILBOX_FORWARDING_CONFIGURATION_OPERATIONS = {
    "Set-Mailbox",
}


# Keywords that suggest external forwarding behavior.
FORWARDING_KEYWORDS = {
    "forward",
    "forwardto",
    "forwardasattachmentto",
    "redirectto",
    "delivertomailboxandforward",
    "forwardingaddress",
    "forwardingsmtpaddress",
}


# Keywords that suggest a mailbox rule is hiding, deleting, moving, or marking
# messages in a way that could conceal attacker activity.
HIDE_OR_DELETE_KEYWORDS = {
    "deleted",
    "archive",
    "rss",
    "junk",
    "markasread",
    "mark as read",
    "markasjunk",
    "mark as junk",
    "delete",
    "deletemessage",
    "move",
    "movetofolder",
    "move to folder",
}


# Keywords often used in rules targeting sensitive or high-value business email.
SENSITIVE_EMAIL_KEYWORDS = {
    "mfa",
    "password",
    "security",
    "docusign",
    "sharepoint",
    "invoice",
    "payroll",
    "wire",
    "teams",
    "review",
    "approval",
    "urgent",
    "contract",
    "settlement",
    "canvas",
    "asap",
    "payment",
    "vendor",
    "nda",
}


# Suspicious sign-in text indicators.
#
# These are checked against raw sign-in payloads or normalized client/user-agent
# fields when available.
SUSPICIOUS_SIGNIN_TEXT_INDICATORS = {
    "python-requests",
    "devicecodeflow",
    "device code",
}

ALERT_SEVERITIES = {
    "medium",
    "high",
    "critical",
}

RISKY_SIGNIN_LEVELS = {
    "medium",
    "high",
    "critical",
}