"""
Audit Detection Rules

This module detects high-risk directory actions such as:
- Role assignments
- MFA resets
- Credential changes
"""

from config.settings import SUPPRESSED_USERS


def detect_audit_events(events):
    """Run audit detection rules"""
    alerts = []

    for event in events:
        user = event["user"]

        # Skip suppressed users
        if user in SUPPRESSED_USERS:
            continue

        # Example: high-risk action
        if event["action"] in ["Add role", "Reset MFA"]:
            alerts.append({
                "type": "High Risk Admin Action",
                "user": user,
                "detail": event["action"]
            })

    return alerts
