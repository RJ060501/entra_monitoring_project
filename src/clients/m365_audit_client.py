"""
Microsoft 365 Audit Client

This will eventually retrieve Microsoft 365 unified audit log events.

Important:
- Entra sign-in logs come from Microsoft Graph /auditLogs/signIns
- Mailbox rule and forwarding events come from Microsoft 365 unified audit logs
- For regular programmatic collection, Microsoft recommends the Microsoft 365
  Management Activity API.
"""


class M365AuditClient:
    def __init__(self, settings):
        self.settings = settings

    def get_email_audit_events(self):
        """
        Placeholder until we wire in Microsoft 365 Management Activity API.

        Expected normalized event shape:
        {
            "id": "...",
            "created_datetime": "...",
            "user": "user@company.com",
            "operation": "New-InboxRule",
            "target": "mailbox or rule target",
            "location": "Unknown",
            "raw": {...}
        }
        """
        return []