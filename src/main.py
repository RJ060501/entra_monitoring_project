"""
Main entry point for the Entra Monitoring Program.

This file ties together the full monitoring pipeline:
1. Load configuration from environment variables and optional .env file
2. Pull data (currently sample data, later Microsoft Graph API)
3. Run detection rules against sign-in and audit events
4. Deduplicate alerts
5. Send alerts to the console
6. Optionally send alerts to Microsoft Teams

Important:
- The program is still a single-run monitor.
- It does NOT run forever by itself.
- Later, we will run this repeatedly using systemd or cron.
"""

from clients.entra_client import EntraClient
from detectors.signin_detector import detect_signin_events
from detectors.audit_detector import detect_audit_events
from core.deduplicator import deduplicate_alerts
from notifiers.console_notifier import send_alerts as send_console_alerts
from notifiers.teams_notifier import send_alerts as send_teams_alerts
from config.settings import load_settings


def main():
    """Run one full monitoring cycle from start to finish."""

    settings = load_settings()

    client = EntraClient()

    signins = client.get_signins()
    audits = client.get_audits()

    alerts = []
    alerts += detect_signin_events(signins)
    alerts += detect_audit_events(audits)

    alerts = deduplicate_alerts(alerts)

    send_console_alerts(alerts)
    send_teams_alerts(alerts, settings)


if __name__ == "__main__":
    main()
