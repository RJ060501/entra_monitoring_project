"""
Manual Teams Alert Test

Run this file when you want to test the Teams notifier without waiting for
a real detector to generate an alert.
"""

import sys
from pathlib import Path

PROJECT_SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_SRC))

from config.settings import load_settings
from notifiers.teams_notifier import send_alerts

def main():
    settings = load_settings()

    test_alert = {
        "severity": "critical",
        "type": "Manual Test Alert",
        "user": "test.user@resolutgroup.com",
        "location": "Test Location",
        "source": "Manual Test",
        "detail": (
            "This is a manual test alert to verify the Microsoft Teams "
            "Adaptive Card formatting and webhook delivery."
        ),
    }

    send_alerts([test_alert], settings)


if __name__ == "__main__":
    main()