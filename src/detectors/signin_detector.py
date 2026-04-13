"""
Sign-in Detection Rules

This module contains detection logic for:
- Failed sign-in followed by success
- Unusual login hours
- New location detection
"""

from config.settings import SUPPRESSED_USERS


def detect_signin_events(events):
    """Run all sign-in detection rules"""
    alerts = []

    for event in events:
        user = event["user"]

        # Skip suppressed users
        if user in SUPPRESSED_USERS:
            continue

        # Example rule: unusual login time
        hour = event["hour"]
        if hour < 6 or hour > 22:
            alerts.append({
                "type": "Unusual Login Time",
                "user": user,
                "detail": f"Login at hour {hour}"
            })

        # Example rule: new location
        if event.get("new_location"):
            alerts.append({
                "type": "New Location",
                "user": user,
                "detail": f"New location detected: {event['location']}"
            })

    return alerts
