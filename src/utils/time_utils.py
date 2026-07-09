"""
Time utilities for alert display.

Microsoft Graph and Microsoft 365 audit logs usually return timestamps in UTC.
For correlation math, UTC is best because it is consistent.

For human-readable alerts, we convert UTC timestamps to Mountain Time so the
IT team can quickly understand when an event actually happened locally.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo


MOUNTAIN_TIMEZONE = ZoneInfo("America/Denver")


def parse_microsoft_datetime(value):
    """
    Parse a Microsoft timestamp into a timezone-aware Python datetime.

    Microsoft commonly returns timestamps like:
    - 2026-07-08T15:30:45Z
    - 2026-07-08T15:30:45.123456Z
    - 2026-07-08T15:30:45+00:00

    Some normalized events may not include timezone information.
    When timezone information is missing, we assume UTC.
    """
    if not value:
        return None

    try:
        parsed_datetime = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        # If timezone information is missing, assume UTC.
        if parsed_datetime.tzinfo is None:
            parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)

        return parsed_datetime

    except ValueError:
        return None


def format_mountain_time(value):
    """
    Convert a Microsoft UTC timestamp into Mountain Time.

    This uses America/Denver, which automatically handles:
    - MST during standard time
    - MDT during daylight saving time
    """
    parsed_datetime = parse_microsoft_datetime(value)

    if not parsed_datetime:
        return "Unknown"

    mountain_datetime = parsed_datetime.astimezone(MOUNTAIN_TIMEZONE)

    return mountain_datetime.strftime("%Y-%m-%d %I:%M:%S %p %Z")