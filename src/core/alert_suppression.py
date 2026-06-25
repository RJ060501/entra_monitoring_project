"""
Alert Suppression

Prevents the same Teams-worthy alert from being sent repeatedly across
scheduled monitoring runs.

Why this exists:
- Some detectors use rolling caches.
- Cached conditions can remain true for 60-120 minutes.
- Without cross-run suppression, the same medium/high/critical alert can be
  regenerated every 15 minutes.
- This module suppresses repeated notifications for the same alert fingerprint
  within a short suppression window.

This does not replace detector tuning.

Detector files decide:
- Is this behavior suspicious?
- What severity should it have?

This file decides:
- Have we already notified people about this same condition recently?
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
SUPPRESSION_FILE = STATE_DIR / "recent_alert_suppression.json"

DEFAULT_SUPPRESSION_WINDOW_MINUTES = 120

SUPPRESSIBLE_SEVERITIES = {
    "medium",
    "high",
    "critical",
}


def parse_datetime(value):
    """
    Parse an ISO datetime string.

    Returns None when the value is missing or invalid.
    """
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def load_recent_alert_suppression():
    """
    Load recent alert suppression entries.

    The file is intentionally separate from security_alert_history.json.

    security_alert_history.json:
    - readable investigation history

    recent_alert_suppression.json:
    - short-lived operational suppression memory
    """
    STATE_DIR.mkdir(exist_ok=True)

    if not SUPPRESSION_FILE.exists():
        return []

    try:
        with SUPPRESSION_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return []


def save_recent_alert_suppression(entries):
    """
    Save recent alert suppression entries.
    """
    STATE_DIR.mkdir(exist_ok=True)

    with SUPPRESSION_FILE.open("w", encoding="utf-8") as file:
        json.dump(entries, file, indent=2)


def build_alert_fingerprint(alert):
    """
    Build a stable fingerprint for repeat-alert suppression.

    We intentionally do not include the full alert detail. Counts can change
    slightly across cache-backed runs, but the underlying condition may be the
    same.

    This fingerprint suppresses repeats for the same:
    - alert type
    - user
    - severity
    - source
    - location

    Example:
    New Location Sign-in Burst | user@company.com | high | Entra Sign-In Logs |
    Ashburn, Virginia, US
    """
    return "|".join([
        str(alert.get("type", "")).lower().strip(),
        str(alert.get("user", "")).lower().strip(),
        str(alert.get("severity", "")).lower().strip(),
        str(alert.get("source", "")).lower().strip(),
        str(alert.get("location", "")).lower().strip(),
    ])


def prune_recent_alert_suppression(entries, window_minutes):
    """
    Remove old suppression entries outside the suppression window.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)

    kept_entries = []

    for entry in entries:
        last_seen_at = parse_datetime(entry.get("last_seen_at"))

        if not last_seen_at:
            continue

        if last_seen_at >= cutoff:
            kept_entries.append(entry)

    return kept_entries


def suppress_recent_alerts(
    alerts,
    window_minutes=DEFAULT_SUPPRESSION_WINDOW_MINUTES,
):
    """
    Split alerts into actionable alerts and suppressed repeat alerts.

    Only medium/high/critical alerts are suppressible. Low alerts are returned
    as actionable because Teams already skips them and they are useful for
    local console visibility.

    Returns:
    - actionable_alerts
    - suppressed_alerts
    """
    alerts = alerts or []

    recent_entries = load_recent_alert_suppression()
    recent_entries = prune_recent_alert_suppression(
        entries=recent_entries,
        window_minutes=window_minutes,
    )

    recent_fingerprints = {
        entry.get("fingerprint")
        for entry in recent_entries
    }

    actionable_alerts = []
    suppressed_alerts = []

    now_string = datetime.now(timezone.utc).isoformat()

    for alert in alerts:
        severity = str(alert.get("severity", "")).lower().strip()

        if severity not in SUPPRESSIBLE_SEVERITIES:
            actionable_alerts.append(alert)
            continue

        fingerprint = build_alert_fingerprint(alert)

        if fingerprint in recent_fingerprints:
            suppressed_alerts.append(alert)
            continue

        actionable_alerts.append(alert)

        recent_entries.append({
            "fingerprint": fingerprint,
            "last_seen_at": now_string,
            "type": alert.get("type"),
            "user": alert.get("user"),
            "severity": alert.get("severity"),
            "source": alert.get("source"),
            "location": alert.get("location"),
        })

        recent_fingerprints.add(fingerprint)

    save_recent_alert_suppression(recent_entries)

    return actionable_alerts, suppressed_alerts