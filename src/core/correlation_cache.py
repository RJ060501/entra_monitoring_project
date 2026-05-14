"""
Correlation Cache

Stores recent suspicious sign-ins so they can be correlated with mailbox
activity in later runs.

Why this exists:
- The app runs every 15 minutes.
- A suspicious sign-in may happen in one run.
- A mailbox rule may appear in a later run.
- Without a cache, those events would not correlate.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
CACHE_FILE = STATE_DIR / "recent_suspicious_signins.json"

MAX_CACHE_AGE_DAYS = 7


def parse_datetime(value):
    """Parse Microsoft timestamp format into a datetime object."""
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def load_suspicious_signin_cache():
    """
    Load cached suspicious sign-ins from disk.

    If the file does not exist, is empty, or contains invalid JSON,
    return an empty list so the monitor does not crash.
    """
    STATE_DIR.mkdir(exist_ok=True)

    if not CACHE_FILE.exists():
        return []

    try:
        with CACHE_FILE.open("r", encoding="utf-8") as file:
            content = file.read().strip()

            if not content:
                return []

            return json.loads(content)

    except json.JSONDecodeError:
        print("Warning: suspicious sign-in cache was invalid. Resetting cache.")
        return []


def save_suspicious_signin_cache(events):
    """Save cached suspicious sign-ins to disk."""
    STATE_DIR.mkdir(exist_ok=True)

    with CACHE_FILE.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=2)


def prune_old_signins(events):
    """Remove cached sign-ins older than MAX_CACHE_AGE_DAYS."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_CACHE_AGE_DAYS)
    fresh_events = []

    for event in events:
        event_time = parse_datetime(event.get("created_datetime"))

        if event_time and event_time >= cutoff:
            fresh_events.append(event)

    return fresh_events


def add_suspicious_signins_to_cache(existing_events, new_events):
    """
    Add new suspicious sign-ins to the cache without duplicating event IDs.
    """
    existing_by_id = {
        event.get("id"): event
        for event in existing_events
        if event.get("id")
    }

    for event in new_events:
        event_id = event.get("id")

        if event_id:
            existing_by_id[event_id] = event

    return prune_old_signins(list(existing_by_id.values()))