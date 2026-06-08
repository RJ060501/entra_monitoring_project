"""
New Location Activity Cache

Tracks recent successful sign-ins from new locations across monitoring runs.

Why this exists:
- The app runs every 15 minutes.
- A suspicious pattern may span multiple runs.
- A single new location may be benign.
- Repeated successful sign-ins from new locations, especially multiple cities/IPs,
  is more suspicious and should be visible in Teams.

This cache lets us detect new-location bursts across time instead of only inside
the current batch of events.
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
CACHE_FILE = STATE_DIR / "new_location_activity_cache.json"


CACHE_WINDOW_MINUTES = 120


def parse_datetime(value):
    """
    Parse a Microsoft Graph timestamp into a UTC datetime.
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def load_new_location_cache():
    """
    Load cached new-location activity from disk.
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
        print("Warning: new location cache was invalid. Resetting.")
        return []


def save_new_location_cache(cache):
    """
    Save cached new-location activity to disk.
    """
    STATE_DIR.mkdir(exist_ok=True)

    with CACHE_FILE.open("w", encoding="utf-8") as file:
        json.dump(cache, file, indent=2)


def prune_new_location_cache(cache, window_minutes=CACHE_WINDOW_MINUTES):
    """
    Keep only recent cached events.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)

    pruned = []

    for event in cache:
        event_time = parse_datetime(event.get("created_datetime"))

        if not event_time:
            continue

        if event_time >= cutoff:
            pruned.append(event)

    return pruned


def build_cache_event(event):
    """
    Store only the fields needed for burst detection.
    """
    return {
        "id": event.get("id"),
        "user": str(event.get("user", "")).lower().strip(),
        "created_datetime": event.get("created_datetime"),
        "status": event.get("status"),
        "location": event.get("location", "Unknown"),
        "ip_address": event.get("ip_address", "Unknown"),
        "app_display_name": event.get("app_display_name", "Unknown"),
        "new_location": event.get("new_location", False),
    }


def add_new_location_events_to_cache(existing_cache, events):
    """
    Add successful new-location sign-ins to cache.
    """
    updated_cache = prune_new_location_cache(existing_cache)

    existing_ids = {
        event.get("id")
        for event in updated_cache
        if event.get("id")
    }

    for event in events:
        if event.get("status") != "success":
            continue

        if not event.get("new_location"):
            continue

        event_id = event.get("id")

        if not event_id or event_id in existing_ids:
            continue

        updated_cache.append(build_cache_event(event))
        existing_ids.add(event_id)

    return prune_new_location_cache(updated_cache)