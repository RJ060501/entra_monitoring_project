"""
New Location Activity Cache

Tracks recent successful sign-ins from new locations across monitoring runs.

Why this exists:
- The app runs every 15 minutes.
- A suspicious pattern may span multiple runs.
- A single new location may be benign.
- Repeated successful sign-ins from new locations, especially multiple cities/IPs,
  is more suspicious and should be visible in Teams.

Production behavior:
- Keep recent new-location success events for 120 minutes.
- This gives enough cross-run memory without keeping stale travel/VPN context.

Test behavior:
- Tests can pass a reference_time based on historical exported events.
- This lets us test old incidents without increasing the real production cache
  window to days or weeks.
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
CACHE_FILE = STATE_DIR / "new_location_activity_cache.json"


# Production cache window.
# This should stay relatively short because this cache is for burst detection,
# not long-term investigation history.
CACHE_WINDOW_MINUTES = 120


def parse_datetime(value):
    """
    Parse a Microsoft Graph timestamp into a timezone-aware UTC datetime.

    Microsoft APIs commonly return timestamps like:
    - 2026-06-02T12:30:38Z
    - 2026-06-02T12:30:38+00:00
    - 2026-06-02T12:30:38

    This function normalizes all valid values to UTC.
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def get_reference_time(reference_time=None):
    """
    Return the time used for pruning cache entries.

    Production:
        reference_time is None, so use current UTC time.

    Tests:
        reference_time can be passed based on exported event timestamps.
        This prevents historical test data from being immediately pruned.
    """
    if reference_time is None:
        return datetime.now(timezone.utc)

    if isinstance(reference_time, datetime):
        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        return reference_time.astimezone(timezone.utc)

    parsed = parse_datetime(reference_time)

    if parsed:
        return parsed

    return datetime.now(timezone.utc)


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


def prune_new_location_cache(
    cache,
    window_minutes=CACHE_WINDOW_MINUTES,
    reference_time=None,
):
    """
    Keep only cache entries within the rolling window.

    window_minutes:
        How long events remain in cache.

    reference_time:
        The timestamp to compare against.

        Production should leave this as None.
        Tests can provide a historical timestamp from exported events.
    """
    reference_datetime = get_reference_time(reference_time)
    cutoff = reference_datetime - timedelta(minutes=window_minutes)

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

    We intentionally do not store the full raw sign-in event here because this
    cache is operational detection memory, not full forensic history.
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


def add_new_location_events_to_cache(
    existing_cache,
    events,
    window_minutes=CACHE_WINDOW_MINUTES,
    reference_time=None,
):
    """
    Add successful new-location sign-ins to the rolling cache.

    Only these events are cached:
    - status == success
    - new_location == True
    - event has an ID
    - event ID is not already cached

    Production:
        Use default window_minutes and reference_time.

    Tests:
        Pass reference_time based on exported event timestamps so old test data
        is not immediately pruned.
    """
    updated_cache = prune_new_location_cache(
        existing_cache,
        window_minutes=window_minutes,
        reference_time=reference_time,
    )

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

        if not event_id:
            continue

        if event_id in existing_ids:
            continue

        updated_cache.append(build_cache_event(event))
        existing_ids.add(event_id)

    return prune_new_location_cache(
        updated_cache,
        window_minutes=window_minutes,
        reference_time=reference_time,
    )