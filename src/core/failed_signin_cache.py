"""
Failed Sign-in Cache

Stores recent failed sign-ins across monitoring runs.

Why this exists:
- The app runs every 15 minutes.
- A suspicious failed-then-success pattern may span multiple runs.
- Without this cache, the detector only sees failures and successes that appear
  in the same batch.

Example problem:
    Run 1: two failed sign-ins
    Run 2: two failed sign-ins
    Run 3: successful sign-in

Without cache:
    No single run has enough failures followed by success.

With cache:
    The success in Run 3 can be compared against recent failures from Run 1
    and Run 2.

Production behavior:
- Keep failed sign-ins for 120 minutes.
- This gives enough cross-run context without keeping stale failures around
  long enough to cause noisy alerts.
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
CACHE_FILE = STATE_DIR / "failed_signin_cache.json"


# Keep failed sign-ins for two hours.
# This should align with the new-location cache because both are short-term
# behavioral detection windows.
CACHE_WINDOW_MINUTES = 120


def parse_datetime(value):
    """
    Parse a Microsoft Graph timestamp into a timezone-aware UTC datetime.
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
    Return the timestamp used for pruning cache entries.

    Production:
        reference_time is None, so current UTC time is used.

    Tests:
        reference_time can be passed based on historical exported events.
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


def load_failed_signin_cache():
    """
    Load cached failed sign-ins from disk.
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
        print("Warning: failed sign-in cache was invalid. Resetting.")
        return []


def save_failed_signin_cache(cache):
    """
    Save cached failed sign-ins to disk.
    """
    STATE_DIR.mkdir(exist_ok=True)

    with CACHE_FILE.open("w", encoding="utf-8") as file:
        json.dump(cache, file, indent=2)


def prune_failed_signin_cache(
    cache,
    window_minutes=CACHE_WINDOW_MINUTES,
    reference_time=None,
):
    """
    Keep only failed sign-ins inside the rolling cache window.
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
    Store only the fields needed for failed-then-success detection.
    """
    return {
        "id": event.get("id"),
        "user": str(event.get("user", "")).lower().strip(),
        "created_datetime": event.get("created_datetime"),
        "status": event.get("status"),
        "location": event.get("location", "Unknown"),
        "ip_address": event.get("ip_address", "Unknown"),
        "app_display_name": event.get("app_display_name", "Unknown"),
        "failure_reason": event.get("failure_reason", "Unknown"),
        "new_location": event.get("new_location", False),
        "source": event.get("source", "Entra Sign-In Logs"),
    }


def add_failed_signins_to_cache(
    existing_cache,
    events,
    window_minutes=CACHE_WINDOW_MINUTES,
    reference_time=None,
):
    """
    Add failed sign-ins to the rolling cache.

    Only failed sign-ins are stored.

    Successful sign-ins are not cached here. They are evaluated by the detector
    when they arrive.
    """
    updated_cache = prune_failed_signin_cache(
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
        if event.get("status") != "failure":
            continue

        event_id = event.get("id")

        if not event_id:
            continue

        if event_id in existing_ids:
            continue

        updated_cache.append(build_cache_event(event))
        existing_ids.add(event_id)

    return prune_failed_signin_cache(
        updated_cache,
        window_minutes=window_minutes,
        reference_time=reference_time,
    )


def clear_failed_signins_for_users(cache, users):
    """
    Remove cached failed sign-ins for users who already triggered an alert.

    This reduces repeated alerts from the same group of failures if the user has
    multiple successful sign-ins shortly after the failure burst.
    """
    normalized_users = {
        str(user).lower().strip()
        for user in users
        if user
    }

    return [
        event
        for event in cache
        if str(event.get("user", "")).lower().strip() not in normalized_users
    ]