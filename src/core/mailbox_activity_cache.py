"""
Mailbox Activity Cache

Stores recent mailbox rule / forwarding / hide-delete configuration events
across monitoring runs.

Why this exists:
- Microsoft 365 audit events and Entra sign-in events may not arrive in the
  same 15-minute run.
- We already cache suspicious sign-ins so later mailbox activity can correlate.
- This cache handles the reverse order:
    Run 1: mailbox rule / forwarding activity appears
    Run 2: suspicious sign-in appears or is processed later

This lets correlation work in both directions without requiring both event
types to appear in the same run.

Production behavior:
- Keep mailbox activity for 24 hours.
- That matches the high-confidence correlation window used by the correlation
  detector for most mailbox-rule/forwarding activity.

This is detection memory, not long-term forensic storage. Medium/high/critical
alerts should still be stored in security_alert_history.json.
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
CACHE_FILE = STATE_DIR / "mailbox_activity_cache.json"


# Keep recent mailbox configuration activity for one day.
# This is long enough to handle Microsoft audit delays and cross-run correlation,
# but short enough to avoid stale mailbox activity causing noisy alerts.
CACHE_WINDOW_MINUTES = 1440


MAILBOX_ACTIVITY_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Set-Mailbox",
}


def parse_datetime(value):
    """
    Parse a Microsoft timestamp into a timezone-aware UTC datetime.

    Microsoft APIs may return timestamps like:
    - 2026-06-02T12:30:38Z
    - 2026-06-02T12:30:38+00:00
    - 2026-06-02T12:30:38
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


def load_mailbox_activity_cache():
    """
    Load cached mailbox activity from disk.
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
        print("Warning: mailbox activity cache was invalid. Resetting.")
        return []


def save_mailbox_activity_cache(cache):
    """
    Save cached mailbox activity to disk.
    """
    STATE_DIR.mkdir(exist_ok=True)

    with CACHE_FILE.open("w", encoding="utf-8") as file:
        json.dump(cache, file, indent=2)


def prune_mailbox_activity_cache(
    cache,
    window_minutes=CACHE_WINDOW_MINUTES,
    reference_time=None,
):
    """
    Keep only mailbox activity inside the rolling cache window.
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


def is_cacheable_mailbox_activity(event):
    """
    Return True if this Microsoft 365 audit event is useful for correlation.

    We intentionally cache only mailbox configuration operations that can matter
    during account compromise.

    We do not cache normal mailbox activity such as:
    - MailItemsAccessed
    - Send
    - Update
    - Create
    - MoveToDeletedItems
    """
    operation = event.get("operation", "")

    return operation in MAILBOX_ACTIVITY_OPERATIONS


def build_cache_event(event):
    """
    Store the fields needed for future sign-in/mailbox correlation.

    raw is kept because the correlation detector needs to classify behavior:
    - external forwarding
    - hide/delete rule
    - generic mailbox rule
    - removed mailbox rule
    """
    return {
        "id": event.get("id"),
        "user": str(event.get("user", "")).lower().strip(),
        "created_datetime": event.get("created_datetime"),
        "operation": event.get("operation", "Unknown"),
        "target": event.get("target", "Unknown"),
        "raw": event.get("raw", ""),
        "source": event.get("source", "Microsoft 365 Audit Logs"),
    }


def add_mailbox_activity_events_to_cache(
    existing_cache,
    events,
    window_minutes=CACHE_WINDOW_MINUTES,
    reference_time=None,
):
    """
    Add mailbox activity events to the rolling cache.

    Production:
        Use the default 24-hour cache window.

    Tests:
        Optionally pass reference_time so historical exported events are not
        immediately pruned.
    """
    # Remove old entries from the existing cache before adding new events.
    updated_cache = prune_mailbox_activity_cache(
        existing_cache,
        window_minutes=window_minutes,
        reference_time=reference_time,
    )

    # Build a set of IDs already present in the cache so we can deduplicate.
    existing_ids = {
        event.get("id")
        for event in updated_cache
        if event.get("id")
    }

    for event in events:
        # Ignore events that are not mailbox configuration operations we care about.
        if not is_cacheable_mailbox_activity(event):
            continue

        event_id = event.get("id")

        # Skip events with no identifier; we cannot deduplicate them safely.
        if not event_id:
            continue

        # Skip duplicates already present in the cache.
        if event_id in existing_ids:
            continue

        updated_cache.append(build_cache_event(event))
        existing_ids.add(event_id)

    # After adding new events, prune again and return only entries still within
    # the allowed retention window.
    return prune_mailbox_activity_cache(
        updated_cache,
        window_minutes=window_minutes,
        reference_time=reference_time,
    )