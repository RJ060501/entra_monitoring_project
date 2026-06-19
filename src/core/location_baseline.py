"""
Location Baseline Manager

Tracks previously-seen sign-in locations per user.

Why this exists:
- A successful sign-in alone is often not suspicious.
- A sign-in from a new/unusual location can be suspicious.
- Correlating a new location with mailbox rule activity is a strong signal.

This file stores simple per-user location baselines in:

    state/location_baseline.json
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
BASELINE_FILE = STATE_DIR / "location_baseline.json"


def load_location_baseline():
    """
    Load location baseline data from disk.
    """
    STATE_DIR.mkdir(exist_ok=True)

    if not BASELINE_FILE.exists():
        return {}

    try:
        with BASELINE_FILE.open("r", encoding="utf-8") as file:
            content = file.read().strip()

            if not content:
                return {}

            return json.loads(content)

    except json.JSONDecodeError:
        print("Warning: location baseline file was invalid. Resetting.")
        return {}


def save_location_baseline(baseline):
    """
    Save location baseline data to disk.
    """
    STATE_DIR.mkdir(exist_ok=True)

    with BASELINE_FILE.open("w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2)


def normalize_location(location):
    """
    Normalize location strings for consistency.
    """
    if not location:
        return "Unknown"

    return str(location).strip().lower()


def is_new_location(user, location, baseline):
    """
    Determine whether a sign-in location is new for this user.

    Important:
    If the user has no known locations yet, we treat the current location as
    baseline seeding, not suspicious activity.
    """
    normalized_user = str(user).lower().strip()
    normalized_location = normalize_location(location)

    known_locations = baseline.get(normalized_user, [])

    if not known_locations:
        return False

    return normalized_location not in known_locations


def update_location_baseline(events, baseline):
    """
    Add sign-in locations from current events into the baseline.
    """
    for event in events:
        user = str(event.get("user", "")).lower().strip()

        if not user:
            continue

        location = normalize_location(
            event.get("location", "Unknown")
        )

        baseline.setdefault(user, [])

        if location not in baseline[user]:
            baseline[user].append(location)

    return baseline


def apply_location_baseline(events, baseline):
    """
    Apply new_location flags to sign-in events.

    Adds:
        event["new_location"] = True/False
    """
    for event in events:
        user = event.get("user", "")
        location = event.get("location", "Unknown")

        event["new_location"] = is_new_location(
            user=user,
            location=location,
            baseline=baseline,
        )

    return events