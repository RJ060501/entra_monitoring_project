"""
State Manager

Tracks which Microsoft Graph events have already been processed.

This prevents repeat Teams alerts when the script runs every 15 minutes.
"""

import json
from pathlib import Path


# Compute the project root relative to this file's own location.
# This ensures the state directory is always resolved under the repository,
# even if the application is started from a different working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
STATE_FILE = STATE_DIR / "state.json"


def load_state():
    """
    Load state from disk.

    If the file does not exist yet, return a blank state.
    """
    # Ensure the state directory exists before reading the file.
    STATE_DIR.mkdir(exist_ok=True)

    # If the state file is missing, return the initial empty structure.
    if not STATE_FILE.exists():
        return {
            "processed_signin_ids": [],
            "processed_audit_ids": [],
            "processed_email_event_ids": [],
        }

    with STATE_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_state(state):
    """
    Save state to disk.
    """
    # Ensure the state directory exists before writing the file.
    STATE_DIR.mkdir(exist_ok=True)

    with STATE_FILE.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)


def filter_new_events(events, processed_ids):
    """
    Return only events whose IDs have not already been processed.

    This prevents duplicate alerts for events that already triggered.
    """
    new_events = []

    for event in events:
        event_id = event.get("id")

        if not event_id:
            # Skip records that are missing an ID.
            continue

        if event_id not in processed_ids:
            new_events.append(event)

    return new_events


def mark_events_processed(state, key, events, max_ids=5000):
    """
    Add event IDs to state after processing.

    max_ids prevents state.json from growing forever.
    """
    existing_ids = state.get(key, [])

    for event in events:
        event_id = event.get("id")

        if event_id and event_id not in existing_ids:
            existing_ids.append(event_id)

    state[key] = existing_ids[-max_ids:]

    return state