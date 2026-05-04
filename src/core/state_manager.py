"""
State Manager

Tracks which Microsoft Graph events have already been processed.

This prevents repeat Teams alerts when the script runs every 15 minutes.
"""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
STATE_FILE = STATE_DIR / "state.json"


def load_state():
    """
    Load state from disk.

    If the file does not exist yet, return a blank state.
    """
    STATE_DIR.mkdir(exist_ok=True)

    if not STATE_FILE.exists():
        return {
            "processed_signin_ids": [],
            "processed_audit_ids": [],
        }

    with STATE_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_state(state):
    """
    Save state to disk.
    """
    STATE_DIR.mkdir(exist_ok=True)

    with STATE_FILE.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=2)


def filter_new_events(events, processed_ids):
    """
    Return only events whose IDs have not already been processed.
    """
    new_events = []

    for event in events:
        event_id = event.get("id")

        if not event_id:
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