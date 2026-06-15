"""
Test New Location Burst Detection

This test validates two things:

1. Same-run new-location burst detection
   - Detects repeated successful sign-ins from new locations inside one batch.

2. Cross-run new-location cache detection
   - Simulates multiple scheduled runs.
   - Confirms cached new-location activity can combine with later activity.

Important:
- Production cache window remains 120 minutes.
- This test also uses a 120-minute window.
- Instead of increasing the cache to 7 days, the test anchors pruning to the
  historical exported event timestamps.
"""

import json
from pathlib import Path

from core.location_baseline import (
    load_location_baseline,
    apply_location_baseline,
)
from core.new_location_cache import (
    load_new_location_cache,
    save_new_location_cache,
    add_new_location_events_to_cache,
    parse_datetime,
    CACHE_WINDOW_MINUTES,
)
from detectors.signin_detector import detect_new_location_burst


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_FILE = PROJECT_ROOT / "InteractiveSignIns_2026-05-29_2026-06-05.json"

TARGET_USER = "cfisher@resolutgroup.com"


def normalize_signin(raw):
    """
    Normalize one exported Entra sign-in record into the same shape used by the
    live application detectors.
    """
    location = raw.get("location", {})

    city = location.get("city", "")
    state = location.get("state", "")
    country = location.get("countryOrRegion", "")

    location_string = ", ".join(
        part for part in [city, state, country] if part
    )

    status_code = raw.get("status", {}).get("errorCode")
    created_datetime = raw.get("createdDateTime", "")

    try:
        hour = int(created_datetime[11:13])
    except Exception:
        hour = None

    return {
        "id": raw.get("id"),
        "user": raw.get("userPrincipalName", "").lower(),
        "created_datetime": created_datetime,
        "status": "success" if status_code == 0 else "failure",
        "status_error_code": status_code,
        "failure_reason": raw.get("status", {}).get("failureReason"),
        "hour": hour,
        "location": location_string,
        "ip_address": raw.get("ipAddress"),
        "app_display_name": raw.get("appDisplayName"),
        "conditional_access_status": raw.get("conditionalAccessStatus"),
        "risk_level_aggregated": raw.get("riskLevelAggregated"),
        "risk_detail": raw.get("riskDetail"),
        "raw": raw,
    }


def load_target_events():
    """
    Load and normalize exported sign-in events for the target user.
    """
    with TEST_FILE.open("r", encoding="utf-8") as file:
        raw_events = json.load(file)

    events = [
        normalize_signin(event)
        for event in raw_events
        if event.get("userPrincipalName", "").lower() == TARGET_USER
    ]

    baseline = load_location_baseline()
    events = apply_location_baseline(events, baseline)

    return events


def get_latest_event_time(events):
    """
    Return the latest created_datetime from a list of events.

    This is used as the test reference time so historical exported data is not
    pruned simply because the current real date is later.
    """
    latest = None

    for event in events:
        event_time = parse_datetime(event.get("created_datetime"))

        if not event_time:
            continue

        if latest is None or event_time > latest:
            latest = event_time

    return latest


def print_alerts(alerts):
    """
    Print generated burst alerts.
    """
    print("\n=== BURST ALERTS ===")

    if not alerts:
        print("No burst alerts generated.")
        return

    for alert in alerts:
        print(alert["severity"].upper(), "-", alert["type"])
        print("User:", alert["user"])
        print("Location:", alert["location"])
        print("Detail:", alert["detail"])
        print()


def run_same_run_test(events):
    """
    Test 1:
    Run burst detection against Christopher's 2026-06-02 12:00 hour.

    This should generate a HIGH alert because the same user had multiple
    successful new-location sign-ins from multiple locations/IPs.
    """
    print("\n=== TEST 1: SAME-RUN BURST DETECTION ===")

    window_events = [
        event for event in events
        if "2026-06-02T12:" in event.get("created_datetime", "")
    ]

    print(f"Events in 12:00 window: {len(window_events)}")

    alerts = detect_new_location_burst(window_events)

    print_alerts(alerts)


def run_cross_run_cache_test(events):
    """
    Test 2:
    Simulate two scheduled runs.

    Run 1:
        Contains Christopher's 12:30 new-location activity.

    Run 2:
        Contains Christopher's 12:57 and 12:58 new-location activity.

    The cache should preserve Run 1 activity and combine it with Run 2 activity.
    """
    print("\n=== TEST 2: CROSS-RUN NEW LOCATION CACHE DETECTION ===")

    run_1_events = [
        event for event in events
        if "2026-06-02T12:30:" in event.get("created_datetime", "")
    ]

    run_2_events = [
        event for event in events
        if "2026-06-02T12:57:" in event.get("created_datetime", "")
        or "2026-06-02T12:58:" in event.get("created_datetime", "")
    ]

    reference_time_run_1 = get_latest_event_time(run_1_events)
    reference_time_run_2 = get_latest_event_time(run_1_events + run_2_events)

    print(f"Run 1 event count: {len(run_1_events)}")
    print(f"Run 2 event count: {len(run_2_events)}")
    print(f"Production-style cache window: {CACHE_WINDOW_MINUTES} minutes")

    cache = []

    cache = add_new_location_events_to_cache(
        existing_cache=cache,
        events=run_1_events,
        window_minutes=CACHE_WINDOW_MINUTES,
        reference_time=reference_time_run_1,
    )

    print(f"Cache count after run 1: {len(cache)}")

    combined_events = cache + run_2_events

    alerts = detect_new_location_burst(combined_events)

    print_alerts(alerts)

    cache = add_new_location_events_to_cache(
        existing_cache=cache,
        events=run_2_events,
        window_minutes=CACHE_WINDOW_MINUTES,
        reference_time=reference_time_run_2,
    )

    print(f"Cache count after run 2: {len(cache)}")


def run_real_cache_file_test(events):
    """
    Test 3:
    Write test activity to the real cache file.

    This confirms the file can be written and loaded.

    Note:
    This writes historical test data into state/new_location_activity_cache.json.
    You may delete that file after testing if you want a clean production state.
    """
    print("\n=== TEST 3: REAL CACHE FILE WRITE TEST ===")

    cache = load_new_location_cache()

    print(f"Existing cache count: {len(cache)}")

    test_events = [
        event for event in events
        if "2026-06-02T12:" in event.get("created_datetime", "")
    ]

    reference_time = get_latest_event_time(test_events)

    updated_cache = add_new_location_events_to_cache(
        existing_cache=cache,
        events=test_events,
        window_minutes=CACHE_WINDOW_MINUTES,
        reference_time=reference_time,
    )

    save_new_location_cache(updated_cache)

    print(f"Updated cache count: {len(updated_cache)}")
    print("Wrote state/new_location_activity_cache.json")


def main():
    """
    Run all new-location burst/cache tests.
    """
    events = load_target_events()

    run_same_run_test(events)
    run_cross_run_cache_test(events)
    run_real_cache_file_test(events)


if __name__ == "__main__":
    main()