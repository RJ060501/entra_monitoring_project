"""
Test Failed Sign-in Cache

This test validates that failed sign-ins can be cached across simulated runs
and later correlated with a successful sign-in.

The production cache window remains 120 minutes.

For historical exported test data, this test passes reference_time based on the
exported event timestamps so the cache does not prune old test events just
because the real current date is later.
"""

import json
from pathlib import Path

from core.location_baseline import (
    load_location_baseline,
    apply_location_baseline,
)
from core.failed_signin_cache import (
    add_failed_signins_to_cache,
    parse_datetime,
    CACHE_WINDOW_MINUTES,
)
from detectors.signin_detector import detect_failed_then_success


# The project root is two levels above this test file.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Path to the exported sign-in data used for this cache test.
TEST_FILE = PROJECT_ROOT / "InteractiveSignIns_2026-05-29_2026-06-05.json"

# The user whose history is used to validate failed sign-in caching.
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

    # Build a compact location string for the normalized event.
    location_string = ", ".join(
        part for part in [city, state, country] if part
    )

    status_code = raw.get("status", {}).get("errorCode")
    created_datetime = raw.get("createdDateTime", "")

    try:
        hour = int(created_datetime[11:13])
    except Exception:
        hour = None

    # Return only the fields the detector and cache logic need.
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

    # Keep only entries for the specific test user.
    events = [
        normalize_signin(event)
        for event in raw_events
        if event.get("userPrincipalName", "").lower() == TARGET_USER
    ]

    # Apply the same location baseline logic used by production detectors.
    baseline = load_location_baseline()
    events = apply_location_baseline(events, baseline)

    # Ensure events are processed in chronological order for the simulated runs.
    events.sort(key=lambda x: x.get("created_datetime", ""))

    return events


def get_latest_event_time(events):
    """
    Return the latest created_datetime from a list of events.
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
    Print generated failed-then-success alerts.
    """
    print("\n=== FAILED SIGN-IN ALERTS ===")

    if not alerts:
        print("No failed sign-in alerts generated.")
        return

    for alert in alerts:
        print(alert["severity"].upper(), "-", alert["type"])
        print("User:", alert["user"])
        print("Location:", alert["location"])
        print("Detail:", alert["detail"])
        print("Cache clear user:", alert.get("cache_clear_user"))
        print()


def run_same_run_test(events):
    """
    Test 1:
    Confirm the current detector still works when failures and success are in
    the same batch.
    """
    print("\n=== TEST 1: SAME-RUN FAILED THEN SUCCESS ===")

    run_events = [
        event for event in events
        if "2026-06-02T18:" in event.get("created_datetime", "")
    ]

    print(f"Event count: {len(run_events)}")

    alerts = detect_failed_then_success(
        events=run_events,
        cached_failed_signins=[],
    )

    print_alerts(alerts)


def run_cross_run_cache_test(events):
    """
    Test 2:
    Simulate failures in one run and a success in a later run.

    Uses Christopher's 17:00 and 18:00 events:
    - 17:00 window has several failures
    - 18:00 window has more failures and then success

    The cache should allow the 18:00 success to see the earlier failures.
    """
    print("\n=== TEST 2: CROSS-RUN FAILED SIGN-IN CACHE ===")

    # Simulate the first run with events around 17:00.
    run_1_events = [
        event for event in events
        if "2026-06-02T17:" in event.get("created_datetime", "")
    ]

    # Simulate the following run with events around 18:00.
    run_2_events = [
        event for event in events
        if "2026-06-02T18:" in event.get("created_datetime", "")
    ]

    print(f"Run 1 event count: {len(run_1_events)}")
    print(f"Run 2 event count: {len(run_2_events)}")
    print(f"Production-style cache window: {CACHE_WINDOW_MINUTES} minutes")

    # Use the latest event time from each run to control pruning consistently
    # in the historical test data.
    reference_time_run_1 = get_latest_event_time(run_1_events)
    reference_time_run_2 = get_latest_event_time(run_1_events + run_2_events)

    cache = []

    cache = add_failed_signins_to_cache(
        existing_cache=cache,
        events=run_1_events,
        window_minutes=CACHE_WINDOW_MINUTES,
        reference_time=reference_time_run_1,
    )

    # After the first run, the cache should contain the failed sign-ins from
    # the 17:00 batch.
    print(f"Cache count after run 1: {len(cache)}")

    # Run the detector on the second batch while providing the cached failures.
    alerts = detect_failed_then_success(
        events=run_2_events,
        cached_failed_signins=cache,
    )

    print_alerts(alerts)

    # Add the second run's events to the cache too, simulating continuous
    # monitoring.
    cache = add_failed_signins_to_cache(
        existing_cache=cache,
        events=run_2_events,
        window_minutes=CACHE_WINDOW_MINUTES,
        reference_time=reference_time_run_2,
    )

    print(f"Cache count after run 2: {len(cache)}")


def main():
    """
    Run all failed sign-in cache tests.

    This function loads the target user's sign-in events and executes both
    same-run and cross-run scenarios to validate cache behavior.
    """
    events = load_target_events()

    run_same_run_test(events)
    run_cross_run_cache_test(events)


if __name__ == "__main__":
    main()