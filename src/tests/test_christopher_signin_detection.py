import json
from pathlib import Path

from detectors.signin_detector import detect_signin_events
from core.location_baseline import (
    load_location_baseline,
    apply_location_baseline,
)

from core.alert_history import (
    load_alert_history,
    save_alert_history,
    add_alerts_to_history,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Change this path if your exported sign-in JSON is stored somewhere else.
TEST_FILE = PROJECT_ROOT / "InteractiveSignIns_2026-05-29_2026-06-05.json"


TARGET_USER = "cfisher@resolutgroup.com"


def normalize_signin(raw):
    """
    Normalize one exported Entra sign-in record into the same shape
    used by the live application detectors.
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


def load_target_user_events():
    """
    Load exported sign-in events for the target user.
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

    return events, baseline


def print_event_summary(events, baseline, title):
    """
    Print readable event summary for debugging.
    """
    print(f"\n=== {title} ===")
    print(f"Events loaded: {len(events)}")
    print(f"Known baseline locations: {baseline.get(TARGET_USER, [])}")

    print("\n=== EVENT SUMMARY ===")

    for event in sorted(events, key=lambda x: x.get("created_datetime", "")):
        print(
            event.get("created_datetime"),
            event.get("status"),
            event.get("location"),
            "new_location=" + str(event.get("new_location")),
            event.get("app_display_name"),
            event.get("ip_address"),
        )


def print_alerts(alerts):
    """
    Print all generated alerts.
    """
    print("\n=== ALERTS GENERATED ===")

    if not alerts:
        print("No alerts generated.")
        return

    for alert in alerts:
        print(
            alert.get("severity", "unknown").upper(),
            "-",
            alert.get("type", "Unknown"),
            "-",
            alert.get("user", "Unknown"),
            "-",
            alert.get("detail", ""),
        )


def print_teams_eligible_alerts(alerts):
    """
    Test 2:
    Show exactly which alerts would be eligible for Teams.

    This mirrors your Teams notifier behavior where low alerts are skipped.
    """
    teams_eligible_alerts = [
        alert for alert in alerts
        if str(alert.get("severity", "")).lower() != "low"
    ]

    print("\n=== TEST 2: WOULD SEND TO TEAMS ===")

    if not teams_eligible_alerts:
        print("No Teams-eligible alerts.")
        return

    for alert in teams_eligible_alerts:
        print(
            alert.get("severity", "unknown").upper(),
            "-",
            alert.get("type", "Unknown"),
            "-",
            alert.get("user", "Unknown"),
        )


def write_alert_history(alerts):
    """
    Test security_alert_history.json writing.
    """
    print("\n=== ALERT HISTORY WRITE TEST ===")

    alert_history = load_alert_history()

    print(f"Existing alert history count: {len(alert_history)}")

    updated_history = add_alerts_to_history(
        existing_history=alert_history,
        alerts=alerts,
    )

    print(f"Updated alert history count: {len(updated_history)}")

    save_alert_history(updated_history)

    stored_count = len(updated_history) - len(alert_history)

    print(f"New alert history records added: {stored_count}")


def run_full_dataset_test():
    """
    Test 1 and Test 2:
    Run detection against the full Christopher Fisher export.
    """
    events, baseline = load_target_user_events()

    print_event_summary(
        events=events,
        baseline=baseline,
        title="TEST 1: FULL CHRISTOPHER FISHER SIGN-IN TEST",
    )

    alerts = detect_signin_events(events)

    print_alerts(alerts)
    print_teams_eligible_alerts(alerts)
    write_alert_history(alerts)


def run_time_window_test(window_label):
    """
    Test 3:
    Run detection against only a specific hour/day substring.

    Example:
    window_label = "2026-06-02T17:"
    """
    events, baseline = load_target_user_events()

    windowed_events = [
        event for event in events
        if window_label in event.get("created_datetime", "")
    ]

    print_event_summary(
        events=windowed_events,
        baseline=baseline,
        title=f"TEST 3: TIME WINDOW {window_label}",
    )

    alerts = detect_signin_events(windowed_events)

    print_alerts(alerts)
    print_teams_eligible_alerts(alerts)


def main():
    run_full_dataset_test()

    # These are the important compromise-day windows to test.
    # They simulate what the app may have seen during separate scheduled runs.
    run_time_window_test("2026-06-02T12:")
    run_time_window_test("2026-06-02T13:")
    run_time_window_test("2026-06-02T14:")
    run_time_window_test("2026-06-02T15:")
    run_time_window_test("2026-06-02T16:")
    run_time_window_test("2026-06-02T17:")
    run_time_window_test("2026-06-02T18:")
    run_time_window_test("2026-06-02T21:")


if __name__ == "__main__":
    main()