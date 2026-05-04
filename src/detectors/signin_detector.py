from config.settings import SUPPRESSED_USERS


def detect_signin_events(events):
    """
    Main sign-in detector entry point.

    main.py calls this one function, and this function runs all sign-in rules.
    """
    alerts = []

    alerts += detect_unusual_login_time(events)
    alerts += detect_new_location(events)
    alerts += detect_failed_then_success(events)

    return alerts


def detect_unusual_login_time(events):
    alerts = []

    for event in events:
        user = event["user"]

        if user in SUPPRESSED_USERS:
            continue

        hour = event.get("hour")

        if hour is not None and (hour < 6 or hour > 22):
            alerts.append({
                "severity": "medium",
                "type": "Unusual Login Time",
                "user": user,
                "detail": f"Login at hour {hour}",
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
            })

    return alerts


def detect_new_location(events):
    alerts = []

    for event in events:
        user = event["user"]

        if user in SUPPRESSED_USERS:
            continue

        if event.get("new_location"):
            alerts.append({
                "severity": "medium",
                "type": "New Location",
                "user": user,
                "detail": f"New location detected: {event.get('location', 'Unknown')}",
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
            })

    return alerts


def detect_failed_then_success(events):
    alerts = []
    events_by_user = {}

    for event in events:
        user = event["user"]

        if user in SUPPRESSED_USERS:
            continue

        events_by_user.setdefault(user, []).append(event)

    for user, user_events in events_by_user.items():
        user_events.sort(key=lambda x: x.get("created_datetime", ""))

        failures_before_success = []

        for event in user_events:
            status = event.get("status")

            if status == "failure":
                failures_before_success.append(event)

            #Change to 3 later, but for now 1 just for testing.
            elif status == "success" and len(failures_before_success) >= 3:
                alerts.append({
                    "severity": "high",
                    "type": "Failed Sign-ins Followed by Success",
                    "user": user,
                    "detail": (
                        f"{len(failures_before_success)} failed sign-in(s) followed by success. "
                        f"Successful app: {event.get('app_display_name', 'Unknown')}. "
                        f"IP: {event.get('ip_address', 'Unknown')}. "
                        f"Last failure reason: {failures_before_success[-1].get('failure_reason', 'Unknown')}"
                    ),
                    "location": event.get("location", "Unknown"),
                    "source": "Entra Sign-In Logs",
                })

                failures_before_success = []

    return alerts