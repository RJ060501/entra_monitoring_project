"""
Sign-in detector module.

This module inspects Entra sign-in events and generates alerts for patterns
that may indicate suspicious login activity.

It currently detects:
- logins at unusual hours
- sign-ins from a new location
- multiple failed sign-ins followed by a success
"""

from config.settings import SUPPRESSED_USERS
from core.security_constants import (
    MAILBOX_CONFIGURATION_OPERATIONS,
    SUSPICIOUS_SIGNIN_TEXT_INDICATORS,
    RISKY_SIGNIN_LEVELS,
)
from utils.time_utils import format_mountain_time, parse_microsoft_datetime, MOUNTAIN_TIMEZONE

NEW_LOCATION_BURST_MIN_EVENTS = 3


def detect_signin_events(events, cached_failed_signins=None):
    """
    Main sign-in detector entry point.

    cached_failed_signins:
        Recent failed sign-ins from previous runs.

        This lets failed-then-success detection work even when failures and
        successes are split across scheduled monitoring runs.
    """
    alerts = []

    alerts += detect_unusual_login_time(events)
    alerts += detect_new_location(events)
    alerts += detect_failed_then_success(
        events=events,
        cached_failed_signins=cached_failed_signins,
    )

    return alerts


def detect_unusual_login_time(events):
    """
    Detect sign-ins that happen during unusual local hours.

    V2 tuning:
    - Unusual login time by itself is LOW.
    - Unusual login time from a new location is MEDIUM.
    - Unusual login time with suspicious risk/client context is HIGH.

    Important:
    This detector uses Mountain Time, not UTC.

    Microsoft sign-in logs are UTC-based, but a UTC hour can be misleading.
    Example:
    - 2:00 AM UTC is only 8:00 PM MDT.
    """
    alerts = []

    for event in events:
        user = normalize_signin_merge_value(event.get("user"))

        if not user:
            continue

        if user in SUPPRESSED_USERS:
            continue

        if event.get("status") != "success":
            continue

        parsed_datetime = parse_event_datetime(event)

        # If we cannot parse a real timestamp, skip unusual-time detection
        # instead of falling back to the UTC hour and creating false positives.
        if not parsed_datetime:
            continue

        local_datetime = parsed_datetime.astimezone(MOUNTAIN_TIMEZONE)
        local_hour = local_datetime.hour
        utc_hour = parsed_datetime.hour

        if not is_unusual_local_hour(local_hour):
            continue

        signin_time = format_event_time(event)
        signin_location = event.get("location", "Unknown")
        signin_ip = event.get("ip_address", "Unknown")
        signin_app = event.get("app_display_name", "Unknown")

        has_new_location = bool(event.get("new_location"))
        has_suspicious_context = has_suspicious_signin_context([event])

        if has_suspicious_context:
            severity = "high"
            reason = "unusual local login time with suspicious sign-in context"
        elif has_new_location:
            severity = "medium"
            reason = "unusual local login time from a new location"
        else:
            severity = "low"
            reason = "unusual local login time only"

        alerts.append({
            "severity": severity,
            "type": "Unusual Login Time",
            "user": user,
            "detail": (
                f"Successful sign-in occurred during unusual local hours. "
                f"Time: {signin_time}. "
                f"Local login hour: {local_hour} Mountain Time. "
                f"UTC hour: {utc_hour}. "
                f"Reason: {reason}. "
                f"Location: {signin_location}. "
                f"IP: {signin_ip}. "
                f"App: {signin_app}."
            ),
            "location": signin_location,
            "source": "Entra Sign-In Logs",

            # Structured fields for alert history and future correlation.
            "created_datetime": get_event_datetime_value(event),
            "signin_time_mountain": signin_time,
            "signin_ip": signin_ip,
            "signin_app": signin_app,
            "signin_location": signin_location,
            "new_location": has_new_location,
            "local_hour": local_hour,
            "utc_hour": utc_hour,
            "severity_reason": reason,
        })

    return alerts


def detect_new_location(events):
    """Detect sign-ins that are marked as coming from a new location."""
    alerts = []

    for event in events:
        user = normalize_signin_merge_value(event.get("user"))

        if not user:
            continue

        if user in SUPPRESSED_USERS:
            continue

        if event.get("status") != "success":
            continue

        if not event.get("new_location"):
            continue

        signin_time = format_event_time(event)
        signin_location = event.get("location", "Unknown")
        signin_ip = event.get("ip_address", "Unknown")
        signin_app = event.get("app_display_name", "Unknown")

        # The normalized sign-in event includes a boolean new_location flag.
        alerts.append({
            "severity": "low",
            "type": "New Location",
            "user": user,
            "detail": (
                f"Successful sign-in from a new location. "
                f"Time: {signin_time}. "
                f"Location: {signin_location}. "
                f"IP: {signin_ip}. "
                f"App: {signin_app}."
            ),
            "location": signin_location,
            "source": "Entra Sign-In Logs",

            # Structured fields for alert history and future correlation.
            "created_datetime": get_event_datetime_value(event),
            "signin_time_mountain": signin_time,
            "signin_ip": signin_ip,
            "signin_app": signin_app,
            "signin_location": signin_location,
        })

    return alerts


def detect_failed_then_success(events, cached_failed_signins=None):
    """
    Detect failed sign-ins followed by a successful sign-in.

    This detector uses:
    - current run events
    - cached failed sign-ins from previous runs

    Important:
    Alerts are only generated on successes from the current run.

    This prevents old cached data from repeatedly generating alerts without a
    new success event.
    """
    alerts = []
    cached_failed_signins = cached_failed_signins or []

    current_success_ids = {
        event.get("id")
        for event in events
        if event.get("status") == "success" and event.get("id")
    }

    combined_events = cached_failed_signins + events
    events_by_user = {}

    for event in combined_events:
        user = normalize_signin_merge_value(event.get("user"))

        if not user:
            continue

        if user in SUPPRESSED_USERS:
            continue

        events_by_user.setdefault(user, []).append(event)

    for user, user_events in events_by_user.items():
        user_events.sort(key=get_event_sort_value)

        failures_before_success = []

        for event in user_events:
            status = event.get("status")

            if status == "failure":
                failures_before_success.append(event)
                continue

            if status != "success":
                continue

            event_id = event.get("id")

            # Only alert on a success from this current run.
            if event_id not in current_success_ids:
                continue

            if len(failures_before_success) < 3:
                continue

            failure_count = len(failures_before_success)
            latest_failure = failures_before_success[-1]
            
            first_failure_time = format_event_time(failures_before_success[0])
            last_failure_time = format_event_time(latest_failure)
            success_time = format_event_time(event)
            
            signin_location = event.get("location", "Unknown")
            signin_ip = event.get("ip_address", "Unknown")
            signin_app = event.get("app_display_name", "Unknown")
            success_from_new_location = bool(event.get("new_location"))

            # Why:
            # Repeated Microsoft sign-in failures can happen during normal
            # prompts such as "Keep me signed in", expired passwords, or MFA
            # registration. Those should be visible, but should only become
            # HIGH when the eventual success happens from a new location.
            if event.get("new_location"):
                severity = "medium"
                severity_reason = (
                    "failed sign-ins were followed by a successful sign-in from a new location"
                )
            else:
                severity = "low"
                severity_reason = (
                    "failed sign-ins were followed by success, but the success was not from a new location"
                )

            alerts.append({
                "severity": severity,
                "type": "Failed Sign-ins Followed by Success",
                "user": user,
                "detail": (
                    f"{failure_count} failed sign-in(s) followed by success. "
                    f"First failure: {first_failure_time}. "
                    f"Last failure: {last_failure_time}. "
                    f"Successful sign-in: {success_time}. "
                    f"Severity reason: {severity_reason}. "
                    f"Success from new location: {success_from_new_location}. "
                    f"Successful app: {signin_app}. "
                    f"IP: {signin_ip}. "
                    f"Location: {signin_location}. "
                    f"Last failure reason: "
                    f"{latest_failure.get('failure_reason', 'Unknown')}."
                ),
                "location": signin_location,
                "source": "Entra Sign-In Logs",
                "cache_clear_user": user,

                # Structured fields for security_alert_history.json and future tuning.
                "failure_count": failure_count,
                "success_from_new_location": success_from_new_location,
                "severity_reason": severity_reason,
                "signin_ip": signin_ip,
                "signin_app": signin_app,
                "signin_location": signin_location,
                "first_failure_time_mountain": first_failure_time,
                "last_failure_time_mountain": last_failure_time,
                "success_time_mountain": success_time,
                "last_failure_reason": latest_failure.get(
                    "failure_reason",
                    "Unknown",
                ),
            })

            # Reset so multiple successes in the same run do not all alert from
            # the same failure group.
            failures_before_success = []

    return alerts

def detect_new_location_burst(
    events,
    failed_signin_events=None,
    mailbox_events=None,
):
    """
    Detect repeated successful sign-ins from new locations.

    This detector is context-aware but intentionally conservative.

    It includes:
    - first sign-in time
    - last sign-in time
    - observed time window
    - compact event timeline

    This makes alerts easier to triage because "two locations" does not always
    mean simultaneous activity. It may simply mean multiple sign-ins occurred
    inside the rolling cache window.
    """
    alerts = []

    failed_signin_events = failed_signin_events or []
    mailbox_events = mailbox_events or []

    events_by_user = {}

    for event in events:
        user = normalize_signin_merge_value(event.get("user"))

        if not user:
            continue

        if user in SUPPRESSED_USERS:
            continue

        if event.get("status") != "success":
            continue

        if not event.get("new_location"):
            continue

        events_by_user.setdefault(user, []).append(event)

    failed_users = {
        normalize_signin_merge_value(event.get("user"))
        for event in failed_signin_events
        if event.get("status") == "failure"
    }

    mailbox_context_users = {
        normalize_signin_merge_value(event.get("user"))
        for event in mailbox_events
        if event.get("operation") in MAILBOX_CONFIGURATION_OPERATIONS
    }

    for user, user_events in events_by_user.items():
        if len(user_events) < NEW_LOCATION_BURST_MIN_EVENTS:
            continue

        user_events.sort(key=get_event_sort_value)

        locations = clean_display_set(
            event.get("location", "Unknown")
            for event in user_events
        )

        ip_addresses = clean_display_set(
            event.get("ip_address", "Unknown")
            for event in user_events
        )

        apps = clean_display_set(
            event.get("app_display_name", "Unknown")
            for event in user_events
        )

        event_count = len(user_events)
        location_count = len(locations)
        ip_count = len(ip_addresses)

        first_event = user_events[0]
        last_event = user_events[-1]

        first_seen = get_event_datetime_value(first_event)
        last_seen = get_event_datetime_value(last_event)
        first_seen_mountain = format_event_time(first_event)
        last_seen_mountain = format_event_time(last_event)
        window_minutes = calculate_event_window_minutes(user_events)

        timeline = build_signin_timeline(user_events)
        timeline_summary = format_timeline_for_alert(timeline)

        has_failed_context = user in failed_users
        has_mailbox_context = user in mailbox_context_users
        has_suspicious_context = has_suspicious_signin_context(user_events)

        multiple_locations = location_count >= 2
        multiple_ips = ip_count >= 2

        if has_mailbox_context:
            severity = "high"
            reason = "new-location burst paired with mailbox activity"

        elif has_suspicious_context:
            severity = "medium"
            reason = "new-location burst paired with suspicious sign-in context"

        elif has_failed_context:
            severity = "medium"
            reason = "new-location burst paired with failed sign-in context"

        elif multiple_locations and multiple_ips:
            severity = "medium"
            reason = "multiple new locations and multiple IP addresses"

        elif multiple_ips:
            severity = "medium"
            reason = "multiple new IP addresses"

        elif multiple_locations:
            severity = "low"
            reason = "multiple location labels from the same IP address"

        else:
            severity = "low"
            reason = "repeated successful sign-ins from one new location and one IP"

        alerts.append({
            "severity": severity,
            "type": "New Location Sign-in Burst",
            "user": user,
            "detail": (
                f"{event_count} successful sign-in(s) from new location activity "
                f"{build_window_sentence_fragment(window_minutes)}. "
                f"Reason: {reason}. "
                f"First sign-in: {first_seen_mountain}. "
                f"Last sign-in: {last_seen_mountain}. "
                f"Locations: {', '.join(sorted(locations))}. "
                f"Location count: {location_count}. "
                f"IP address(es): {', '.join(sorted(ip_addresses))}. "
                f"IP count: {ip_count}. "
                f"Apps: {', '.join(sorted(apps))}. "
                f"Timeline: {timeline_summary}."
            ),
            "location": ", ".join(sorted(locations)),
            "source": "Entra Sign-In Logs",

            # Structured fields for security_alert_history.json and future tuning.
            "event_count": event_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_seen_mountain": first_seen_mountain,
            "last_seen_mountain": last_seen_mountain,
            "window_minutes": window_minutes,
            "locations": sorted(locations),
            "location_count": location_count,
            "ip_addresses": sorted(ip_addresses),
            "ip_count": ip_count,
            "apps": sorted(apps),
            "timeline": timeline,
            "severity_reason": reason,
            "has_failed_context": has_failed_context,
            "has_mailbox_context": has_mailbox_context,
            "has_suspicious_context": has_suspicious_context,
        })

    return alerts

def has_suspicious_signin_context(events):
    """
    Return True if any sign-in event has suspicious client or risk context.

    This is intentionally conservative.

    Current signals:
    - Python Requests / automation-style user agent
    - device code flow
    - medium/high risk level
    - conditional access failure
    - risky sign-in details present

    This helps elevate single-IP new-location bursts when the sign-in itself has
    stronger compromise indicators.
    """

    for event in events:
        raw_text = str(event.get("raw", "")).lower()

        for indicator in SUSPICIOUS_SIGNIN_TEXT_INDICATORS:
            if indicator in raw_text:
                return True

        risk_level = str(
            event.get("risk_level_aggregated")
            or event.get("risk_level")
            or ""
        ).lower()

        if risk_level in RISKY_SIGNIN_LEVELS:
            return True

        conditional_access_status = str(
            event.get("conditional_access_status", "")
        ).lower()

        if conditional_access_status == "failure":
            return True

        risk_detail = str(event.get("risk_detail", "")).lower()

        if risk_detail and risk_detail not in {
            "none",
            "hidden",
            "unknown",
        }:
            return True

    return False

#V2 alert merging logic for sign-in detectors

def merge_related_signin_alerts(alerts):
    """
    Merge related sign-in alerts into one clearer sequence alert.

    Why this exists:
    Some real-world sign-in patterns trigger multiple individual detectors.
    For example:
    - Unusual Login Time
    - Failed Sign-ins Followed by Success
    - New Location Sign-in Burst

    Each detector is useful by itself, but when they describe the same user
    and overlapping sign-in context, multiple Teams alerts can create noise.

    This function keeps the detection signal, but consolidates related alerts
    into a single "Suspicious Sign-in Sequence" alert that explains the series
    of alerts that caused it.
    """
    if not alerts:
        return []

    grouped_alerts = group_signin_alerts_by_user(alerts)

    final_alerts = []
    consumed_alert_ids = set()

    for user_key, user_alerts in grouped_alerts.items():
        sequence_alert = build_related_signin_sequence_alert(user_alerts)

        if not sequence_alert:
            continue

        for alert in sequence_alert.get("merged_alerts", []):
            consumed_alert_ids.add(id(alert))

        final_alerts.append(sequence_alert)

    for alert in alerts:
        if id(alert) not in consumed_alert_ids:
            final_alerts.append(alert)

    return final_alerts


def group_signin_alerts_by_user(alerts):
    """
    Group sign-in alerts by user.

    We group by user first because sign-in sequences should not merge across
    different users, even if locations or IPs are similar.
    """
    grouped = {}

    for alert in alerts:
        user = normalize_signin_merge_value(alert.get("user"))

        if not user:
            continue

        grouped.setdefault(user, []).append(alert)

    return grouped


def build_related_signin_sequence_alert(user_alerts):
    """
    Build a consolidated Suspicious Sign-in Sequence alert when related
    sign-in alerts exist for the same user.

    A sequence alert is created when a New Location Sign-in Burst is paired
    with at least one additional suspicious sign-in signal, such as:
    - Failed Sign-ins Followed by Success
    - Unusual Login Time

    This keeps standalone new-location bursts intact unless there is another
    related sign-in signal to explain.
    """
    burst_alerts = [
        alert for alert in user_alerts
        if alert.get("type") == "New Location Sign-in Burst"
    ]

    failed_success_alerts = [
        alert for alert in user_alerts
        if alert.get("type") == "Failed Sign-ins Followed by Success"
    ]

    unusual_time_alerts = [
        alert for alert in user_alerts
        if alert.get("type") == "Unusual Login Time"
    ]

    if not burst_alerts:
        return None

    if not failed_success_alerts and not unusual_time_alerts:
        return None

    best_burst_alert = burst_alerts[0]

    related_alerts = []

    related_alerts.extend(
        find_contextually_related_alerts(
            anchor_alert=best_burst_alert,
            candidate_alerts=failed_success_alerts,
        )
    )

    related_alerts.extend(
        find_contextually_related_alerts(
            anchor_alert=best_burst_alert,
            candidate_alerts=unusual_time_alerts,
        )
    )

    if not related_alerts:
        return None

    merged_alerts = [best_burst_alert] + related_alerts

    user = best_burst_alert.get("user") or related_alerts[0].get("user") or "Unknown"
    location = build_sequence_location_summary(merged_alerts)
    time_summary = build_sequence_time_summary(merged_alerts)
    timeline_summary = build_sequence_timeline_summary(merged_alerts)
    ip_summary = build_sequence_ip_summary(merged_alerts)
    app_summary = build_sequence_app_summary(merged_alerts)

    sequence_reason = build_sequence_reason(
        has_failed_success=bool(failed_success_alerts),
        unusual_time_count=len(unusual_time_alerts),
        has_burst=True,
    )

    severity = get_sequence_severity(merged_alerts)

    correlated_alert_types = []

    for alert in merged_alerts:
        alert_type = alert.get("type")

        if alert_type and alert_type not in correlated_alert_types:
            correlated_alert_types.append(alert_type)

    detail_parts = [
        "Suspicious sign-in sequence detected.",
        f"Reason: {sequence_reason}.",
        f"Formula: {build_sequence_formula(merged_alerts)}.",
    ]

    if time_summary:
        detail_parts.append(time_summary)

    detail_parts.extend([
        f"User: {user}.",
        f"Locations: {location}.",
        f"IP address(es): {ip_summary}.",
        f"Apps: {app_summary}.",
    ])

    if timeline_summary:
        detail_parts.append(f"Timeline: {timeline_summary}.")

    detail_parts.append(
        f"Merged signals: {', '.join(correlated_alert_types)}."
    )

    detail_parts.append(
        "Full merged evidence is retained in alert history."
    )

    return {
        "type": "Suspicious Sign-in Sequence",
        "severity": severity,
        "user": user,
        "location": location,
        "source": "Entra Sign-In Logs",
        "detail": " ".join(detail_parts),
        "ip_address": ip_summary,
        "merged_alerts": merged_alerts,
        "merged_evidence": build_merged_alert_evidence(merged_alerts),
        "correlated_alert_types": correlated_alert_types,
        "timeline": get_first_available_timeline(merged_alerts),
    }


def find_contextually_related_alerts(anchor_alert, candidate_alerts):
    """
    Find alerts that appear related to the anchor alert.

    Safer V2 rule:
    - Same user is always required.
    - If both alerts have IP context, require overlapping IPs.
    - Only fall back to location overlap when one side lacks IP context.

    This prevents false merges where two different locations only overlap on
    broad location fragments like "US".
    """
    related = []

    anchor_user = normalize_signin_merge_value(anchor_alert.get("user"))
    anchor_locations = extract_locations_from_alert(anchor_alert)
    anchor_ips = extract_ips_from_alert(anchor_alert)

    for candidate in candidate_alerts:
        candidate_user = normalize_signin_merge_value(candidate.get("user"))

        if anchor_user != candidate_user:
            continue

        candidate_locations = extract_locations_from_alert(candidate)
        candidate_ips = extract_ips_from_alert(candidate)

        has_shared_ip = bool(anchor_ips.intersection(candidate_ips))
        has_shared_location = bool(anchor_locations.intersection(candidate_locations))

        # If both alerts have IP data, require shared IP.
        # This is safer than allowing broad location overlap to merge alerts.
        if anchor_ips and candidate_ips:
            if has_shared_ip:
                related.append(candidate)
            continue

        # If IP data is missing on one side, fall back to exact location overlap.
        if has_shared_location:
            related.append(candidate)

    return related


def build_sequence_reason(has_failed_success, unusual_time_count, has_burst):
    """
    Build a human-readable explanation for why the sequence alert exists.
    """
    reasons = []

    if has_failed_success:
        reasons.append("failed sign-ins were followed by a successful sign-in")

    if unusual_time_count == 1:
        reasons.append("an unusual-time sign-in occurred")
    elif unusual_time_count > 1:
        reasons.append(f"{unusual_time_count} unusual-time sign-ins occurred")

    if has_burst:
        reasons.append("new-location sign-in burst activity occurred")

    return "; ".join(reasons)


def build_sequence_formula(merged_alerts):
    """
    Explain the alert formula as a readable series of detector outputs.
    """
    alert_types = []

    for alert in merged_alerts:
        alert_type = alert.get("type") or "Unknown Alert"
        if alert_type not in alert_types:
            alert_types.append(alert_type)

    return " + ".join(alert_types) + " → Suspicious Sign-in Sequence"


def build_merged_alert_evidence(merged_alerts):
    """
    Preserve the useful evidence from the original alerts in the new alert.

    This keeps the consolidated alert explainable and auditable.
    """
    evidence_parts = []

    for alert in merged_alerts:
        alert_type = alert.get("type") or "Unknown Alert"
        detail = alert.get("detail") or "No detail available"

        evidence_parts.append(f"[{alert_type}] {detail}")

    return " ".join(evidence_parts)


def get_sequence_severity(merged_alerts):
    """
    Decide severity for the consolidated sign-in sequence.

    Default:
    - MEDIUM for related sign-in anomalies.

    Escalate to HIGH only when stronger context appears in the merged evidence.
    """
    combined_detail = " ".join(
        str(alert.get("detail", "")).lower()
        for alert in merged_alerts
    )

    high_indicators = [
        "ip count: 3",
        "ip count: 4",
        "location count: 3",
        "location count: 4",
        "risky",
        "risk level: medium",
        "risk level: high",
        "exchange admin center",
        "microsoft 365 admin portal",
        "office365 shell",
        "security and compliance",
        "mailbox activity",
        "conditional access failure",
    ]

    for indicator in high_indicators:
        if indicator in combined_detail:
            return "high"

    return "medium"


def build_sequence_location_summary(alerts):
    """
    Build a clean comma-separated location summary from merged alerts.
    """
    locations = set()

    for alert in alerts:
        locations.update(extract_locations_from_alert(alert))

    if not locations:
        return "Unknown"

    return ", ".join(sorted(locations))


def build_sequence_ip_summary(alerts):
    """
    Build a clean comma-separated IP summary from merged alerts.
    """
    ips = set()

    for alert in alerts:
        ips.update(extract_ips_from_alert(alert))

    if not ips:
        return "Unknown"

    return ", ".join(sorted(ips))


def build_sequence_app_summary(alerts):
    """
    Build a clean app summary from merged alert details when possible.
    """
    apps = set()

    for alert in alerts:
        apps.update(extract_apps_from_alert(alert))

    if not apps:
        return "Unknown"

    return ", ".join(sorted(apps))

def build_sequence_time_summary(alerts):
    """
    Build a short time summary for a merged sequence alert.

    Prefer the structured fields from the New Location Sign-in Burst alert.
    """
    for alert in alerts:
        if alert.get("type") != "New Location Sign-in Burst":
            continue

        first_seen = alert.get("first_seen_mountain")
        last_seen = alert.get("last_seen_mountain")
        window_minutes = alert.get("window_minutes")

        if first_seen and last_seen:
            return (
                f"First sign-in: {first_seen}. "
                f"Last sign-in: {last_seen}. "
                f"Window: {format_window_minutes(window_minutes)}."
            )

    return ""

def build_sequence_timeline_summary(alerts):
    """
    Reuse the timeline from the burst alert when available.
    """
    timeline = get_first_available_timeline(alerts)

    if not timeline:
        return ""

    return format_timeline_for_alert(timeline)


def get_first_available_timeline(alerts):
    """
    Return the first structured timeline found in a list of alerts.
    """
    for alert in alerts:
        timeline = alert.get("timeline")

        if timeline:
            return timeline

    return []

# ---------------------------------------------------------------------------
# Alert field extraction helpers
# ---------------------------------------------------------------------------

def extract_locations_from_alert(alert):
    """
    Extract location values from the alert location field and detail text.

    Supports:
    - alert["location"]
    - alert["locations"]
    - "Locations: location1, location2."
    - "Location: location."
    """
    locations = set()

    location_value = alert.get("location")
    if location_value:
        locations.update(split_location_list(location_value))

    structured_locations = alert.get("locations")
    if isinstance(structured_locations, list):
        locations.update(structured_locations)

    detail = str(alert.get("detail", ""))

    locations_text = extract_detail_value(
        text=detail,
        start_marker="Locations:",
        end_markers=[
            "Location count:",
            "IP address(es):",
            "IP:",
            "Apps:",
            "Timeline:",
        ],
    )

    if locations_text:
        locations.update(split_location_list(locations_text))

    location_text = extract_detail_value(
        text=detail,
        start_marker="Location:",
        end_markers=[
            "IP:",
            "App:",
            "Last failure reason:",
            "Timeline:",
        ],
    )

    if location_text:
        locations.update(split_location_list(location_text))

    return {
        normalize_display_value(location)
        for location in locations
        if normalize_display_value(location)
    }


def extract_ips_from_alert(alert):
    """
    Extract IP addresses from alert fields and detail text.

    Supports:
    - alert["ip_address"]
    - alert["ip_addresses"]
    - alert["signin_ip"]
    - "IP: x.x.x.x"
    - "IP address(es): x.x.x.x, y.y.y.y"
    """
    ips = set()

    for field_name in ["ip_address", "signin_ip"]:
        ip_value = alert.get(field_name)

        if ip_value:
            ips.update(split_ip_list(ip_value))

    structured_ips = alert.get("ip_addresses")
    if isinstance(structured_ips, list):
        ips.update(structured_ips)

    detail = str(alert.get("detail", ""))

    ip_list_text = extract_detail_value(
        text=detail,
        start_marker="IP address(es):",
        end_markers=[
            "IP count:",
            "Apps:",
            "Timeline:",
            "Merged alert evidence:",
        ],
    )

    if ip_list_text:
        ips.update(split_ip_list(ip_list_text))

    ip_text = extract_detail_value(
        text=detail,
        start_marker="IP:",
        end_markers=[
            "Location:",
            "App:",
            "Apps:",
            "Last failure reason:",
            "Timeline:",
        ],
    )

    if ip_text:
        ips.update(split_ip_list(ip_text))

    return {
        normalize_display_value(ip)
        for ip in ips
        if normalize_display_value(ip)
    }


def extract_apps_from_alert(alert):
    """
    Extract app names from structured fields and alert detail text.

    Supports:
    - alert["signin_app"]
    - alert["app_display_name"]
    - alert["apps"]
    - "App: ..."
    - "Successful app: ..."
    - "Apps: ..."
    """
    apps = set()

    for field_name in ["signin_app", "app_display_name"]:
        app_value = alert.get(field_name)

        if app_value:
            apps.add(str(app_value).strip())

    structured_apps = alert.get("apps")
    if isinstance(structured_apps, list):
        apps.update(structured_apps)

    detail = str(alert.get("detail", ""))

    markers = [
        ("Successful app:", ["IP:", "Location:", "Timeline:"]),
        ("Apps:", ["Timeline:", "Merged alert evidence:"]),
        ("App:", ["IP:", "Location:", "Timeline:"]),
    ]

    for start_marker, end_markers in markers:
        app_text = extract_detail_value(
            text=detail,
            start_marker=start_marker,
            end_markers=end_markers,
        )

        if app_text:
            for app in split_app_list(app_text):
                apps.add(app)

    return {
        normalize_display_value(app)
        for app in apps
        if normalize_display_value(app)
        and normalize_display_value(app).lower() != "unknown"
    }


def extract_detail_value(text, start_marker, end_markers):
    """
    Extract a value from human-readable alert detail text.

    Example:
        text:
            "Locations: Atlanta, Georgia, US. Location count: 1."

        start_marker:
            "Locations:"

        end_markers:
            ["Location count:"]

        result:
            "Atlanta, Georgia, US"

    This avoids fragile parsing where a period inside an IPv4 address causes
    the value to be split incorrectly.
    """
    if not text or start_marker not in text:
        return ""

    value = text.split(start_marker, 1)[1].strip()

    marker_positions = [
        value.find(marker)
        for marker in end_markers
        if marker in value
    ]

    if marker_positions:
        value = value[:min(marker_positions)]

    return value.strip().strip(".; ")


# ---------------------------------------------------------------------------
# Time and timeline helpers
# ---------------------------------------------------------------------------

def get_event_datetime_value(event):
    """
    Return the best available timestamp string from a normalized sign-in event.
    """
    return (
        event.get("created_datetime")
        or event.get("createdDateTime")
        or event.get("activityDateTime")
        or event.get("time")
        or event.get("timestamp")
    )


def parse_event_datetime(event):
    """
    Parse the best available timestamp from an event.
    """
    value = get_event_datetime_value(event)

    if not value:
        return None

    return parse_microsoft_datetime(value)


def format_event_time(event):
    """
    Format an event timestamp in Mountain Time for readable alerts.
    """
    value = get_event_datetime_value(event)

    if not value:
        return "Unknown"

    return format_mountain_time(value)


def get_event_sort_value(event):
    """
    Sort events chronologically using their parsed timestamp.

    Events without a usable timestamp sort first. That is acceptable here
    because the alert timeline will still show "Unknown" for those entries.
    """
    parsed_datetime = parse_event_datetime(event)

    if not parsed_datetime:
        return 0

    return parsed_datetime.timestamp()


def calculate_event_window_minutes(events):
    """
    Calculate the number of minutes between the first and last parsed event
    timestamps.
    """
    parsed_datetimes = [
        parse_event_datetime(event)
        for event in events
    ]

    parsed_datetimes = [
        parsed_datetime
        for parsed_datetime in parsed_datetimes
        if parsed_datetime
    ]

    if len(parsed_datetimes) < 2:
        return None

    first_seen = min(parsed_datetimes)
    last_seen = max(parsed_datetimes)

    seconds = max(
        0,
        int((last_seen - first_seen).total_seconds()),
    )

    return seconds // 60


def format_window_minutes(window_minutes):
    """
    Format a time window for human-readable alert text.
    """
    if window_minutes is None:
        return "unknown"

    if window_minutes <= 0:
        return "less than 1 minute"

    if window_minutes == 1:
        return "1 minute"

    return f"{window_minutes} minutes"


def build_window_sentence_fragment(window_minutes):
    """
    Build the time-window phrase used in burst alert summaries.
    """
    if window_minutes is None:
        return "inside the current cache window"

    return f"within {format_window_minutes(window_minutes)}"


def build_signin_timeline(events, max_items=8):
    """
    Build a compact structured timeline from sign-in events.

    The timeline is stored in alert history and also rendered into Teams detail
    text. Limiting the count prevents very large Teams messages during noisy
    sign-in bursts.
    """
    sorted_events = sorted(events, key=get_event_sort_value)

    timeline = []

    for event in sorted_events[:max_items]:
        timeline.append({
            "time": format_event_time(event),
            "location": event.get("location", "Unknown"),
            "ip_address": event.get("ip_address", "Unknown"),
            "app": event.get("app_display_name", "Unknown"),
            "status": event.get("status", "Unknown"),
        })

    if len(sorted_events) > max_items:
        timeline.append({
            "time": "Additional events omitted",
            "location": f"{len(sorted_events) - max_items} more event(s)",
            "ip_address": "",
            "app": "",
            "status": "",
        })

    return timeline


def format_timeline_for_alert(timeline):
    """
    Convert a structured timeline into compact text for Teams/detail output.
    """
    if not timeline:
        return "Unknown"

    timeline_parts = []

    for index, item in enumerate(timeline, start=1):
        time_value = item.get("time", "Unknown")
        location = item.get("location", "Unknown")
        ip_address = item.get("ip_address", "Unknown")
        app = item.get("app", "Unknown")

        if time_value == "Additional events omitted":
            timeline_parts.append(
                f"{index}) {location}"
            )
            continue

        timeline_parts.append(
            f"{index}) {time_value} | {location} | {ip_address} | {app}"
        )

    return "; ".join(timeline_parts)


# ---------------------------------------------------------------------------
# Value normalization helpers
# ---------------------------------------------------------------------------

def clean_display_set(values):
    """
    Normalize a collection of display values while removing empty values.
    """
    cleaned_values = set()

    for value in values:
        cleaned_value = normalize_display_value(value)

        if not cleaned_value:
            continue

        if cleaned_value.lower() in {"unknown", "n/a"}:
            continue

        cleaned_values.add(cleaned_value)

    if not cleaned_values:
        return {"Unknown"}

    return cleaned_values


def split_location_list(value):
    """
    Split detector-generated location summaries without breaking individual
    city/state/country values into separate pieces.

    Examples:
    - "Denver, Colorado, US"
      -> ["Denver, Colorado, US"]

    - "Sunland Park, New Mexico, US, Walsenburg, Colorado, US"
      -> ["Sunland Park, New Mexico, US", "Walsenburg, Colorado, US"]
    """
    if not value:
        return []

    text = str(value).strip().strip(".;")

    if not text or text.lower() in {"unknown", "n/a - exchange audit event"}:
        return []

    parts = [
        part.strip()
        for part in text.split(",")
        if part.strip()
    ]

    # Most Microsoft location strings in this project are:
    # City, State, Country
    #
    # If we have multiple of those chained together, regroup them in threes.
    if len(parts) > 3 and len(parts) % 3 == 0:
        locations = []

        for index in range(0, len(parts), 3):
            locations.append(", ".join(parts[index:index + 3]))

        return locations

    return [text]


def split_ip_list(value):
    """
    Split an IP list while preserving IPv6 addresses.

    IPv6 addresses contain colons, so we only split on comma separators.

    This also removes trailing sentence punctuation from alert detail text.
    """
    if not value:
        return []

    cleaned_ips = []

    for item in str(value).split(","):
        cleaned_ip = item.strip().rstrip(".;")

        if not cleaned_ip:
            continue

        if cleaned_ip.lower() in {"unknown", "n/a"}:
            continue

        cleaned_ips.append(cleaned_ip)

    return cleaned_ips


def split_app_list(value):
    """
    Split an app list from alert detail text.
    """
    if not value:
        return []

    apps = []

    for item in str(value).split(","):
        cleaned_app = item.strip().rstrip(".;")

        if not cleaned_app:
            continue

        if cleaned_app.lower() in {"unknown", "n/a"}:
            continue

        apps.append(cleaned_app)

    return apps


def normalize_signin_merge_value(value):
    """
    Normalize values for comparison.
    """
    if not value:
        return ""

    return str(value).strip().lower()


def normalize_display_value(value):
    """
    Normalize display values without forcing lowercase.

    We keep original casing for Teams alerts but remove extra whitespace.
    """
    if not value:
        return ""

    return str(value).strip()
    
def is_unusual_local_hour(local_hour):
    """
    Return True when a sign-in happened during a locally unusual hour.

    We use Mountain Time because the company operates primarily from Mountain
    Time locations.

    Current rule:
    - 11:00 PM through 5:59 AM Mountain Time is unusual.

    This avoids false positives where 2:00 AM UTC is actually only 8:00 PM MDT.
    """
    if local_hour is None:
        return False

    return local_hour >= 23 or local_hour <= 5