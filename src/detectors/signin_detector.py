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
from collections import defaultdict


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
    alerts = merge_related_signin_alerts(alerts)

    return alerts


def detect_unusual_login_time(events):
    """
    Detect sign-ins that happen outside normal business hours.

    V1 tuning:
    - Unusual login time by itself is LOW.
    - Unusual login time from a new location is MEDIUM.
    - Unusual login time with suspicious risk/client context is HIGH.

    This keeps the signal available in console/history without spamming Teams
    for normal after-hours Microsoft 365 activity.
    """
    alerts = []

    for event in events:
        user = str(event.get("user", "")).lower().strip()

        if not user:
            continue

        # Ignore users that are intentionally suppressed from alerting.
        if user in SUPPRESSED_USERS:
            continue

        # Only alert on successful sign-ins.
        if event.get("status") != "success":
            continue

        hour = event.get("hour")

        # Treat sign-ins between 1:00 AM and 4:59 AM UTC as unusual.
        if hour is None or not (1 <= hour <= 4):
            continue

        has_new_location = bool(event.get("new_location"))
        has_suspicious_context = has_suspicious_signin_context([event])

        if has_suspicious_context:
            severity = "high"
            reason = "unusual login time with suspicious sign-in context"
        elif has_new_location:
            severity = "medium"
            reason = "unusual login time from a new location"
        else:
            severity = "low"
            reason = "unusual login time only"

        alerts.append({
            "severity": severity,
            "type": "Unusual Login Time",
            "user": user,
            "detail": (
                f"Login at hour {hour} UTC. "
                f"Reason: {reason}. "
                f"App: {event.get('app_display_name', 'Unknown')}. "
                f"IP: {event.get('ip_address', 'Unknown')}."
            ),
            "location": event.get("location", "Unknown"),
            "source": "Entra Sign-In Logs",
        })

    return alerts


def detect_new_location(events):
    """Detect sign-ins that are marked as coming from a new location."""
    alerts = []

    for event in events:
        user = event["user"]

        if user in SUPPRESSED_USERS:
            continue

        # The normalized sign-in event includes a boolean new_location flag.
        if event.get("new_location"):
            alerts.append({
                "severity": "low",
                "type": "New Location",
                "user": user,
                "detail": f"New location detected: {event.get('location', 'Unknown')}",
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
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
        user = event.get("user")

        if not user:
            continue

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
                    f"Severity reason: {severity_reason}. "
                    f"Success from new location: {success_from_new_location}. "
                    f"Successful app: {event.get('app_display_name', 'Unknown')}. "
                    f"IP: {event.get('ip_address', 'Unknown')}. "
                    f"Location: {event.get('location', 'Unknown')}. "
                    f"Last failure reason: {latest_failure.get('failure_reason', 'Unknown')}."
                ),
                "location": event.get("location", "Unknown"),
                "source": "Entra Sign-In Logs",
                "cache_clear_user": user,

                # Structured fields for security_alert_history.json and future tuning.
                "failure_count": failure_count,
                "success_from_new_location": success_from_new_location,
                "severity_reason": severity_reason,
                "signin_ip": event.get("ip_address", "Unknown"),
                "signin_app": event.get("app_display_name", "Unknown"),
                "signin_location": event.get("location", "Unknown"),
                "last_failure_reason": latest_failure.get("failure_reason", "Unknown"),
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

    This detector is context-aware but still intentionally simple.

    It does not replace the dedicated detectors for:
    - failed sign-ins followed by success
    - mailbox rules
    - forwarding
    - hide/delete rules
    - sign-in/mailbox correlation

    Instead, it uses nearby context to decide whether a new-location burst is
    just LOW context or should be Teams-visible.

    Severity logic:

    LOW:
    - 3+ successful new-location sign-ins
    - same user
    - same location
    - same IP
    - no failed sign-in context
    - no mailbox activity context
    - no suspicious client/risk context

    MEDIUM:
    - same location/IP burst, but high volume
    - OR same location/IP burst with failed sign-in context
    - OR same location/IP burst with suspicious client/risk context

    HIGH:
    - burst from multiple new locations
    - OR burst from multiple IP addresses
    - OR burst paired with mailbox activity context

    Why:
    Microsoft 365 often creates several successful sign-ins close together from
    normal apps such as Office, SharePoint, Teams, OneDrive, and Outlook.
    That should not page Teams by itself.

    But when new-location burst activity overlaps with failures, mailbox rule
    activity, suspicious client behavior, or multiple IPs/locations, it becomes
    much more useful as a security alert.
    """
    alerts = []

    failed_signin_events = failed_signin_events or []
    mailbox_events = mailbox_events or []

    events_by_user = {}

    for event in events:
        user = event.get("user", "Unknown")

        if user in SUPPRESSED_USERS:
            continue

        if event.get("status") != "success":
            continue

        if not event.get("new_location"):
            continue

        events_by_user.setdefault(user, []).append(event)

    failed_users = {
        str(event.get("user", "")).lower().strip()
        for event in failed_signin_events
        if event.get("status") == "failure"
    }

    mailbox_context_users = {
        str(event.get("user", "")).lower().strip()
        for event in mailbox_events
        if event.get("operation") in MAILBOX_CONFIGURATION_OPERATIONS
    }

    for user, user_events in events_by_user.items():
        if len(user_events) < 3:
            continue

        normalized_user = str(user).lower().strip()

        locations = {
            event.get("location", "Unknown")
            for event in user_events
        }

        ip_addresses = {
            event.get("ip_address", "Unknown")
            for event in user_events
        }

        apps = {
            event.get("app_display_name", "Unknown")
            for event in user_events
        }

        event_count = len(user_events)
        location_count = len(locations)
        ip_count = len(ip_addresses)

        has_failed_context = normalized_user in failed_users
        has_mailbox_context = normalized_user in mailbox_context_users
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
                f"{event_count} successful sign-in(s) from new location activity. "
                f"Reason: {reason}. "
                f"Locations: {', '.join(sorted(locations))}. "
                f"Location count: {location_count}. "
                f"IP address(es): {', '.join(sorted(ip_addresses))}. "
                f"IP count: {ip_count}. "
                f"Apps: {', '.join(sorted(apps))}."
            ),
            "location": ", ".join(sorted(locations)),
            "source": "Entra Sign-In Logs",
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
    # Pull out the strongest anchor alert first: the burst is the main event that
    # provides the most context about the sequence (location, IPs, app mix, volume).
    # This keeps the final merged alert anchored to the real suspicious pattern.
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

    # A burst alone is not enough to create a consolidated sequence alert.
    # We only merge when the burst is paired with additional context that makes
    # the pattern worth summarizing into one higher-level security event.
    if not burst_alerts:
        return None

    if not failed_success_alerts and not unusual_time_alerts:
        return None

    # Use the first burst alert as the anchor because it is the most complete
    # summary of the suspicious activity and the best candidate for correlation.
    best_burst_alert = burst_alerts[0]

    # Build the list of related alerts that are temporally and contextually tied
    # to this burst, using shared user, location, and/or IP characteristics.
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

    # If the burst had no valid supporting alerts, do not collapse the event.
    # The original individual alerts should remain visible instead of being merged.
    if not related_alerts:
        return None

    # Preserve the anchor alert first so the merged summary keeps the most
    # informative signal at the front, then append only the related evidence.
    merged_alerts = [best_burst_alert] + related_alerts

    # Choose the effective user from the anchor or first related alert, falling
    # back to "Unknown" if neither provides a value.
    user = best_burst_alert.get("user") or related_alerts[0].get("user") or "Unknown"

    # Summarize the combined evidence across all merged alerts so the final alert
    # is readable and easier for analysts to audit.
    location = build_sequence_location_summary(merged_alerts)
    ip_summary = build_sequence_ip_summary(merged_alerts)
    app_summary = build_sequence_app_summary(merged_alerts)

    # Explain why the merged sequence is suspicious, combining the factors that
    # contributed to the final alert.
    sequence_reason = build_sequence_reason(
        has_failed_success=bool(failed_success_alerts),
        unusual_time_count=len(unusual_time_alerts),
        has_burst=True,
    )

    # Severity is based on the combined evidence of the sequence rather than any
    # single detector in isolation.
    severity = get_sequence_severity(merged_alerts)

    # Create a concise but explainable summary for Teams or reporting output.
    detail = (
        "Suspicious sign-in sequence detected. "
        f"Reason: {sequence_reason}. "
        "Formula: "
        f"{build_sequence_formula(merged_alerts)}. "
        f"User: {user}. "
        f"Locations: {location}. "
        f"IP address(es): {ip_summary}. "
        f"Apps: {app_summary}. "
        "Merged alert evidence: "
        f"{build_merged_alert_evidence(merged_alerts)}"
    )

    # Return a single consolidated alert object that preserves the original
    # evidence list and the full set of correlated alert types.
    return {
        "type": "Suspicious Sign-in Sequence",
        "severity": severity,
        "user": user,
        "location": location,
        "source": "Entra Sign-In Logs",
        "detail": detail,
        "ip_address": ip_summary,
        "merged_alerts": merged_alerts,
        "correlated_alert_types": [
            alert.get("type") for alert in merged_alerts
        ],
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
        detail = str(alert.get("detail", ""))

        if "App:" in detail:
            after_marker = detail.split("App:", 1)[1].strip()
            app_text = after_marker.split(".")[0].strip()

            if app_text:
                apps.add(app_text)

            for app in app_text.split(","):
                cleaned_app = app.strip()
                if cleaned_app:
                    apps.add(cleaned_app)

        if "Successful app:" in detail:
            after_marker = detail.split("Successful app:", 1)[1].strip()
            app_text = after_marker.split(".")[0].strip()

            if app_text:
                apps.add(app_text)

        app_display_name = alert.get("app_display_name")
        if app_display_name:
            apps.add(str(app_display_name).strip())

    if not apps:
        return "Unknown"

    return ", ".join(sorted(apps))


def extract_locations_from_alert(alert):
    """
    Extract location values from the alert location field and detail text.

    Supports:
    - alert["location"]
    - "Locations: location1, location2."
    - "Location: location."
    """
    locations = set()

    location_value = alert.get("location")
    if location_value:
        for location in split_location_list(location_value):
            locations.add(location)

    detail = str(alert.get("detail", ""))

    if "Locations:" in detail:
        after_marker = detail.split("Locations:", 1)[1].strip()
        location_text = after_marker.split(".")[0].strip()

        for location in split_location_list(location_text):
            locations.add(location)

    elif "Location:" in detail:
        after_marker = detail.split("Location:", 1)[1].strip()
        location_text = after_marker.split(".")[0].strip()

        for location in split_location_list(location_text):
            locations.add(location)

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
    - "IP: x.x.x.x"
    - "IP address(es): x.x.x.x, y.y.y.y"
    """
    ips = set()

    ip_value = alert.get("ip_address")
    if ip_value:
        for ip in split_ip_list(ip_value):
            ips.add(ip)

    detail = str(alert.get("detail", ""))

    if "IP address(es):" in detail:
        after_marker = detail.split("IP address(es):", 1)[1].strip()
        ip_text = after_marker.split(". ")[0].strip()
        ip_text = ip_text.split(" Apps:")[0].strip()

        for ip in split_ip_list(ip_text):
            ips.add(ip)

    elif "IP:" in detail:
        after_marker = detail.split("IP:", 1)[1].strip()
        ip_text = after_marker.split(". ")[0].strip()
        ip_text = ip_text.split(" Location:")[0].strip()
        ip_text = ip_text.split(" Apps:")[0].strip()

        for ip in split_ip_list(ip_text):
            ips.add(ip)

    return {
        normalize_display_value(ip)
        for ip in ips
        if normalize_display_value(ip)
    }


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

    text = str(value).strip()

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

    # A single location should stay whole.
    return [text]


def split_ip_list(value):
    """
    Split an IP list while preserving IPv6 addresses.

    IPv6 addresses contain colons, so we only split on comma separators.

    This also removes trailing sentence punctuation from alert detail text.
    Example:
    - "2605:59ca:...:b78." becomes "2605:59ca:...:b78"
    """
    if not value:
        return []

    cleaned_ips = []

    for item in str(value).split(","):
        cleaned_ip = item.strip()

        # Remove common punctuation that may appear because the IP was pulled
        # from a human-readable sentence.
        cleaned_ip = cleaned_ip.strip()
        cleaned_ip = cleaned_ip.rstrip(".;")

        if not cleaned_ip:
            continue

        if cleaned_ip.lower() in {"unknown", "n/a"}:
            continue

        cleaned_ips.append(cleaned_ip)

    return cleaned_ips


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