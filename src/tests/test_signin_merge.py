"""
Tests for V2 sign-in alert merge behavior.

These tests do not call Microsoft Graph, Exchange, Teams, Docker, or any
external service. They only validate the local alert-merging logic.

Goal:
- Related sign-in alerts should merge into one Suspicious Sign-in Sequence.
- Unrelated alerts should remain separate.
- Different users, IPs, and locations should not be over-merged.
"""

from detectors.signin_detector import merge_related_signin_alerts


def unusual_login_time(user, location, ip, severity="medium"):
    """Build a realistic Unusual Login Time alert."""
    return {
        "severity": severity,
        "type": "Unusual Login Time",
        "user": user,
        "detail": (
            "Login at hour 1 UTC. "
            "Reason: unusual login time from a new location. "
            "App: SharePoint Online Web Client Extensibility. "
            f"IP: {ip}."
        ),
        "location": location,
        "source": "Entra Sign-In Logs",
    }


def failed_then_success(user, location, ip, severity="medium"):
    """Build a realistic Failed Sign-ins Followed by Success alert."""
    return {
        "severity": severity,
        "type": "Failed Sign-ins Followed by Success",
        "user": user,
        "detail": (
            "3 failed sign-in(s) followed by success. "
            "Severity reason: failed sign-ins were followed by a successful sign-in from a new location. "
            "Success from new location: True. "
            "Successful app: Microsoft Forms. "
            f"IP: {ip}. "
            f"Location: {location}. "
            "Last failure reason: Error validating credentials due to invalid username or password."
        ),
        "location": location,
        "source": "Entra Sign-In Logs",
    }


def new_location_burst(
    user,
    location,
    ip,
    severity="medium",
    location_count=1,
    ip_count=1,
):
    """Build a realistic New Location Sign-in Burst alert."""
    return {
        "severity": severity,
        "type": "New Location Sign-in Burst",
        "user": user,
        "detail": (
            "4 successful sign-in(s) from new location activity. "
            "Reason: new-location burst paired with failed sign-in context. "
            f"Locations: {location}. "
            f"Location count: {location_count}. "
            f"IP address(es): {ip}. "
            f"IP count: {ip_count}. "
            "Apps: Microsoft Forms, My Profile."
        ),
        "location": location,
        "source": "Entra Sign-In Logs",
    }


def get_sequence_alerts(alerts):
    """Return only Suspicious Sign-in Sequence alerts from a result list."""
    return [
        alert for alert in alerts
        if alert.get("type") == "Suspicious Sign-in Sequence"
    ]


def assert_sequence_count(input_alerts, expected_count):
    """Run merge logic and assert the number of sequence alerts produced."""
    result = merge_related_signin_alerts(input_alerts)
    sequence_alerts = get_sequence_alerts(result)

    assert len(sequence_alerts) == expected_count

    for sequence_alert in sequence_alerts:
        detail = sequence_alert.get("detail", "")
        assert "Formula:" in detail
        assert "Merged alert evidence:" in detail

    return result


def test_failed_then_success_and_burst_merge():
    user = "test.user@resolutgroup.com"
    location = "Denver, Colorado, US"
    ip = "2605:59ca:227e:9610:dc20:99d2:395d:b78"

    result = assert_sequence_count(
        [
            failed_then_success(user, location, ip),
            new_location_burst(user, location, ip),
        ],
        expected_count=1,
    )

    assert len(result) == 1


def test_unusual_login_time_and_burst_merge():
    user = "test.user@resolutgroup.com"
    location = "Denver, Colorado, US"
    ip = "2605:59ca:227e:9610:dc20:99d2:395d:b78"

    result = assert_sequence_count(
        [
            unusual_login_time(user, location, ip),
            new_location_burst(user, location, ip),
        ],
        expected_count=1,
    )

    assert len(result) == 1


def test_failed_then_success_unusual_time_and_burst_merge():
    user = "test.user@resolutgroup.com"
    location = "Denver, Colorado, US"
    ip = "2605:59ca:227e:9610:dc20:99d2:395d:b78"

    result = assert_sequence_count(
        [
            failed_then_success(user, location, ip),
            unusual_login_time(user, location, ip),
            new_location_burst(user, location, ip),
        ],
        expected_count=1,
    )

    assert len(result) == 1


def test_burst_only_does_not_merge():
    user = "test.user@resolutgroup.com"
    location = "Denver, Colorado, US"
    ip = "2605:59ca:227e:9610:dc20:99d2:395d:b78"

    result = assert_sequence_count(
        [
            new_location_burst(user, location, ip),
        ],
        expected_count=0,
    )

    assert len(result) == 1
    assert result[0]["type"] == "New Location Sign-in Burst"


def test_unusual_and_failed_without_burst_do_not_merge():
    user = "test.user@resolutgroup.com"
    location = "Denver, Colorado, US"
    ip = "2605:59ca:227e:9610:dc20:99d2:395d:b78"

    result = assert_sequence_count(
        [
            unusual_login_time(user, location, ip),
            failed_then_success(user, location, ip),
        ],
        expected_count=0,
    )

    assert len(result) == 2


def test_different_users_do_not_merge():
    location = "Denver, Colorado, US"
    ip = "2605:59ca:227e:9610:dc20:99d2:395d:b78"

    result = assert_sequence_count(
        [
            unusual_login_time("other.user@resolutgroup.com", location, ip),
            new_location_burst("test.user@resolutgroup.com", location, ip),
        ],
        expected_count=0,
    )

    assert len(result) == 2


def test_same_user_different_ip_and_location_do_not_merge():
    user = "test.user@resolutgroup.com"

    result = assert_sequence_count(
        [
            unusual_login_time(
                user,
                "Salt Lake City, Utah, US",
                "1.1.1.1",
            ),
            new_location_burst(
                user,
                "Denver, Colorado, US",
                "2605:59ca:227e:9610:dc20:99d2:395d:b78",
            ),
        ],
        expected_count=0,
    )

    assert len(result) == 2


def test_multi_location_vpn_style_burst_can_merge_with_matching_unusual_alert():
    user = "test.user@resolutgroup.com"

    result = assert_sequence_count(
        [
            unusual_login_time(
                user,
                "Walsenburg, Colorado, US",
                "2a09:bac3:69df:183c::26a:12",
            ),
            new_location_burst(
                user,
                "Sunland Park, New Mexico, US, Walsenburg, Colorado, US",
                "2a09:bac2:a2eb:2da5::48c:1e, 2a09:bac3:69df:183c::26a:12",
                location_count=2,
                ip_count=2,
            ),
        ],
        expected_count=1,
    )

    assert len(result) == 1