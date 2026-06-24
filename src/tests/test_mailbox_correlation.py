"""
Mailbox Correlation Tests

These tests validate cross-run sign-in/mailbox correlation logic.

Scenarios tested:
1. Cached suspicious sign-in + new inbox rule = alert
2. New suspicious sign-in + cached inbox rule = alert
3. Suspicious sign-in + external forwarding = critical
4. Suspicious sign-in + hide/delete rule:
   - within 60 minutes = critical
   - within 24 hours = high

These tests use normalized fake events so they do not depend on live Microsoft
API data.
"""

from detectors.correlation_detector import detect_correlations


TEST_USER = "test.user@resolutgroup.com"


def make_signin_event(
    event_id,
    created_datetime,
    user=TEST_USER,
    status="success",
    new_location=True,
    app_display_name="Microsoft Office",
    ip_address="203.0.113.10",
    location="Ashburn, Virginia, US",
):
    """
    Build a normalized sign-in event.

    new_location=True makes this suspicious enough for correlation.
    """
    return {
        "id": event_id,
        "user": user,
        "created_datetime": created_datetime,
        "status": status,
        "new_location": new_location,
        "hour": 12,
        "app_display_name": app_display_name,
        "ip_address": ip_address,
        "location": location,
        "risk_level_aggregated": "none",
        "conditional_access_status": "success",
        "risk_detail": "none",
        "raw": "",
    }


def make_email_event(
    event_id,
    created_datetime,
    operation,
    raw,
    user=TEST_USER,
    target="Inbox rule",
):
    """
    Build a normalized Microsoft 365 audit event.
    """
    return {
        "id": event_id,
        "user": user,
        "created_datetime": created_datetime,
        "operation": operation,
        "target": target,
        "raw": raw,
        "source": "Microsoft 365 Audit Logs",
    }


def print_alerts(alerts):
    """
    Print generated alerts in a readable format.
    """
    if not alerts:
        print("No alerts generated.")
        return

    for alert in alerts:
        print(alert["severity"].upper(), "-", alert["type"])
        print("User:", alert["user"])
        print("Detail:", alert["detail"])
        print()


def assert_alert_exists(alerts, expected_severity):
    """
    Fail loudly if the expected alert severity is missing.
    """
    severities = {
        str(alert.get("severity", "")).lower()
        for alert in alerts
    }

    assert expected_severity in severities, (
        f"Expected {expected_severity.upper()} alert, "
        f"but got severities: {sorted(severities)}"
    )


def test_cached_signin_new_inbox_rule():
    """
    Cached suspicious sign-in + new inbox rule should alert.

    Simulates:
    Run 1: suspicious sign-in is cached
    Run 2: inbox rule appears
    """
    print("\n=== TEST 1: CACHED SIGN-IN + NEW INBOX RULE ===")

    cached_signins = [
        make_signin_event(
            event_id="signin-cached-1",
            created_datetime="2026-06-02T12:30:00Z",
        )
    ]

    new_email_events = [
        make_email_event(
            event_id="email-new-rule-1",
            created_datetime="2026-06-02T12:45:00Z",
            operation="New-InboxRule",
            raw="Created inbox rule named TestRule",
        )
    ]

    alerts = detect_correlations(
        signin_events=[],
        email_events=new_email_events,
        cached_signins=cached_signins,
    )

    print_alerts(alerts)
    assert_alert_exists(alerts, "high")


def test_new_signin_cached_inbox_rule():
    """
    New suspicious sign-in + cached inbox rule should alert.

    Simulates:
    Run 1: inbox rule is cached
    Run 2: suspicious sign-in appears
    """
    print("\n=== TEST 2: NEW SIGN-IN + CACHED INBOX RULE ===")

    new_signins = [
        make_signin_event(
            event_id="signin-new-1",
            created_datetime="2026-06-02T12:45:00Z",
        )
    ]

    cached_email_events = [
        make_email_event(
            event_id="email-cached-rule-1",
            created_datetime="2026-06-02T12:30:00Z",
            operation="New-InboxRule",
            raw="Created inbox rule named TestRule",
        )
    ]

    alerts = detect_correlations(
        signin_events=new_signins,
        email_events=[],
        cached_email_events=cached_email_events,
    )

    print_alerts(alerts)
    assert_alert_exists(alerts, "high")


def test_external_forwarding_critical():
    """
    Suspicious sign-in + external forwarding within 24 hours should be critical.
    """
    print("\n=== TEST 3: EXTERNAL FORWARDING = CRITICAL ===")

    signins = [
        make_signin_event(
            event_id="signin-forwarding-1",
            created_datetime="2026-06-02T12:30:00Z",
        )
    ]

    email_events = [
        make_email_event(
            event_id="email-forwarding-1",
            created_datetime="2026-06-02T13:00:00Z",
            operation="Set-Mailbox",
            raw=(
                "ForwardingSmtpAddress changed to attacker@example.com "
                "DeliverToMailboxAndForward enabled"
            ),
            target="Mailbox forwarding",
        )
    ]

    alerts = detect_correlations(
        signin_events=signins,
        email_events=email_events,
    )

    print_alerts(alerts)
    assert_alert_exists(alerts, "critical")


def test_hide_delete_rule_critical_within_60_minutes():
    """
    Suspicious sign-in + hide/delete inbox rule within 60 minutes should be
    critical.
    """
    print("\n=== TEST 4: HIDE/DELETE RULE WITHIN 60 MINUTES = CRITICAL ===")

    signins = [
        make_signin_event(
            event_id="signin-hide-delete-1",
            created_datetime="2026-06-02T12:30:00Z",
        )
    ]

    email_events = [
        make_email_event(
            event_id="email-hide-delete-1",
            created_datetime="2026-06-02T13:00:00Z",
            operation="New-InboxRule",
            raw="Created rule to markasread and move messages to archive",
            target="Inbox rule",
        )
    ]

    alerts = detect_correlations(
        signin_events=signins,
        email_events=email_events,
    )

    print_alerts(alerts)
    assert_alert_exists(alerts, "critical")


def test_hide_delete_rule_high_within_24_hours():
    """
    Suspicious sign-in + hide/delete inbox rule after 60 minutes but within
    24 hours should be high.
    """
    print("\n=== TEST 5: HIDE/DELETE RULE WITHIN 24 HOURS = HIGH ===")

    signins = [
        make_signin_event(
            event_id="signin-hide-delete-2",
            created_datetime="2026-06-02T12:30:00Z",
        )
    ]

    email_events = [
        make_email_event(
            event_id="email-hide-delete-2",
            created_datetime="2026-06-02T15:30:00Z",
            operation="New-InboxRule",
            raw="Created rule to markasread and move messages to archive",
            target="Inbox rule",
        )
    ]

    alerts = detect_correlations(
        signin_events=signins,
        email_events=email_events,
    )

    print_alerts(alerts)
    assert_alert_exists(alerts, "high")


def main():
    """
    Run all mailbox correlation tests.
    """
    test_cached_signin_new_inbox_rule()
    test_new_signin_cached_inbox_rule()
    test_external_forwarding_critical()
    test_hide_delete_rule_critical_within_60_minutes()
    test_hide_delete_rule_high_within_24_hours()

    print("\nAll mailbox correlation tests passed.")


if __name__ == "__main__":
    main()