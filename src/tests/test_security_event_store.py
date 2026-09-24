"""
Tests for the source-agnostic SQLite event store.

These tests use a temporary database and do not touch the real state folder.
"""

from storage.security_event_store import (
    get_recent_alerts,
    get_recent_source_events,
    get_source_events_for_user,
    initialize_database,
    insert_alert,
    insert_alerts,
    insert_source_event,
    insert_source_events,
)


def test_initialize_database_creates_tables(tmp_path):
    database_path = tmp_path / "security_events.db"

    initialize_database(database_path)

    assert database_path.exists()


def test_insert_source_event_is_queryable(tmp_path):
    database_path = tmp_path / "security_events.db"

    event = {
        "id": "signin-001",
        "created_datetime": "2026-09-23T14:00:00Z",
        "user": "test.user@resolutgroup.com",
        "status": "success",
        "ip_address": "1.2.3.4",
        "location": "Salt Lake City, Utah, US",
        "app_display_name": "OfficeHome",
    }

    event_id = insert_source_event(
        event=event,
        source="microsoft_entra",
        event_type="signin",
        database_path=database_path,
    )

    assert event_id is not None

    recent_events = get_recent_source_events(
        limit=10,
        database_path=database_path,
    )

    assert len(recent_events) == 1
    assert recent_events[0]["source"] == "microsoft_entra"
    assert recent_events[0]["event_type"] == "signin"
    assert recent_events[0]["user"] == "test.user@resolutgroup.com"
    assert recent_events[0]["ip_address"] == "1.2.3.4"


def test_insert_source_event_is_idempotent_by_source_event_id(tmp_path):
    database_path = tmp_path / "security_events.db"

    event = {
        "id": "same-event-id",
        "created_datetime": "2026-09-23T14:00:00Z",
        "user": "test.user@resolutgroup.com",
        "status": "success",
    }

    first_id = insert_source_event(
        event=event,
        source="microsoft_entra",
        event_type="signin",
        database_path=database_path,
    )

    second_id = insert_source_event(
        event=event,
        source="microsoft_entra",
        event_type="signin",
        database_path=database_path,
    )

    recent_events = get_recent_source_events(
        limit=10,
        database_path=database_path,
    )

    assert first_id == second_id
    assert len(recent_events) == 1


def test_insert_multiple_source_events(tmp_path):
    database_path = tmp_path / "security_events.db"

    events = [
        {
            "id": "signin-001",
            "created_datetime": "2026-09-23T14:00:00Z",
            "user": "one@resolutgroup.com",
            "status": "success",
        },
        {
            "id": "signin-002",
            "created_datetime": "2026-09-23T14:01:00Z",
            "user": "two@resolutgroup.com",
            "status": "failure",
        },
    ]

    result = insert_source_events(
        events=events,
        source="microsoft_entra",
        event_type="signin",
        database_path=database_path,
    )

    assert result["attempted"] == 2
    assert len(result["event_ids"]) == 2

    recent_events = get_recent_source_events(
        limit=10,
        database_path=database_path,
    )

    assert len(recent_events) == 2


def test_get_source_events_for_user(tmp_path):
    database_path = tmp_path / "security_events.db"

    events = [
        {
            "id": "signin-001",
            "created_datetime": "2026-09-23T14:00:00Z",
            "user": "target.user@resolutgroup.com",
            "status": "success",
        },
        {
            "id": "signin-002",
            "created_datetime": "2026-09-23T14:01:00Z",
            "user": "other.user@resolutgroup.com",
            "status": "success",
        },
    ]

    insert_source_events(
        events=events,
        source="microsoft_entra",
        event_type="signin",
        database_path=database_path,
    )

    user_events = get_source_events_for_user(
        user="target.user@resolutgroup.com",
        database_path=database_path,
    )

    assert len(user_events) == 1
    assert user_events[0]["user"] == "target.user@resolutgroup.com"


def test_insert_alert_is_queryable(tmp_path):
    database_path = tmp_path / "security_events.db"

    alert = {
        "type": "New Location Sign-in Burst",
        "severity": "medium",
        "user": "test.user@resolutgroup.com",
        "source": "Entra Sign-In Logs",
        "location": "Salt Lake City, Utah, US",
        "ip_address": "1.2.3.4",
        "detail": "Test alert detail.",
        "created_datetime": "2026-09-23T14:00:00Z",
    }

    alert_id = insert_alert(
        alert=alert,
        delivery_status="active",
        database_path=database_path,
    )

    assert alert_id is not None

    recent_alerts = get_recent_alerts(
        limit=10,
        database_path=database_path,
    )

    assert len(recent_alerts) == 1
    assert recent_alerts[0]["alert_type"] == "New Location Sign-in Burst"
    assert recent_alerts[0]["severity"] == "medium"
    assert recent_alerts[0]["delivery_status"] == "active"


def test_insert_alert_is_idempotent(tmp_path):
    database_path = tmp_path / "security_events.db"

    alert = {
        "type": "External Mail Forwarding Detected",
        "severity": "critical",
        "user": "test.user@resolutgroup.com",
        "source": "Microsoft 365 Audit Logs",
        "location": "N/A - Exchange audit event",
        "detail": "Mailbox rule forwards emails outside the organization.",
    }

    first_id = insert_alert(
        alert=alert,
        delivery_status="active",
        database_path=database_path,
    )

    second_id = insert_alert(
        alert=alert,
        delivery_status="active",
        database_path=database_path,
    )

    recent_alerts = get_recent_alerts(
        limit=10,
        database_path=database_path,
    )

    assert first_id == second_id
    assert len(recent_alerts) == 1


def test_insert_multiple_alerts(tmp_path):
    database_path = tmp_path / "security_events.db"

    alerts = [
        {
            "type": "Alert One",
            "severity": "medium",
            "user": "one@resolutgroup.com",
            "source": "Unit Test",
            "detail": "First alert.",
        },
        {
            "type": "Alert Two",
            "severity": "high",
            "user": "two@resolutgroup.com",
            "source": "Unit Test",
            "detail": "Second alert.",
        },
    ]

    result = insert_alerts(
        alerts=alerts,
        delivery_status="active",
        database_path=database_path,
    )

    assert result["attempted"] == 2
    assert len(result["alert_ids"]) == 2

    recent_alerts = get_recent_alerts(
        limit=10,
        database_path=database_path,
    )

    assert len(recent_alerts) == 2
