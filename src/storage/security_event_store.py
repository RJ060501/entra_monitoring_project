"""
Source-agnostic SQLite event store for the Entra monitoring project.

Purpose:
- Store normalized security source events from any system.
- Store generated alerts from any detector/correlation engine.
- Preserve full raw JSON for future dashboards, reporting, and AI triage.

This is intentionally not Graph-specific.

Examples of future event sources:
- Microsoft Entra sign-in logs
- Microsoft Entra audit logs
- Microsoft 365 / Exchange audit logs
- Sophos firewall/VPN logs
- Defender alerts
- Freshservice tickets
- Windows event logs
"""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DATABASE_PATH = "state/security_events.db"

def get_database_path(database_path=none):
    """
    Resolve the database path.

    Priority:
    1. Explicit database_path argument
    2. SECURITY_EVENT_DB_PATH environment variable
    3. Default state/security_events.db

    The default works both locally and in Docker because ./state is mounted to
    /app/state in docker-compose.yml.
    """
    return database_path or os.getenv(
        "SECURITY_EVENT_DB_PATH",
        DEFAULT_DATABASE_PATH
    )
    
def get_utc_now_iso():
    """
    Return the current UTC time as an ISO 8601 formatted string.
    """
    return datetime.now(timezone.utc).isoformat()

def json_dumps(value):
    """
    Serialize data as stable JSON.

    default=str prevents datetime or other unusual values from breaking storage.
    """
    return json.dumps(
        value,
        sort_keys=True,
        default=str
    )
    
def connect_database(database_path=None):
    """
    Connect to the SQLite database.

    Args:
        database_path (str, optional): Path to the SQLite database file.
            If not provided, the default path will be used.

    Returns:
        sqlite3.Connection: Connection object to the SQLite database.
    """
    # Resolve the configured database path, falling back to the default if none is provided.
    resolved_path = Path(get_database_path(database_path))
    # Ensure the parent directory exists before creating or opening the SQLite file.
    resolved_path.parent.mkdir(parents=True, exist_ok=True)

    # Open the SQLite database connection to the resolved file path.
    connection = sqlite3.connect(resolved_path)
    # Return rows as sqlite3.Row objects so callers can access fields by name.
    connection.row_factory = sqlite3.Row

    return connection

def initialize_database(database_path=None):
    """
    Create database tables and indexes if they do not already exist.
    """
    with connect_database(database_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        connection.execute("""
            INSERT OR REPLACE INTO metadata (key, value)
            VALUES ('schema_version', '1')
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS source_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                event_hash TEXT NOT NULL UNIQUE,

                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_event_id TEXT,

                event_time_utc TEXT,
                collected_at_utc TEXT NOT NULL,

                user TEXT,
                ip_address TEXT,
                location TEXT,
                app TEXT,
                operation TEXT,
                status TEXT,

                summary TEXT,
                raw_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_source_events_source_id
            ON source_events (source, source_event_id)
            WHERE source_event_id IS NOT NULL
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_events_time
            ON source_events (event_time_utc)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_events_source_type
            ON source_events (source, event_type)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_events_user
            ON source_events (user)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_source_events_ip
            ON source_events (ip_address)
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                alert_hash TEXT NOT NULL UNIQUE,

                created_at_utc TEXT NOT NULL,
                stored_at_utc TEXT NOT NULL,

                delivery_status TEXT NOT NULL,

                severity TEXT,
                alert_type TEXT,
                user TEXT,
                source TEXT,
                location TEXT,
                ip_address TEXT,

                detail TEXT,
                alert_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at
            ON alerts (created_at_utc)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_user
            ON alerts (user)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_type
            ON alerts (alert_type)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts (severity)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_delivery_status
            ON alerts (delivery_status)
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_event_links (
                alert_id INTEGER NOT NULL,
                source_event_id INTEGER NOT NULL,
                relationship TEXT NOT NULL DEFAULT 'related',

                PRIMARY KEY (alert_id, source_event_id, relationship),

                FOREIGN KEY (alert_id)
                    REFERENCES alerts (id)
                    ON DELETE CASCADE,

                FOREIGN KEY (source_event_id)
                    REFERENCES source_events (id)
                    ON DELETE CASCADE
            )
        """)
        
def clean_string(value):
    """
    Normalize values for database storage.
    """
    if value is None:
        return None
    
    cleaned_value = str(value).strip()
    
    if not cleaned_value:
        return None
    
    return cleaned_value

def extract_source_event_id(event):
    """
    Extract the best available source event ID.

    Different systems use different names:
    - Microsoft Graph sign-ins commonly use id
    - M365 audit logs may use Id, RecordId, or other fields depending on parser
    """
    return clean_string(
        get_first_value(
            event,
            [
                "id",
                "Id",
                "event_id",
                "record_id",
                "RecordId",
                "source_event_id",
                "audit_id",
            ],
        )
    )

def extract_event_time(event):
    """
    Extract the best available event timestamp.

    This field is named event_time_utc, but this function stores the original
    timestamp string for now. Most Microsoft timestamps are already UTC ISO
    strings. Later we can add strict UTC normalization if needed.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "created_datetime",
                "createdDateTime",
                "activityDateTime",
                "CreationTime",
                "creation_time",
                "event_time",
                "time",
                "timestamp",
            ],
        )
    )


def extract_event_user(event):
    """
    Extract the best available user identity from a source event.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "user",
                "userPrincipalName",
                "UserId",
                "user_id",
                "mailbox_owner",
                "actor",
                "target_user",
            ],
        )
    )


def extract_event_ip(event):
    """
    Extract the best available IP address from a source event.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "ip_address",
                "ipAddress",
                "ClientIP",
                "client_ip",
                "source_ip",
                "IPAddress",
            ],
        )
    )


def extract_event_location(event):
    """
    Extract the best available location from a source event.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "location",
                "signin_location",
                "Location",
                "city_state_country",
            ],
        )
    )


def extract_event_app(event):
    """
    Extract the best available application/client name from a source event.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "app_display_name",
                "appDisplayName",
                "Application",
                "application",
                "client_app",
                "workload",
            ],
        )
    )


def extract_event_operation(event):
    """
    Extract the best available operation/action from a source event.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "operation",
                "Operation",
                "activityDisplayName",
                "activity",
                "action",
                "event_name",
            ],
        )
    )


def extract_event_status(event):
    """
    Extract the best available event status.
    """
    return clean_string(
        get_first_value(
            event,
            [
                "status",
                "result",
                "ResultStatus",
                "outcome",
            ],
        )
    )
    
def build_event_summary(event):
    """
    Build a short source-agnostic summary for quick CLI/dashboard display.
    """
    operation = extract_event_operation(event)
    app = extract_event_app(event)
    status = extract_event_status(event)
    location = extract_event_location(event)

    parts = []

    if operation:
        parts.append(f"operation={operation}")

    if app:
        parts.append(f"app={app}")

    if status:
        parts.append(f"status={status}")

    if location:
        parts.append(f"location={location}")

    if not parts:
        return "No summary fields available"

    return "; ".join(parts)

def build_source_event_hash(event, source, event_type):
    """
    Build a stable hash for source event deduplication.

    If the source provides a real event ID, use that. Otherwise use the full
    event JSON as the fallback.
    
    Hash used to tell whether we've seen this event before.
    """
    source_event_id = extract_source_event_id(event)

    if source_event_id:
        hash_payload = {
            "source": source,
            "event_type": event_type,
            "source_event_id": source_event_id,
        }
    else:
        hash_payload = {
            "source": source,
            "event_type": event_type,
            "event": event,
        }

    return hashlib.sha256(
        json_dumps(hash_payload).encode("utf-8")
    ).hexdigest()

def insert_source_event(
    event,
    source,
    event_type,
    database_path=None,
):
    """
    Insert one source event into SQLite.

    Returns:
        The source_events.id value for the inserted or existing event.
    """
    initialize_database(database_path)

    event_hash = build_source_event_hash(
        event=event,
        source=source,
        event_type=event_type,
    )

    source_event_id = extract_source_event_id(event)
    collected_at_utc = get_utc_now_iso()
    raw_json = json_dumps(event)

    with connect_database(database_path) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO source_events (
                event_hash,
                source,
                event_type,
                source_event_id,
                event_time_utc,
                collected_at_utc,
                user,
                ip_address,
                location,
                app,
                operation,
                status,
                summary,
                raw_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_hash,
                source,
                event_type,
                source_event_id,
                extract_event_time(event),
                collected_at_utc,
                extract_event_user(event),
                extract_event_ip(event),
                extract_event_location(event),
                extract_event_app(event),
                extract_event_operation(event),
                extract_event_status(event),
                build_event_summary(event),
                raw_json,
            ),
        )

        row = connection.execute(
            """
            SELECT id
            FROM source_events
            WHERE event_hash = ?
            """,
            (event_hash,),
        ).fetchone()

    if not row:
        return None

    return row["id"]

def insert_source_events(
    events,
    source,
    event_type,
    database_path=None,
):
    """
    Insert multiple source events.

    Returns:
        Dictionary with attempted count and event IDs.
    """
    events = events or []
    event_ids = []

    for event in events:
        event_id = insert_source_event(
            event=event,
            source=source,
            event_type=event_type,
            database_path=database_path,
        )

        if event_id:
            event_ids.append(event_id)

    return {
        "attempted": len(events),
        "event_ids": event_ids,
    }
    