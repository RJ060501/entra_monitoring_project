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

