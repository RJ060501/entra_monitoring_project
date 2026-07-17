"""
SQLite storage layer for the Entra Monitoring Project.

This module is intentionally small and conservative for V1.1.

Initial purpose:
- Store phishing report metadata harvested from the phishing-report mailbox.
- Preserve analyst/manual verdicts for future reporting and ML use.
- Avoid storing full raw email bodies by default.

Database location:
- state/entra_monitor.db

Why SQLite first:
- No separate database server required.
- Easy to back up.
- Easy to inspect locally.
- Good bridge before PostgreSQL or SIEM output.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


# Resolve the repository root and the state directory relative to this file.
# The SQLite database file is stored under state/entra_monitor.db.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
DATABASE_PATH = STATE_DIR / "entra_monitor.db"


def get_utc_now():
    """
    Return the current UTC timestamp as an ISO string.

    SQLite does not enforce timezone-aware datetime types, so we store timestamps
    as strings in ISO-8601 format.
    """
    return datetime.now(timezone.utc).isoformat()


def get_connection():
    """
    Return a SQLite database connection.

    This function ensures the state directory exists before opening the
    database file. It also configures SQLite to return rows as dictionaries
    via sqlite3.Row so callers can use column names instead of numeric index.
    """
    STATE_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create database tables and indexes if they do not already exist.

    This initialization is idempotent; calling it multiple times does not
    recreate existing tables or indexes because the SQL uses IF NOT EXISTS.
    """
    with get_connection() as connection:
        cursor = connection.cursor()

        # Create the main phishing report table, which stores metadata for
        # each report and the current manual review state.

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                report_message_id TEXT UNIQUE,
                internet_message_id TEXT,

                report_received_time TEXT,
                collected_at TEXT NOT NULL,

                reporting_user TEXT,
                original_sender TEXT,
                original_sender_domain TEXT,
                reply_to TEXT,

                subject TEXT,
                received_time TEXT,

                has_attachments INTEGER DEFAULT 0,
                attachment_count INTEGER DEFAULT 0,
                url_count INTEGER DEFAULT 0,

                body_text_sample TEXT,

                microsoft_verdict TEXT,
                manual_verdict TEXT DEFAULT 'unknown',
                review_status TEXT DEFAULT 'new',

                reviewed_by TEXT,
                reviewed_at TEXT,
                notes TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_report_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                phishing_report_id INTEGER NOT NULL,

                url TEXT NOT NULL,
                domain TEXT,

                created_at TEXT NOT NULL,

                FOREIGN KEY (phishing_report_id)
                    REFERENCES phishing_reports(id)
                    ON DELETE CASCADE
            )
        """)

        # Child table for attachment metadata extracted from each report.
        # These rows reference phishing_reports(id) and cascade deletes when the
        # parent report is removed.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_report_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                phishing_report_id INTEGER NOT NULL,

                filename TEXT,
                extension TEXT,
                content_type TEXT,
                size_bytes INTEGER,

                created_at TEXT NOT NULL,

                FOREIGN KEY (phishing_report_id)
                    REFERENCES phishing_reports(id)
                    ON DELETE CASCADE
            )
        """)

        # Stores a history of manual verdict changes. Each update creates a
        # new record so you can audit changes over time.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_report_verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                phishing_report_id INTEGER NOT NULL,

                verdict TEXT NOT NULL,
                reviewed_by TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,

                FOREIGN KEY (phishing_report_id)
                    REFERENCES phishing_reports(id)
                    ON DELETE CASCADE
            )
        """)

        # Create indexes for common filtering operations to improve performance.
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_manual_verdict
            ON phishing_reports(manual_verdict)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_review_status
            ON phishing_reports(review_status)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_sender_domain
            ON phishing_reports(original_sender_domain)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_report_urls_domain
            ON phishing_report_urls(domain)
        """)

        connection.commit()


def insert_phishing_report(report):
    """
    Insert a phishing report into SQLite.

    This helper performs the full insert workflow for a single phishing report:
    1. Ensure the database schema exists.
    2. Insert the main report row into phishing_reports.
    3. Retrieve the inserted or existing report id.
    4. Insert any associated URLs and attachments as child rows.

    Expected report dictionary keys:
    - report_message_id
    - internet_message_id
    - report_received_time
    - reporting_user
    - original_sender
    - original_sender_domain
    - reply_to
    - subject
    - received_time
    - has_attachments
    - attachment_count
    - url_count
    - body_text_sample
    - microsoft_verdict
    - urls
    - attachments

    If report_message_id already exists, the main row insert is ignored, and
    the existing database id is returned.
    """
    initialize_database()

    urls = report.get("urls", []) or []
    attachments = report.get("attachments", []) or []

    collected_at = get_utc_now()

    with get_connection() as connection:
        cursor = connection.cursor()

        # Insert the main report row. INSERT OR IGNORE avoids duplicates when the
        # same message has already been recorded by report_message_id.
        cursor.execute(
            """
            INSERT OR IGNORE INTO phishing_reports (
                report_message_id,
                internet_message_id,
                report_received_time,
                collected_at,
                reporting_user,
                original_sender,
                original_sender_domain,
                reply_to,
                subject,
                received_time,
                has_attachments,
                attachment_count,
                url_count,
                body_text_sample,
                microsoft_verdict,
                manual_verdict,
                review_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.get("report_message_id"),
                report.get("internet_message_id"),
                report.get("report_received_time"),
                collected_at,
                report.get("reporting_user"),
                report.get("original_sender"),
                report.get("original_sender_domain"),
                report.get("reply_to"),
                report.get("subject"),
                report.get("received_time"),
                int(bool(report.get("has_attachments"))),
                int(report.get("attachment_count", 0) or 0),
                int(report.get("url_count", 0) or 0),
                report.get("body_text_sample"),
                report.get("microsoft_verdict"),
                report.get("manual_verdict", "unknown"),
                report.get("review_status", "new"),
            ),
        )

        # Query the row back by report_message_id to get the numeric primary key.
        # This works for both new and previously existing reports.
        cursor.execute(
            """
            SELECT id
            FROM phishing_reports
            WHERE report_message_id = ?
            """,
            (report.get("report_message_id"),),
        )

        row = cursor.fetchone()

        if not row:
            # If the report could not be found, commit any pending work and
            # return None to signal failure.
            connection.commit()
            return None

        phishing_report_id = row["id"]

        # Persist associated URL data for this report.
        for url_entry in urls:
            cursor.execute(
                """
                INSERT INTO phishing_report_urls (
                    phishing_report_id,
                    url,
                    domain,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    phishing_report_id,
                    url_entry.get("url"),
                    url_entry.get("domain"),
                    collected_at,
                ),
            )

        # Persist associated attachment metadata for this report.
        for attachment in attachments:
            cursor.execute(
                """
                INSERT INTO phishing_report_attachments (
                    phishing_report_id,
                    filename,
                    extension,
                    content_type,
                    size_bytes,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    phishing_report_id,
                    attachment.get("filename"),
                    attachment.get("extension"),
                    attachment.get("content_type"),
                    attachment.get("size_bytes"),
                    collected_at,
                ),
            )

        # Commit all inserts in a single transaction so the report and its child
        # records are persisted together atomically.
        connection.commit()

        return phishing_report_id


def update_phishing_report_verdict(
    phishing_report_id,
    verdict,
    reviewed_by=None,
    notes=None,
):
    """
    Update the manual verdict for a phishing report.

    This function updates the current status of the report in
    `phishing_reports` and also appends a historical entry to
    `phishing_report_verdicts` so review actions are preserved.

    Suggested verdict values:
    - malicious
    - spam
    - benign
    - simulation
    - unknown
    - needs_escalation
    """
    reviewed_at = get_utc_now()

    with get_connection() as connection:
        cursor = connection.cursor()

        # Update the main report row with the user-provided verdict and review metadata.
        # The review_status field is set to 'reviewed' to indicate the item has been processed.
        cursor.execute(
            """
            UPDATE phishing_reports
            SET manual_verdict = ?,
                review_status = 'reviewed',
                reviewed_by = ?,
                reviewed_at = ?,
                notes = ?
            WHERE id = ?
            """,
            (
                verdict,
                reviewed_by,
                reviewed_at,
                notes,
                phishing_report_id,
            ),
        )

        # Record the verdict in a separate history table so the audit trail is
        # preserved even when manual_verdict is later changed.
        cursor.execute(
            """
            INSERT INTO phishing_report_verdicts (
                phishing_report_id,
                verdict,
                reviewed_by,
                notes,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                phishing_report_id,
                verdict,
                reviewed_by,
                notes,
                reviewed_at,
            ),
        )

        connection.commit()


def get_recent_phishing_reports(limit=25):
    """
    Return recent phishing reports for quick review.

    This helper retrieves the latest reports ordered by the collection time
    so dashboards and review lists can show the newest items first.

    Args:
        limit: Maximum number of report rows to return.

    Returns:
        A list of dictionaries representing recent phishing reports.
    """
    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM phishing_reports
            ORDER BY collected_at DESC
            LIMIT ?
            """,
            (limit,),
        )

        # Return a list of plain dictionaries instead of sqlite3.Row objects.
        return [dict(row) for row in cursor.fetchall()]


def get_unreviewed_phishing_reports(limit=25):
    """
    Return phishing reports that still need manual review.

    This helper builds a review queue of reports whose review status is
    still `new`. It is useful for dashboards and workflows that focus on
    unprocessed items before any analyst action.

    Args:
        limit: Maximum number of report rows to return.

    Returns:
        A list of dictionaries representing unreviewed phishing reports.
    """
    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM phishing_reports
            WHERE review_status = 'new'
            ORDER BY collected_at DESC
            LIMIT ?
            """,
            (limit,),
        )

        return [dict(row) for row in cursor.fetchall()]