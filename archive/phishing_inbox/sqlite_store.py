"""
SQLite storage layer for the Entra Monitoring Project.

This module stores phishing-report metadata harvested from the phishing-report
mailbox.

Current purpose:
- Store Microsoft reported-message wrapper metadata.
- Store original-message metadata extracted from the report body/headers.
- Store Outlook category labels used by the IT team during review.
- Store limited original email body samples when available from the attached
  reported message.
- Preserve analyst/manual verdicts for reporting and future ML use.
- Avoid storing full raw email bodies or full attachment contents by default.

Database location:
- state/entra_monitor.db
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Path configuration
# ---------------------------------------------------------------------------
# sqlite_store.py lives here:
# src/storage/sqlite_store.py
#
# parents[2] walks back to the project root:
# src/storage/sqlite_store.py -> storage -> src -> project root
#
# The database is stored under state/ so Docker can persist it through a volume
# and Git can ignore it.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
DATABASE_PATH = STATE_DIR / "entra_monitor.db"


def get_utc_now():
    """
    Return the current UTC timestamp as an ISO-8601 string.

    SQLite stores timestamps as text. UTC keeps the database consistent with
    Microsoft Graph and M365 audit timestamps.
    """
    return datetime.now(timezone.utc).isoformat()


def serialize_json(value):
    """
    Serialize a Python object into JSON text for SQLite storage.

    Used for fields like Outlook categories.
    """
    if value is None:
        return None

    return json.dumps(value, sort_keys=True)


def get_connection():
    """
    Open and return a SQLite database connection.

    This also:
    - Creates the state directory if missing.
    - Enables dictionary-style row access.
    - Enables foreign key enforcement.
    """
    STATE_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    # Required per SQLite connection if we want ON DELETE CASCADE to work.
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def column_exists(cursor, table_name, column_name):
    """
    Return True if a column exists in a SQLite table.

    Used by lightweight migrations.
    """
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row["name"] for row in cursor.fetchall()]

    return column_name in columns


def add_column_if_missing(cursor, table_name, column_name, column_definition):
    """
    Add a column to an existing table if missing.

    CREATE TABLE IF NOT EXISTS does not add new columns to old tables, so this
    lets us safely evolve the schema without deleting data.
    """
    if not column_exists(cursor, table_name, column_name):
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


def initialize_database():
    """
    Create database tables, indexes, and lightweight migrations.

    Safe to run repeatedly.
    """
    with get_connection() as connection:
        cursor = connection.cursor()

        # -------------------------------------------------------------------
        # Main phishing reports table
        # -------------------------------------------------------------------
        # One row per report message in the phishing mailbox.
        #
        # This stores:
        # - The reporting mailbox wrapper.
        # - Microsoft reported-message fields.
        # - Outlook category/review fields.
        # - Original email metadata extracted from wrapper headers.
        # - Original email body preview/sample extracted from the attachment,
        #   when the collector can access it.
        # - Final labels for reporting and later ML.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                -- Reporting mailbox / wrapper metadata
                report_message_id TEXT UNIQUE,
                report_subject TEXT,
                report_received_time TEXT,
                collected_at TEXT NOT NULL,
                last_seen_at TEXT,

                -- Microsoft reported-message / submission metadata
                microsoft_or_report_label TEXT,
                network_message_id TEXT,
                internet_message_id TEXT,

                -- Reporting / reviewer context
                reporting_user TEXT,
                outlook_categories_raw TEXT,

                category_verdict TEXT,
                category_review_status TEXT,
                category_reviewed_by TEXT,
                priority TEXT DEFAULT 'normal',

                -- Original email metadata extracted from wrapper/body/headers
                original_sender TEXT,
                original_sender_domain TEXT,
                reply_to TEXT,
                original_recipient TEXT,
                original_subject TEXT,
                subject TEXT,
                received_time TEXT,
                original_sender_ip TEXT,

                -- Authentication / filtering metadata
                spf_result TEXT,
                dkim_result TEXT,
                dmarc_result TEXT,
                auth_results TEXT,
                scl TEXT,

                -- Wrapper indicators / wrapper content summary
                has_attachments INTEGER DEFAULT 0,
                attachment_count INTEGER DEFAULT 0,
                url_count INTEGER DEFAULT 0,
                body_text_sample TEXT,

                -- Original reported email content extracted from attachment
                original_body_preview TEXT,
                original_body_text_sample TEXT,
                original_url_count INTEGER DEFAULT 0,
                original_attachment_count INTEGER DEFAULT 0,
                original_content_source TEXT,

                -- Review / ML label fields
                microsoft_verdict TEXT,
                manual_verdict TEXT DEFAULT 'unknown',
                review_status TEXT DEFAULT 'new',
                reviewed_by TEXT,
                reviewed_at TEXT,
                notes TEXT,

                -- Remediation tracking
                blocked_in_defender INTEGER DEFAULT 0,
                blocked_at TEXT,
                block_notes TEXT
            )
        """)

        # -------------------------------------------------------------------
        # URL child table
        # -------------------------------------------------------------------
        # Stores URLs extracted from either:
        # - the Microsoft report wrapper, or
        # - the original reported email attachment.
        #
        # source tells us where the URL came from.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_report_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                phishing_report_id INTEGER NOT NULL,

                url TEXT NOT NULL,
                domain TEXT,
                source TEXT DEFAULT 'wrapper',

                created_at TEXT NOT NULL,

                FOREIGN KEY (phishing_report_id)
                    REFERENCES phishing_reports(id)
                    ON DELETE CASCADE
            )
        """)

        # -------------------------------------------------------------------
        # Attachment child table
        # -------------------------------------------------------------------
        # Stores metadata only.
        #
        # We do not store attachment file contents in SQLite.
        #
        # source can be:
        # - report_wrapper
        # - original_email
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_report_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                phishing_report_id INTEGER NOT NULL,

                filename TEXT,
                extension TEXT,
                content_type TEXT,
                size_bytes INTEGER,
                source TEXT DEFAULT 'report_wrapper',

                created_at TEXT NOT NULL,

                FOREIGN KEY (phishing_report_id)
                    REFERENCES phishing_reports(id)
                    ON DELETE CASCADE
            )
        """)

        # -------------------------------------------------------------------
        # Verdict history table
        # -------------------------------------------------------------------
        # Stores verdict/category changes over time.
        #
        # Useful later for auditability and ML label tracking.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_report_verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                phishing_report_id INTEGER NOT NULL,

                verdict TEXT NOT NULL,
                review_status TEXT,
                reviewed_by TEXT,
                notes TEXT,
                source TEXT DEFAULT 'manual',
                created_at TEXT NOT NULL,

                FOREIGN KEY (phishing_report_id)
                    REFERENCES phishing_reports(id)
                    ON DELETE CASCADE
            )
        """)

        # -------------------------------------------------------------------
        # Lightweight migrations for phishing_reports
        # -------------------------------------------------------------------
        # These keep existing databases compatible if you already initialized an
        # older schema before adding original attachment/body support.
        add_column_if_missing(cursor, "phishing_reports", "report_subject", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "last_seen_at", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "microsoft_or_report_label", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "network_message_id", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "outlook_categories_raw", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "category_verdict", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "category_review_status", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "category_reviewed_by", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "priority", "TEXT DEFAULT 'normal'")
        add_column_if_missing(cursor, "phishing_reports", "original_recipient", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "original_subject", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "original_sender_ip", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "spf_result", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "dkim_result", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "dmarc_result", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "auth_results", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "scl", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "original_body_preview", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "original_body_text_sample", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "original_url_count", "INTEGER DEFAULT 0")
        add_column_if_missing(cursor, "phishing_reports", "original_attachment_count", "INTEGER DEFAULT 0")
        add_column_if_missing(cursor, "phishing_reports", "original_content_source", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "blocked_in_defender", "INTEGER DEFAULT 0")
        add_column_if_missing(cursor, "phishing_reports", "blocked_at", "TEXT")
        add_column_if_missing(cursor, "phishing_reports", "block_notes", "TEXT")

        # -------------------------------------------------------------------
        # Lightweight migrations for child/history tables
        # -------------------------------------------------------------------
        add_column_if_missing(cursor, "phishing_report_urls", "source", "TEXT DEFAULT 'wrapper'")
        add_column_if_missing(cursor, "phishing_report_attachments", "source", "TEXT DEFAULT 'report_wrapper'")
        add_column_if_missing(cursor, "phishing_report_verdicts", "review_status", "TEXT")
        add_column_if_missing(cursor, "phishing_report_verdicts", "source", "TEXT DEFAULT 'manual'")

        # -------------------------------------------------------------------
        # Indexes for common searches and reporting
        # -------------------------------------------------------------------
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_manual_verdict
            ON phishing_reports(manual_verdict)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_review_status
            ON phishing_reports(review_status)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_category_verdict
            ON phishing_reports(category_verdict)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_category_review_status
            ON phishing_reports(category_review_status)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_sender_domain
            ON phishing_reports(original_sender_domain)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_network_message_id
            ON phishing_reports(network_message_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_original_sender_ip
            ON phishing_reports(original_sender_ip)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_reports_blocked_in_defender
            ON phishing_reports(blocked_in_defender)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_report_urls_domain
            ON phishing_report_urls(domain)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_report_urls_source
            ON phishing_report_urls(source)
        """)

        # -------------------------------------------------------------------
        # Unique indexes for child rows
        # -------------------------------------------------------------------
        # Prevent duplicate URLs/attachments for the same report/source.
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_phishing_report_urls_unique
            ON phishing_report_urls(phishing_report_id, url, source)
        """)

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_phishing_report_attachments_unique
            ON phishing_report_attachments(
                phishing_report_id,
                filename,
                size_bytes,
                source
            )
        """)

        connection.commit()


def insert_phishing_report(report):
    """
    Insert or update a phishing report in SQLite.

    Supports repeated collection of the same report message. This matters
    because Outlook categories may change after the first collection.

    Returns:
        phishing_reports.id
    """
    initialize_database()

    # Child records. These may include wrapper-level and original-email-level
    # indicators. Each item can include a source field.
    urls = report.get("urls", []) or []
    attachments = report.get("attachments", []) or []

    collected_at = get_utc_now()
    last_seen_at = collected_at

    # Store Outlook categories as JSON text if they arrive as a list.
    outlook_categories_raw = report.get("outlook_categories_raw")

    if isinstance(outlook_categories_raw, (list, tuple, set, dict)):
        outlook_categories_raw = serialize_json(outlook_categories_raw)

    report_message_id = report.get("report_message_id")

    if not report_message_id:
        raise ValueError("report_message_id is required for phishing report storage")

    with get_connection() as connection:
        cursor = connection.cursor()

        # -------------------------------------------------------------------
        # Upsert main report row
        # -------------------------------------------------------------------
        # New report_message_id:
        #   INSERT a row.
        #
        # Existing report_message_id:
        #   UPDATE the row with current categories, parser output, and
        #   attachment-derived original email fields.
        cursor.execute(
            """
            INSERT INTO phishing_reports (
                report_message_id,
                report_subject,
                report_received_time,
                collected_at,
                last_seen_at,

                microsoft_or_report_label,
                network_message_id,
                internet_message_id,

                reporting_user,
                outlook_categories_raw,

                category_verdict,
                category_review_status,
                category_reviewed_by,
                priority,

                original_sender,
                original_sender_domain,
                reply_to,
                original_recipient,
                original_subject,
                subject,
                received_time,
                original_sender_ip,

                spf_result,
                dkim_result,
                dmarc_result,
                auth_results,
                scl,

                has_attachments,
                attachment_count,
                url_count,
                body_text_sample,

                original_body_preview,
                original_body_text_sample,
                original_url_count,
                original_attachment_count,
                original_content_source,

                microsoft_verdict,
                manual_verdict,
                review_status,
                reviewed_by,
                reviewed_at,
                notes,

                blocked_in_defender,
                blocked_at,
                block_notes
            )
            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?
            )
            ON CONFLICT(report_message_id) DO UPDATE SET
                report_subject = excluded.report_subject,
                report_received_time = excluded.report_received_time,
                last_seen_at = excluded.last_seen_at,

                microsoft_or_report_label = excluded.microsoft_or_report_label,
                network_message_id = excluded.network_message_id,
                internet_message_id = excluded.internet_message_id,

                reporting_user = excluded.reporting_user,
                outlook_categories_raw = excluded.outlook_categories_raw,

                category_verdict = excluded.category_verdict,
                category_review_status = excluded.category_review_status,
                category_reviewed_by = excluded.category_reviewed_by,
                priority = excluded.priority,

                original_sender = excluded.original_sender,
                original_sender_domain = excluded.original_sender_domain,
                reply_to = excluded.reply_to,
                original_recipient = excluded.original_recipient,
                original_subject = excluded.original_subject,
                subject = excluded.subject,
                received_time = excluded.received_time,
                original_sender_ip = excluded.original_sender_ip,

                spf_result = excluded.spf_result,
                dkim_result = excluded.dkim_result,
                dmarc_result = excluded.dmarc_result,
                auth_results = excluded.auth_results,
                scl = excluded.scl,

                has_attachments = excluded.has_attachments,
                attachment_count = excluded.attachment_count,
                url_count = excluded.url_count,
                body_text_sample = excluded.body_text_sample,

                original_body_preview = excluded.original_body_preview,
                original_body_text_sample = excluded.original_body_text_sample,
                original_url_count = excluded.original_url_count,
                original_attachment_count = excluded.original_attachment_count,
                original_content_source = excluded.original_content_source,

                microsoft_verdict = excluded.microsoft_verdict,

                manual_verdict = excluded.manual_verdict,
                review_status = excluded.review_status,
                reviewed_by = excluded.reviewed_by,
                reviewed_at = excluded.reviewed_at,
                notes = excluded.notes,

                blocked_in_defender = excluded.blocked_in_defender,
                blocked_at = excluded.blocked_at,
                block_notes = excluded.block_notes
            """,
            (
                report_message_id,
                report.get("report_subject"),
                report.get("report_received_time"),
                collected_at,
                last_seen_at,

                report.get("microsoft_or_report_label"),
                report.get("network_message_id"),
                report.get("internet_message_id"),

                report.get("reporting_user"),
                outlook_categories_raw,

                report.get("category_verdict"),
                report.get("category_review_status"),
                report.get("category_reviewed_by"),
                report.get("priority", "normal"),

                report.get("original_sender"),
                report.get("original_sender_domain"),
                report.get("reply_to"),
                report.get("original_recipient"),
                report.get("original_subject"),
                report.get("subject") or report.get("original_subject"),
                report.get("received_time"),
                report.get("original_sender_ip"),

                report.get("spf_result"),
                report.get("dkim_result"),
                report.get("dmarc_result"),
                report.get("auth_results"),
                report.get("scl"),

                int(bool(report.get("has_attachments"))),
                int(report.get("attachment_count", 0) or 0),
                int(report.get("url_count", 0) or 0),
                report.get("body_text_sample"),

                report.get("original_body_preview"),
                report.get("original_body_text_sample"),
                int(report.get("original_url_count", 0) or 0),
                int(report.get("original_attachment_count", 0) or 0),
                report.get("original_content_source"),

                report.get("microsoft_verdict"),
                report.get("manual_verdict", "unknown"),
                report.get("review_status", "new"),
                report.get("reviewed_by"),
                report.get("reviewed_at"),
                report.get("notes"),

                int(bool(report.get("blocked_in_defender"))),
                report.get("blocked_at"),
                report.get("block_notes"),
            ),
        )

        # -------------------------------------------------------------------
        # Retrieve the numeric parent ID
        # -------------------------------------------------------------------
        # Child rows use phishing_reports.id as their foreign key.
        cursor.execute(
            """
            SELECT id
            FROM phishing_reports
            WHERE report_message_id = ?
            """,
            (report_message_id,),
        )

        row = cursor.fetchone()

        if not row:
            connection.commit()
            return None

        phishing_report_id = row["id"]

        # -------------------------------------------------------------------
        # Rebuild child rows
        # -------------------------------------------------------------------
        # Rebuilding avoids stale/duplicate URL and attachment rows when the
        # parser improves or when the same report is collected more than once.
        cursor.execute(
            """
            DELETE FROM phishing_report_urls
            WHERE phishing_report_id = ?
            """,
            (phishing_report_id,),
        )

        cursor.execute(
            """
            DELETE FROM phishing_report_attachments
            WHERE phishing_report_id = ?
            """,
            (phishing_report_id,),
        )

        for url_entry in urls:
            cursor.execute(
                """
                INSERT OR IGNORE INTO phishing_report_urls (
                    phishing_report_id,
                    url,
                    domain,
                    source,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    phishing_report_id,
                    url_entry.get("url"),
                    url_entry.get("domain"),
                    url_entry.get("source", "wrapper"),
                    collected_at,
                ),
            )

        for attachment in attachments:
            cursor.execute(
                """
                INSERT OR IGNORE INTO phishing_report_attachments (
                    phishing_report_id,
                    filename,
                    extension,
                    content_type,
                    size_bytes,
                    source,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    phishing_report_id,
                    attachment.get("filename"),
                    attachment.get("extension"),
                    attachment.get("content_type"),
                    attachment.get("size_bytes"),
                    attachment.get("source", "report_wrapper"),
                    collected_at,
                ),
            )

        connection.commit()

        return phishing_report_id


def update_phishing_report_verdict(
    phishing_report_id,
    verdict,
    reviewed_by=None,
    notes=None,
    review_status="reviewed",
    source="manual",
):
    """
    Update the final/manual verdict for a phishing report.

    Suggested verdict values:
    - malicious
    - spam_or_marketing
    - benign
    - simulation
    - unknown
    - needs_escalation
    """
    reviewed_at = get_utc_now()

    with get_connection() as connection:
        cursor = connection.cursor()

        # Update current report state.
        cursor.execute(
            """
            UPDATE phishing_reports
            SET manual_verdict = ?,
                review_status = ?,
                reviewed_by = ?,
                reviewed_at = ?,
                notes = ?
            WHERE id = ?
            """,
            (
                verdict,
                review_status,
                reviewed_by,
                reviewed_at,
                notes,
                phishing_report_id,
            ),
        )

        # Append review history.
        cursor.execute(
            """
            INSERT INTO phishing_report_verdicts (
                phishing_report_id,
                verdict,
                review_status,
                reviewed_by,
                notes,
                source,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                phishing_report_id,
                verdict,
                review_status,
                reviewed_by,
                notes,
                source,
                reviewed_at,
            ),
        )

        connection.commit()


def mark_report_blocked_in_defender(
    phishing_report_id,
    blocked_by=None,
    notes=None,
):
    """
    Mark a phishing report as remediated in Microsoft Defender.

    This does not perform the Defender block. It only records that the action
    happened.
    """
    blocked_at = get_utc_now()

    block_notes = notes

    if blocked_by:
        if block_notes:
            block_notes = f"Blocked by {blocked_by}. {block_notes}"
        else:
            block_notes = f"Blocked by {blocked_by}."

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE phishing_reports
            SET blocked_in_defender = 1,
                blocked_at = ?,
                block_notes = ?
            WHERE id = ?
            """,
            (
                blocked_at,
                block_notes,
                phishing_report_id,
            ),
        )

        connection.commit()


def get_recent_phishing_reports(limit=25):
    """
    Return recent phishing reports.
    """
    initialize_database()

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

        return [dict(row) for row in cursor.fetchall()]


def get_unreviewed_phishing_reports(limit=25):
    """
    Return reports that still need review.
    """
    initialize_database()

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM phishing_reports
            WHERE COALESCE(review_status, 'new') = 'new'
               OR COALESCE(category_review_status, 'new') = 'new'
            ORDER BY collected_at DESC
            LIMIT ?
            """,
            (limit,),
        )

        return [dict(row) for row in cursor.fetchall()]


def get_phishing_reports_by_verdict(verdict, limit=100):
    """
    Return reports matching a manual verdict.
    """
    initialize_database()

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM phishing_reports
            WHERE manual_verdict = ?
            ORDER BY collected_at DESC
            LIMIT ?
            """,
            (verdict, limit),
        )

        return [dict(row) for row in cursor.fetchall()]


def get_training_labeled_phishing_reports(limit=1000):
    """
    Return reports safe to use as trusted ML labels.

    Trusted labels:
    - malicious
    - spam_or_marketing
    - benign
    """
    initialize_database()

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM phishing_reports
            WHERE manual_verdict IN (
                'malicious',
                'spam_or_marketing',
                'benign'
            )
            ORDER BY collected_at DESC
            LIMIT ?
            """,
            (limit,),
        )

        return [dict(row) for row in cursor.fetchall()]


def get_phishing_report_counts_by_verdict():
    """
    Return counts grouped by manual verdict.
    """
    initialize_database()

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT manual_verdict, COUNT(*) AS count
            FROM phishing_reports
            GROUP BY manual_verdict
            ORDER BY count DESC
            """
        )

        return [dict(row) for row in cursor.fetchall()]


def search_phishing_reports_by_domain(domain, limit=100):
    """
    Search reports by original sender domain or URL domain.
    """
    initialize_database()

    with get_connection() as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT DISTINCT phishing_reports.*
            FROM phishing_reports
            LEFT JOIN phishing_report_urls
                ON phishing_reports.id = phishing_report_urls.phishing_report_id
            WHERE phishing_reports.original_sender_domain = ?
               OR phishing_report_urls.domain = ?
            ORDER BY phishing_reports.collected_at DESC
            LIMIT ?
            """,
            (domain, domain, limit),
        )

        return [dict(row) for row in cursor.fetchall()]