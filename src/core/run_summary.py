"""
Run Summary

Tracks high-level health information for each monitoring run.

Why this exists:
- A SIEM-style scheduled script should make it obvious whether a run completed.
- If API ingestion partially fails, we should know which data source failed.
- If alerts were generated, we should know how many and what severity.
- This gives us a lightweight operational health check before moving to V2.

This is not long-term reporting or a dashboard. It is simple run health logging.
"""

from datetime import datetime, timezone
from collections import Counter


def create_run_summary():
    """
    Create a new run summary object.
    """
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "status": "running",
        "errors": [],
        "counts": {
            "fetched_signins": 0,
            "fetched_audits": 0,
            "fetched_email_events": 0,
            "new_signins": 0,
            "new_audits": 0,
            "new_email_events": 0,
            "alerts": 0,
        },
        "alert_severities": {},
    }


def set_count(summary, key, value):
    """
    Set one count value on the run summary.
    """
    summary["counts"][key] = int(value or 0)
    return summary


def add_error(summary, source, error):
    """
    Add an error to the run summary.
    """
    summary["errors"].append({
        "source": source,
        "error": str(error),
    })

    summary["status"] = "completed_with_errors"

    return summary


def set_alert_summary(summary, alerts):
    """
    Store alert count and alert severity breakdown.
    """
    alerts = alerts or []

    summary["counts"]["alerts"] = len(alerts)

    severity_counts = Counter(
        str(alert.get("severity", "unknown")).lower()
        for alert in alerts
    )

    summary["alert_severities"] = dict(severity_counts)

    return summary


def finish_run_summary(summary):
    """
    Mark the run summary complete.
    """
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()

    if summary["status"] == "running":
        summary["status"] = "completed"

    return summary


def log_run_summary(summary, logger):
    """
    Write the run summary to the logger.
    """
    logger.info("Run summary status: %s", summary.get("status"))
    logger.info("Run summary counts: %s", summary.get("counts"))
    logger.info("Run summary alert severities: %s", summary.get("alert_severities"))

    errors = summary.get("errors", [])

    if errors:
        logger.warning("Run summary errors: %s", errors)