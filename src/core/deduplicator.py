"""
Alert Deduplication

Prevents duplicate alerts from being sent repeatedly.

Current logic:
- Removes identical alerts within the same run

Future:
- Add time-based suppression (e.g., 15 minutes)
"""

def deduplicate_alerts(alerts):
    """Remove duplicate alerts"""
    seen = set()
    unique = []

    for alert in alerts:
        key = (alert["type"], alert["user"], alert["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(alert)

    return unique
