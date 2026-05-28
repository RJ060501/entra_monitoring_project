def deduplicate_alerts(alerts):
    """
    Remove duplicate or near-duplicate alerts within the same run.

    We intentionally avoid using the full detail field because small changes
    like time difference can cause duplicate Teams alerts.
    """
    seen = set()
    unique = []

    for alert in alerts:
        key = (
            alert.get("type"),
            alert.get("user"),
            alert.get("severity"),
            alert.get("source"),
        )

        if key not in seen:
            seen.add(key)
            unique.append(alert)

    return unique