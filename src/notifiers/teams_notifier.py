"""
Teams Notifier

This module sends alerts to Microsoft Teams using a webhook URL.

Current design:
- Sends one Adaptive Card per alert
- Uses only Python standard library modules
- Prints debug output for troubleshooting

Why this version:
- A plain {"text": "..."} payload was not reliable for your workflow
- Your manual Adaptive Card POST worked
- So this notifier now matches that working pattern
"""

"""
Microsoft Teams notifier.

Sends detection alerts to Microsoft Teams using an incoming workflow/webhook.

This version uses Adaptive Cards so alerts are easier to read than plain text.
"""

import json
import urllib.request
import urllib.error


SEVERITY_STYLE = {
    "critical": {
        "title": "CRITICAL SECURITY ALERT",
        "emoji": "🚨",
        "color": "Attention",
    },
    "high": {
        "title": "HIGH SECURITY ALERT",
        "emoji": "⚠️",
        "color": "Attention",
    },
    "medium": {
        "title": "MEDIUM SECURITY ALERT",
        "emoji": "🔎",
        "color": "Warning",
    },
    "low": {
        "title": "LOW SECURITY ALERT",
        "emoji": "ℹ️",
        "color": "Default",
    },
    "info": {
        "title": "SECURITY NOTICE",
        "emoji": "ℹ️",
        "color": "Default",
    },
}


def get_severity_style(severity):
    """
    Return display settings for an alert severity.
    """
    normalized = str(severity or "info").lower()
    return SEVERITY_STYLE.get(normalized, SEVERITY_STYLE["info"])


def build_payload(alert):
    """
    Build a Microsoft Teams Adaptive Card payload for one alert.
    """
    severity = str(alert.get("severity", "info")).lower()
    style = get_severity_style(severity)

    alert_type = alert.get("type", "Unknown Alert")
    user = alert.get("user", "Unknown User")
    location = alert.get("location", "Unknown")
    source = alert.get("source", "Unknown Source")
    detail = alert.get("detail", "No detail provided")

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"{style['emoji']} {style['title']}",
                            "size": "Large",
                            "weight": "Bolder",
                            "color": style["color"],
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": alert_type,
                            "size": "Medium",
                            "weight": "Bolder",
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {
                                    "title": "Severity",
                                    "value": severity.upper(),
                                },
                                {
                                    "title": "User",
                                    "value": user,
                                },
                                {
                                    "title": "Location",
                                    "value": location,
                                },
                                {
                                    "title": "Source",
                                    "value": source,
                                },
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": "Details",
                            "weight": "Bolder",
                            "spacing": "Medium",
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": detail,
                            "wrap": True,
                        },
                    ],
                },
            }
        ],
    }

    return payload


def post_to_teams(webhook_url, payload, timeout=10):
    """
    Send one Adaptive Card payload to Teams.
    """
    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status_code = response.getcode()
            response_body = response.read().decode("utf-8", errors="ignore")

            print(f"Teams response status: {status_code}")

            if response_body:
                print(f"Teams response body: {response_body}")

            return 200 <= status_code < 300

    except urllib.error.HTTPError as exc:
        error_body = ""

        try:
            error_body = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            pass

        print(f"Teams delivery failed with HTTP error: {exc.code} {exc.reason}")

        if error_body:
            print(f"Teams error body: {error_body}")

        return False

    except urllib.error.URLError as exc:
        print(f"Teams delivery failed with network error: {exc.reason}")
        return False

    except Exception as exc:
        print(f"Teams delivery failed with unexpected error: {exc}")
        return False


def send_alert(alert, settings):
    """
    Send one alert to Teams.
    """
    webhook_url = settings.get("teams_webhook_url", "").strip()

    if not webhook_url:
        print("Teams notifier skipped: no TEAMS_WEBHOOK_URL configured.")
        return False

    payload = build_payload(alert)

    print("Sending Teams alert...")
    print(f"Alert type: {alert.get('type', 'Unknown Alert')}")
    print(f"Alert user: {alert.get('user', 'Unknown User')}")

    success = post_to_teams(webhook_url, payload)

    if success:
        print(f"Teams alert sent for {alert.get('type', 'Unknown Alert')}.")
    else:
        print(f"Teams alert failed for {alert.get('type', 'Unknown Alert')}.")

    return success


def send_alerts(alerts, settings):
    """
    Send a list of alerts to Teams.
    """
    if not alerts:
        print("Teams notifier: no alerts to send.")
        return

    print(f"Teams notifier: sending {len(alerts)} alert(s).")

    success_count = 0
    failure_count = 0

    for alert in alerts:
        if send_alert(alert, settings):
            success_count += 1
        else:
            failure_count += 1

    print(
        f"Teams notifier complete. "
        f"Success: {success_count}, Failure: {failure_count}"
    )