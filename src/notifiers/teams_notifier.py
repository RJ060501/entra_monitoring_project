"""
Teams Notifier

This module sends alerts to Microsoft Teams using a workflow/webhook URL.

Current design:
- Sends one Adaptive Card per alert
- Uses Python standard library only
- Prints debug output so it is easy to troubleshoot

Why this version:
- A plain {"text": "..."} payload was not reliable for your workflow
- Your manual Adaptive Card POST worked
- So this notifier now matches that working pattern
"""

import json
import urllib.request
import urllib.error


def build_payload(alert):
    """
    Build the Adaptive Card payload for a single alert.

    Expected alert fields:
    - severity
    - type
    - user
    - detail
    - location
    - source
    """
    severity = alert.get("severity", "info").upper()
    alert_type = alert.get("type", "Unknown Alert")
    user = alert.get("user", "Unknown User")
    detail = alert.get("detail", "No detail provided")
    location = alert.get("location", "Unknown")
    source = alert.get("source", "Unknown Source")

    message = (
        f"Type: {alert_type}\n"
        f"User: {user}\n"
        f"Location: {location}\n"
        f"Source: {source}\n"
        f"Detail: {detail}"
    )

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
                            "size": "Large",
                            "weight": "Bolder",
                            "text": f"{severity} ALERT"
                        },
                        {
                            "type": "TextBlock",
                            "text": message,
                            "wrap": True
                        }
                    ]
                }
            }
        ]
    }

    return payload


def post_to_teams(webhook_url, payload, timeout=10):
    """
    Send the payload to Teams.

    Returns:
        True if the request succeeded, otherwise False.
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
    Send a list of alerts to Teams, one message per alert.
    """
    webhook_url = settings.get("teams_webhook_url", "").strip()

    if not webhook_url:
        print("Teams notifier skipped: no TEAMS_WEBHOOK_URL configured.")
        return

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