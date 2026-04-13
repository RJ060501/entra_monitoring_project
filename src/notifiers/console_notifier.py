"""
Console Notifier

Outputs alerts to the terminal.

Future:
- Replace or extend with Teams / Outlook / ticketing
"""

def send_alerts(alerts):
    """Print alerts to console"""
    if not alerts:
        print("No alerts detected.")
        return

    print("\n=== ALERTS ===")
    for alert in alerts:
        print(f"[{alert['type']}] {alert['user']} - {alert['detail']}")
