# Entra Monitoring Project

Automated Microsoft Entra monitoring system that ingests sign-in and audit logs via Microsoft Graph, detects suspicious activity, and sends alerts to Microsoft Teams.

---

## Overview

This project provides:

- Real-time monitoring of Entra sign-in activity
- Detection of suspicious login patterns (e.g., failed → success)
- Alerting to Microsoft Teams
- State tracking to prevent duplicate alerts
- Scheduled execution via systemd

---

## Project Structure


---

## Setup

Activate virtual environment:
source .venv/bin/activate

Run manually:

python3 src/main.py

---

## Useful Commands

### Service (Manual Run)

Start service:
sudo systemctl start entra-monitor.service

This stops the automatic 15-minute runs:
sudo systemctl stop entra-monitor.timer

To also prevent it from starting on reboot:
sudo systemctl disable entra-monitor.timer

If you manually started it or it’s mid-run:
sudo systemctl stop entra-monitor.service

Check status:
sudo systemctl status entra-monitor.service

---

### Logs

Application logs:
cat logs/entra_monitor.log


Systemd logs:
journalctl -u entra-monitor.service -n 50 --no-pager


---

### Timer (Scheduled Execution)

Enable and start timer:
sudo systemctl enable --now entra-monitor.timer


Check timer:
systemctl list-timers | grep entra-monitor


Stop timer:
sudo systemctl stop entra-monitor.timer


---

## Notes

- The application runs every 15 minutes via systemd timer
- Alerts are only sent for new events (state tracking enabled)
- Ensure `.env` is configured with required credentials
- Requires systemd (may need to be enabled in WSL)