# Entra Monitoring Project

Automated Microsoft Entra and Microsoft 365 monitoring platform that ingests sign-in and audit logs via Microsoft Graph and the Microsoft 365 Management Activity API, detects suspicious activity patterns, and sends alerts to Microsoft Teams.

---

# Features

- Microsoft Entra sign-in monitoring
- Microsoft Entra audit log monitoring
- Microsoft 365 / Exchange audit log monitoring
- External mailbox forwarding detection
- Mailbox hide/delete rule detection
- Correlation between suspicious sign-ins and mailbox activity
- Microsoft Teams Adaptive Card alerting
- State tracking to prevent duplicate alerts
- Rolling suspicious sign-in cache
- Scheduled execution
- Docker-ready architecture

---

# Detection Examples

The platform currently detects:

- Failed sign-ins followed by success
- New/unusual sign-in locations
- External mailbox forwarding
- Mailbox rules that:
  - move mail to Deleted Items
  - archive messages
  - mark messages as read
  - move mail to junk/rss folders
- Rules targeting sensitive keywords:
  - docusign
  - mfa
  - password
  - payroll
  - invoice
  - wire
  - sharepoint
  - teams
- Correlation between suspicious sign-ins and mailbox rule activity

---

# Project Structure

```text
entra_monitoring_project/
├── config/
├── logs/
├── src/
│   ├── clients/
│   ├── core/
│   ├── detectors/
│   ├── notifiers/
│   ├── tests/
│   └── main.py
├── state/
├── systemd/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env
└── README.md
```

---

# Setup

## Create Virtual Environment

```bash
python3 -m venv .venv
```

## Activate Virtual Environment

```bash
source .venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Manual Execution

Run one monitoring cycle manually:

```bash
python3 src/main.py
```

---

# Tests

Send a manual Teams test alert:
```bash
PYTHONPATH=src python3 src/tests/send_test_alert.py
```

Temporary alert test
```bash
PYTHONPATH=src python3 src/tests/test_christopher_signin_detection.py
```

Test new location burst
```bash
PYTHONPATH=src python3 src/tests/test_new_location_burst.py
```

---

# Clear Rolling Caches

```bash
cat > state/recent_suspicious_signins.json <<'EOF'
[]
EOF

cat > state/new_location_activity_cache.json <<'EOF'
[]
EOF

cat > state/mailbox_activity_cache.json <<'EOF'
[]
EOF

cat > state/failed_signin_cache.json <<'EOF'
[]
EOF
```

# Verify:

```bash
for f in \
  state/recent_suspicious_signins.json \
  state/new_location_activity_cache.json \
  state/mailbox_activity_cache.json \
  state/failed_signin_cache.json
do
  echo "$f:"
  cat "$f"
  echo
done
```

---

# Useful Commands

## Service (Manual Run)

Start service manually:

```bash
sudo systemctl start entra-monitor.service
```

Stop scheduled timer:

```bash
sudo systemctl stop entra-monitor.timer
```

Prevent timer from starting on boot:

```bash
sudo systemctl disable entra-monitor.timer
```

Stop currently running service:

```bash
sudo systemctl stop entra-monitor.service
```

Check service status:

```bash
sudo systemctl status entra-monitor.service
```

---

# Check When The Monitor Ran In The Past Week

```bash
journalctl -u entra-monitor.service --since "7 days ago" --no-pager | grep "Starting Entra monitoring run"
journalctl -u entra-monitor.timer --since "7 days ago" --no-pager
```

---

# Quick Health Check Commands

```bash
systemctl is-enabled entra-monitor.timer
systemctl is-active entra-monitor.timer
systemctl list-timers --all | grep entra-monitor
journalctl -u entra-monitor.service --since "7 days ago" --no-pager | grep "Starting Entra monitoring run"
journalctl -u entra-monitor.timer --since "7 days ago" --no-pager
```

---


# Logs

Application logs:

```bash
cat logs/entra_monitor.log
```

Follow logs live:

```bash
tail -f logs/entra_monitor.log
```

Systemd logs:

```bash
journalctl -u entra-monitor.service -n 50 --no-pager
```

---

# Timer (Scheduled Execution)

Enable and start timer:

```bash
sudo systemctl enable --now entra-monitor.timer
```

Check timer:

```bash
systemctl list-timers | grep entra-monitor
```

Stop timer:

```bash
sudo systemctl stop entra-monitor.timer
```

---

# Environment Variables

The application uses environment variables stored in `.env`.

Important values include:

```env
TENANT_ID=
CLIENT_ID=
CLIENT_SECRET=
TEAMS_WEBHOOK_URL=
INTERNAL_DOMAINS=
```

If deploying to another company/tenant, typically only these values need to change.

---

# Docker Deployment

This project is designed to support Docker deployment for portability between environments and organizations.

Docker packages:
- Python version
- dependencies
- monitoring application
- runtime behavior

This allows the platform to be deployed consistently across systems without rebuilding the environment manually.

The intended Docker deployment model is:

```text
container starts
→ monitor runs
→ sleeps 15 minutes
→ monitor runs again
```

This removes the need for systemd scheduling inside the container.

Future Docker deployment will include:

```text
Dockerfile
docker-compose.yml
.dockerignore
persistent volume mounts for:
- logs/
- state/
```

---

# Notes

- Alerts are only generated for new events
- State tracking prevents duplicate alerts
- Microsoft audit logs may appear with slight delays
- Requires Microsoft Graph API permissions
- Requires Microsoft 365 Management Activity API permissions
- Requires Microsoft Teams incoming webhook/workflow
- Works well in Linux or WSL environments
- Docker deployment is planned for cross-environment portability

---

# Current Status

Current implementation includes:

- Entra sign-in ingestion
- Entra audit ingestion
- Microsoft 365 audit ingestion
- Detection engine
- Correlation engine
- Teams alerting
- Persistent state tracking
- Rolling suspicious sign-in cache
- systemd scheduling

Future enhancements may include:

- dashboard/reporting
- additional behavioral detections
- threat scoring
- improved baselining
- SIEM integration
- Docker deployment