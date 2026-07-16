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
- Rolling mailbox activity cache
- Rolling new-location activity cache
- Recent alert suppression
- Docker Compose scheduling
- Docker-ready architecture

---

# Detection Examples

The platform currently detects:

- Failed sign-ins followed by success
- New/unusual sign-in locations
- New-location sign-in bursts
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
├── docker/
│   └── run_monitor_loop.sh
├── logs/
├── src/
│   ├── clients/
│   ├── core/
│   ├── detectors/
│   ├── notifiers/
│   ├── tests/
│   ├── utils/
│   └── main.py
├── state/
├── systemd/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .dockerignore
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

If deploying to another company or tenant, these values typically need to change.

The `.env` file is intentionally not baked into the Docker image. Docker Compose loads it at runtime using:

```yaml
env_file:
  - .env
```

---

# Manual Execution

Run one monitoring cycle manually without Docker:

```bash
source .venv/bin/activate
PYTHONPATH=src python3 src/main.py
```

Use this mainly for development or troubleshooting. Normal scheduled execution now runs through Docker Compose.

---

# Tests

Send a manual Teams test alert:

```bash
PYTHONPATH=src python3 src/tests/send_test_alert.py
```

Run mailbox correlation tests:

```bash
PYTHONPATH=src python3 src/tests/test_mailbox_correlation.py
```

Run failed sign-in cache tests:

```bash
PYTHONPATH=src python3 src/tests/test_failed_signin_cache.py
```

Run new-location burst tests:

```bash
PYTHONPATH=src python3 src/tests/test_new_location_burst.py
```

Note: be careful with any test that writes to real files in `state/`. Test files should avoid polluting live production cache files.

---

# Compile / Syntax Check

Use `py_compile` to confirm Python files are valid and importable:

```bash
source .venv/bin/activate

python3 -m py_compile \
  src/main.py \
  src/detectors/signin_detector.py \
  src/detectors/correlation_detector.py \
  src/utils/time_utils.py
```

Compiling does not prove the detection logic is correct. It confirms the code has valid Python syntax and catches import-time errors.

---

# Docker Scheduling Model

Docker Compose is now the scheduler for this project.

The container starts, runs the monitor, sleeps for 15 minutes, and repeats.

```text
container starts
→ monitor runs
→ sleeps 15 minutes
→ monitor runs again
→ repeats
```

The interval is controlled in `docker-compose.yml`:

```yaml
environment:
  RUN_INTERVAL_SECONDS: "900"
```

`900` seconds equals 15 minutes.

---

# Running the Monitor with Docker Compose

The monitor can be run with Docker Compose in either foreground mode or detached mode.

---

## Option 1: Foreground Mode

Use foreground mode when you want one Linux terminal to run the monitor and show live output.

```bash
cd ~/scripts/entra_monitoring_project
docker compose up entra-monitor
```

This will:

- Start the container
- Run the monitor loop
- Show live output directly in the terminal
- Continue running every 15 minutes

To stop the monitor in foreground mode:

```text
Ctrl + C
```

Important: if you close the Linux terminal while running in foreground mode, the container will stop.

---

## Option 2: Detached Mode

Use detached mode when you want the monitor to keep running in the background.

```bash
cd ~/scripts/entra_monitoring_project
docker compose up -d
```

View live logs from the detached container:

```bash
docker compose logs -f entra-monitor
```

Stop following the logs:

```text
Ctrl + C
```

This only exits the log view. It does not stop the container.

To stop the container completely:

```bash
docker compose down
```

---

# Useful Docker Commands

## Start the Monitor

Start in foreground mode:

```bash
cd ~/scripts/entra_monitoring_project
docker compose up entra-monitor
```

Start in detached mode:

```bash
cd ~/scripts/entra_monitoring_project
docker compose up -d
```

---

## Stop the Monitor

Stop and remove the running container:

```bash
docker compose down
```

Stop the container without removing it:

```bash
docker compose stop entra-monitor
```

---

## Restart the Monitor

```bash
docker compose restart entra-monitor
```

---

## Rebuild the Monitor

Rebuild the Docker image after code or dependency changes:

```bash
docker compose build
```

Rebuild and start in detached mode:

```bash
docker compose up -d --build
```

---

# Docker Health Check Commands

Check whether the container is running:

```bash
docker compose ps
```

Check only the container status:

```bash
docker inspect -f '{{.State.Status}}' entra-monitor
```

Check Docker health status:

```bash
docker inspect -f '{{.State.Health.Status}}' entra-monitor
```

Check when the container started:

```bash
docker inspect -f '{{.State.StartedAt}}' entra-monitor
```

Check whether the monitor process is running inside the container:

```bash
docker compose exec entra-monitor ps aux
```

---

# Check When the Monitor Ran Recently

View recent monitor output:

```bash
docker compose logs entra-monitor
```

Follow live monitor output:

```bash
docker compose logs -f entra-monitor
```

Show only recent logs:

```bash
docker compose logs --tail=100 entra-monitor
```

Check monitor runs from the logs:

```bash
docker compose logs entra-monitor | grep "Starting monitor run"
```

Check successful monitor runs:

```bash
docker compose logs entra-monitor | grep "Monitor run completed successfully"
```

Check failed monitor runs:

```bash
docker compose logs entra-monitor | grep "Monitor run failed"
```

Check alert counts from recent runs:

```bash
docker compose logs entra-monitor | grep "Alert count"
```

Check suppression activity:

```bash
docker compose logs entra-monitor | grep "Suppressed repeat alert count"
```

Check run summaries:

```bash
docker compose logs entra-monitor | grep "Run summary"
```

Check for Python errors:

```bash
docker compose logs entra-monitor | grep -i "traceback\|error\|exception\|failed"
```

---

# Quick Health Check Commands

Run these commands when you want to quickly confirm the monitor is healthy:

```bash
cd ~/scripts/entra_monitoring_project

docker compose ps

docker inspect -f '{{.State.Status}}' entra-monitor

docker compose logs --tail=50 entra-monitor

docker compose logs entra-monitor | grep "Starting monitor run" | tail

docker compose logs entra-monitor | grep -i "traceback\|error\|exception\|failed" | tail
```

Expected healthy signs:

```text
Container status is running
Logs show monitor runs every 15 minutes
Recent runs say "Monitor run completed successfully"
No recent Traceback errors
State files continue updating
```

---

# Logs

View Docker logs:

```bash
docker compose logs entra-monitor
```

Follow Docker logs live:

```bash
docker compose logs -f entra-monitor
```

View only the last 100 log lines:

```bash
docker compose logs --tail=100 entra-monitor
```

Application logs are also stored on the host in:

```text
logs/
```

View the application log directly:

```bash
cat logs/entra_monitor.log
```

Follow the application log directly:

```bash
tail -f logs/entra_monitor.log
```

---

# State and Persistence

Runtime state is stored on the host in:

```text
state/
```

The Docker container mounts this folder into the container:

```text
./state:/app/state
```

Runtime logs are stored on the host in:

```text
logs/
```

The Docker container mounts this folder into the container:

```text
./logs:/app/logs
```

This allows processed event IDs, baselines, caches, alert history, suppression memory, and logs to survive container rebuilds.

Important state files may include:

```text
state/state.json
state/location_baseline.json
state/security_alert_history.json
state/recent_alert_suppression.json
state/recent_suspicious_signins.json
state/new_location_activity_cache.json
state/mailbox_activity_cache.json
state/failed_signin_cache.json
```

---

# Clear Rolling Caches

Use this when you want to clear short-term rolling correlation caches without resetting the full monitor state.

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

Verify:

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

Restart the Docker monitor after clearing caches:

```bash
docker compose restart entra-monitor
```

---

# Docker Deployment Model

This project supports Docker deployment for portability between environments and organizations.

Docker packages:

- Python version
- Python dependencies
- monitoring application
- runtime behavior

Docker does not bake in:

- `.env`
- `state/`
- `logs/`

Those are provided at runtime through Docker Compose and bind mounts.

The intended Docker deployment model is:

```text
container starts
→ monitor runs
→ sleeps 15 minutes
→ monitor runs again
```

This removes the need for systemd scheduling inside the container.

---

# WSL / Docker Desktop Note

Running through Docker removes the need for the old systemd timer, but the workstation still needs to stay awake.

When running this from WSL and Docker Desktop, the monitor requires:

```text
Windows is powered on
Docker Desktop is running
WSL/Docker backend remains active
The PC does not sleep or shut down
```

For true 24/7 production use, this should eventually run on an always-on Linux host, VM, VPS, or Azure container platform.

---

# Notes

- Alerts are only generated for new events
- State tracking prevents duplicate processing
- Recent alert suppression reduces repeated Teams noise
- Microsoft Graph and Microsoft 365 audit logs may appear with delays
- Teams alert time is not always the same as event time
- Alert details include Mountain Time for easier incident review
- Requires Microsoft Graph API permissions
- Requires Microsoft 365 Management Activity API permissions
- Requires Microsoft Teams incoming webhook or workflow
- Works well in Linux, WSL, or Docker environments

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
- Rolling mailbox activity cache
- Rolling new-location activity cache
- Recent alert suppression
- Docker Compose scheduling
- Docker deployment files

---

# Future Enhancements

Future enhancements may include:

- Dashboard/reporting
- Additional behavioral detections
- Threat scoring
- Improved baselining
- SQLite or PostgreSQL event storage
- Prometheus/Grafana metrics
- Optional Splunk output
- SIEM integration
- Additional collectors
  - Sophos
  - UniFi
  - Windows Event Forwarding
  - Synology logs
  - Freshservice
  - AWS CloudTrail / CloudWatch lab
- Cloud deployment with Terraform