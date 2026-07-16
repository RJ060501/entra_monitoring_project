#!/usr/bin/env bash

# Docker runtime loop for the Entra monitoring project.
#
# This replaces the systemd timer when running inside Docker.
# It runs the monitor once, waits 15 minutes, then runs it again.
#
# The loop keeps running even if one monitor cycle fails, which is important
# because Microsoft Graph or M365 audit APIs may occasionally timeout.

set -u

RUN_INTERVAL_SECONDS="${RUN_INTERVAL_SECONDS:-900}"

echo "Starting Entra Monitor Docker loop..."
echo "Run interval: ${RUN_INTERVAL_SECONDS} seconds"

while true; do
    echo "------------------------------------------------------------"
    echo "Starting monitor run at $(TZ=America/Denver date +"%Y-%m-%d %I:%M:%S %p %Z") Mountain Time"
    echo "------------------------------------------------------------"

    PYTHONPATH=/app/src python3 /app/src/main.py

    EXIT_CODE=$?

    if [ "$EXIT_CODE" -ne 0 ]; then
        echo "Monitor run failed with exit code ${EXIT_CODE}"
        echo "The container will continue and try again after the sleep interval."
    else
        echo "Monitor run completed successfully."
    fi

    echo "Sleeping for ${RUN_INTERVAL_SECONDS} seconds..."
    sleep "${RUN_INTERVAL_SECONDS}"
done
