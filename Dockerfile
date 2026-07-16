# Entra Monitoring System - Dockerfile
#
# V1 goal:
# Run the existing Python monitor inside a container without changing detection
# logic or project behavior.

FROM python:3.12-slim

# Prevent Python from writing .pyc files and force unbuffered logs so Docker
# shows output immediately.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the container working directory.
WORKDIR /app

# Install OS-level packages that are useful for HTTPS requests and diagnostics.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file first so Docker can cache pip installs.
COPY requirements.txt /app/requirements.txt

# Install Python dependencies.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Copy the application code.
COPY src /app/src
COPY docker /app/docker

# Make sure the runner script is executable.
RUN chmod +x /app/docker/run_monitor_loop.sh

# These directories should be mounted from the host through docker-compose.yml.
# Creating them here prevents errors if the mounts are missing during testing.
RUN mkdir -p /app/state /app/logs

# Default command.
CMD ["/app/docker/run_monitor_loop.sh"]
