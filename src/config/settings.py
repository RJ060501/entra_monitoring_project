"""
Configuration Settings

This module is the single place where configuration is loaded and exposed.

Current responsibilities:
- Define suppressed users
- Load environment variables from the shell
- Optionally read a local .env file

Why include a simple .env loader here:
- Keeps the project easy to run
- Avoids external dependencies
- Lets you configure Teams without editing Python files
"""

import os
from pathlib import Path

SUPPRESSED_USERS = [
    "bdavis@resolutgroup.com",
]


def load_dotenv():
    """Load local .env values into the process environment.

    This loader is intentionally simple and dependency-free. It reads a
    top-level .env file if present and sets any variables that are not already
    defined in the current shell environment.
    """
    project_root = Path(__file__).resolve().parents[2]
    env_file = project_root / ".env"

    if not env_file.exists():
        print(f"No .env file found at: {env_file}")
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        # Skip blank lines, comments, and malformed entries.
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Only set values that are not already defined in os.environ.
        if key and key not in os.environ:
            os.environ[key] = value


def load_settings():
    """Load application settings from environment variables.

    This function first attempts to load a local .env file, then reads the
    required configuration values from the environment. It returns a dict of
    normalized settings used throughout the app.
    """
    load_dotenv()

    return {
        # Teams webhook used by the notifier.
        "teams_webhook_url": os.getenv("TEAMS_WEBHOOK_URL", "").strip(),

        # Entra/Microsoft Graph app-only authentication values.
        "tenant_id": os.getenv("TENANT_ID", "").strip(),
        "client_id": os.getenv("CLIENT_ID", "").strip(),
        "client_secret": os.getenv("CLIENT_SECRET", "").strip(),
        
        # Microsoft 365 Management Activity API credentials.
        # If M365-specific values are not provided, fall back to the Graph values.
        "m365_tenant_id": os.getenv(
            "M365_TENANT_ID",
            os.getenv("TENANT_ID", "")
        ).strip(),

        "m365_client_id": os.getenv(
            "M365_CLIENT_ID",
            os.getenv("CLIENT_ID", "")
        ).strip(),

        "m365_client_secret": os.getenv(
            "M365_CLIENT_SECRET",
            os.getenv("CLIENT_SECRET", "")
        ).strip(),
    }
