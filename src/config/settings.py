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


def load_dotenv(dotenv_path=".env"):
    """Read a simple .env file and add values to os.environ."""
    env_file = Path(dotenv_path)

    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key and key not in os.environ:
            os.environ[key] = value


def load_settings():
    """Load runtime settings for the monitor."""
    load_dotenv()

    return {
        "teams_webhook_url": os.getenv("TEAMS_WEBHOOK_URL", ""),
    }
