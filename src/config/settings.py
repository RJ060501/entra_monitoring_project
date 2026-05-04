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
    project_root = Path(__file__).resolve().parents[2]
    env_file = project_root / ".env"

    if not env_file.exists():
        print(f"No .env file found at: {env_file}")
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key and key not in os.environ:
            os.environ[key] = value

def load_settings():
    load_dotenv()

    return {
        "teams_webhook_url": os.getenv("TEAMS_WEBHOOK_URL", "").strip(),
        "tenant_id": os.getenv("TENANT_ID", "").strip(),
        "client_id": os.getenv("CLIENT_ID", "").strip(),
        "client_secret": os.getenv("CLIENT_SECRET", "").strip(),
    }
