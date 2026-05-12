"""
Logger setup for the Entra monitoring project.

Writes logs to:
    logs/entra_monitor.log
"""

import logging
from pathlib import Path


# Determine the repository root and the logging output location.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "entra_monitor.log"


def setup_logger():
    """Configure and return the shared project logger.

    This function ensures the logs directory exists, creates a single logger
    instance, and attaches both file and console handlers. If the logger has
    already been configured, the existing logger is returned unchanged.
    """
    # Create logs directory if it does not already exist.
    LOG_DIR.mkdir(exist_ok=True)

    logger = logging.getLogger("entra_monitor")
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers when setup_logger is called more than once.
    if logger.handlers:
        return logger

    # Use a consistent log message format for file and console output.
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    # Persist logs to a file for later review and historical debugging.
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)

    # Also write logs to the console so live runs show status immediately.
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger