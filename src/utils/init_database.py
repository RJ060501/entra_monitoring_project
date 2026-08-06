"""
Initialize the SQLite database for the Entra Monitoring Project.

This script creates or updates the SQLite schema used by the phishing-report
storage layer.

Run from the project root with:

    PYTHONPATH=src python3 src/utils/init_database.py
"""

from storage.sqlite_store import initialize_database, DATABASE_PATH


def main():
    """
    Initialize the SQLite database and print the database path.

    initialize_database() is safe to run multiple times because it uses
    CREATE TABLE IF NOT EXISTS and lightweight migrations.
    """
    initialize_database()

    print(f"SQLite database initialized successfully: {DATABASE_PATH}")


if __name__ == "__main__":
    main()