"""
Initialize the SQLite database.

Run from project root:

PYTHONPATH=src python3 src/utils/init_database.py
"""

from storage.sqlite_store import initialize_database, DATABASE_PATH


def main():
    initialize_database()
    print(f"SQLite database initialized: {DATABASE_PATH}")


if __name__ == "__main__":
    main()