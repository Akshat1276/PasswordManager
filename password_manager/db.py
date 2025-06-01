import os
import sqlite3

DB_FILE = os.environ.get("DB_FILE", "vault.db")

def get_connection():
    """Return a connection to the SQLite database."""
    return sqlite3.connect(DB_FILE)

def init_db():
    """Create the credentials table if it does not exist."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                iv BLOB NOT NULL
            )
        """)
        conn.commit()

def setUp(self):
    with get_connection() as conn:
        conn.execute("DELETE FROM credentials")
        conn.commit()