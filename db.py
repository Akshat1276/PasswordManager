import sqlite3

DB_FILE = "vault.db"

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
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