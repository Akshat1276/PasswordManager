from password_manager.db import get_connection, init_db
from password_manager.crypto_utils import encrypt_gcm, decrypt_gcm

init_db()

def add_credential(service, username, password, key):
    """Encrypt and add a credential to the database."""
    encrypted, iv = encrypt_gcm(password.encode(), key)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO credentials (service, username, encrypted_password, iv) VALUES (?, ?, ?, ?)",
            (service, username, encrypted, iv)
        )
        conn.commit()

def get_credentials():
    """Retrieve all credentials (id, service, username) from the database."""
    with get_connection() as conn:
        cur = conn.execute("SELECT id, service, username FROM credentials")
        return cur.fetchall()

def get_credential_by_id(entry_id, key):
    """Retrieve and decrypt a credential by its ID."""
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT service, username, encrypted_password, iv FROM credentials WHERE id=?",
            (entry_id,)
        )
        row = cur.fetchone()
        if row:
            service, username, encrypted_password, iv = row
            password = decrypt_gcm(encrypted_password, key, iv).decode()
            return {"service": service, "username": username, "password": password}
        return None

def delete_credential(entry_id):
    """Delete a credential from the database by its ID."""
    with get_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id=?", (entry_id,))
        conn.commit()

def update_credential(entry_id, service, username, new_password, key):
    """
    Update the password for an existing credential in the database.
    """
    encrypted, iv = encrypt_gcm(new_password.encode(), key)
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE credentials SET encrypted_password=?, iv=? WHERE id=?",
            (encrypted, iv, entry_id)
        )
        conn.commit()
        return cur.rowcount > 0  # True if a row was updated