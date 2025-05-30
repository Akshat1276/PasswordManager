from db import get_connection, init_db
from crypto_utils import encrypt_gcm, decrypt_gcm

init_db()

def add_credential(service, username, password, key):
    encrypted, iv = encrypt_gcm(password.encode(), key)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO credentials (service, username, encrypted_password, iv) VALUES (?, ?, ?, ?)",
            (service, username, encrypted, iv)
        )
        conn.commit()

def get_credentials():
    with get_connection() as conn:
        cur = conn.execute("SELECT id, service, username FROM credentials")
        return cur.fetchall()

def get_credential_by_id(entry_id, key):
    with get_connection() as conn:
        cur = conn.execute("SELECT service, username, encrypted_password, iv FROM credentials WHERE id=?", (entry_id,))
        row = cur.fetchone()
        if row:
            service, username, encrypted_password, iv = row
            password = decrypt_gcm(encrypted_password, key, iv).decode()
            return {"service": service, "username": username, "password": password}
        return None

def delete_credential(entry_id):
    with get_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id=?", (entry_id,))
        conn.commit()