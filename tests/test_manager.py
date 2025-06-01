import os
import unittest
import sqlite3
import atexit

# Set test database before importing modules that use it
os.environ["DB_FILE"] = "test_vault.db"

from password_manager.db import init_db, get_connection
from password_manager.manager import add_credential, get_credentials, get_credential_by_id, delete_credential
from password_manager.crypto_utils import derive_key


#test cases for manager.py
# -> test_add_and_get_credential
# Adds a credential (service, username, password).
# Retrieves all credentials and checks that the new one exists.
# Fetches the credential by ID and checks that service, username, and password match what was added.

# -> test_delete_credential
# Adds a credential.
# Deletes it by ID.
# Checks that fetching the credential by ID returns None (i.e., it was deleted).


class TestManager(unittest.TestCase):
    """Unit tests for credential management logic."""

    @classmethod
    def setUpClass(cls):
        """Set up a fresh test database and encryption key."""
        cls.test_db = "test_vault.db"
        os.environ["DB_FILE"] = cls.test_db
        if os.path.exists(cls.test_db):
            os.remove(cls.test_db)
        init_db()
        cls.key = derive_key("TestMasterPassword", b"testsalt12345678")

    @classmethod
    def tearDownClass(cls):
        """Clean up the test database file."""
        import gc
        gc.collect()  # Force garbage collection to close any lingering connections
        try:
            sqlite3.connect(cls.test_db).close()
        except Exception:
            pass
        try:
            os.remove(cls.test_db)
        except PermissionError:
            print("Could not delete test DB file; it may still be in use.")

    def setUp(self):
        """Clean the credentials table before each test."""
        with get_connection() as conn:
            conn.execute("DELETE FROM credentials")
            conn.commit()

    def test_add_and_get_credential(self):
        """Test adding a credential and retrieving it by ID."""
        add_credential("TestService", "TestUser", "TestPass123!", self.key)
        creds = get_credentials()
        self.assertEqual(len(creds), 1)
        entry_id = creds[0][0]
        entry = get_credential_by_id(entry_id, self.key)
        self.assertEqual(entry["service"], "TestService")
        self.assertEqual(entry["username"], "TestUser")
        self.assertEqual(entry["password"], "TestPass123!")

    def test_delete_credential(self):
        """Test deleting a credential and ensuring it is removed."""
        add_credential("ToDelete", "User", "Pass", self.key)
        creds = get_credentials()
        entry_id = creds[-1][0]
        delete_credential(entry_id)
        entry = get_credential_by_id(entry_id, self.key)
        self.assertIsNone(entry)

def cleanup():
    """Ensure test database is removed on exit."""
    try:
        os.remove("test_vault.db")
    except Exception:
        pass

atexit.register(cleanup)

if __name__ == "__main__":
    unittest.main()