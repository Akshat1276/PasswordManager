import unittest
import os
from crypto_utils import derive_key, encrypt, decrypt

class TestCryptoUtils(unittest.TestCase):
    def setUp(self):
        self.password = "TestPassword123!"
        self.salt = os.urandom(16)
        self.key = derive_key(self.password, self.salt)
        self.data = b"Secret data for testing!"

    def test_key_derivation_same_password(self):
        key2 = derive_key(self.password, self.salt)
        self.assertEqual(self.key, key2)

    def test_key_derivation_different_password(self):
        key2 = derive_key("WrongPassword", self.salt)
        self.assertNotEqual(self.key, key2)

    def test_encryption_decryption(self):
        encrypted = encrypt(self.data, self.key)
        decrypted = decrypt(encrypted, self.key)
        self.assertEqual(self.data, decrypted)

    def test_encryption_with_wrong_key(self):
        encrypted = encrypt(self.data, self.key)
        wrong_key = derive_key("AnotherPassword", self.salt)
        with self.assertRaises(Exception):
            decrypt(encrypted, wrong_key)

if __name__ == "__main__":
    unittest.main()