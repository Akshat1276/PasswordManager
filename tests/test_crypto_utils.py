import unittest
from password_manager.crypto_utils import derive_key, encrypt_gcm, decrypt_gcm, hash_password, verify_password


# Test cases for the crypto_utils module
# -> test_key_derivation
# Checks that deriving a key with the same password and salt always produces the same result.
# Checks that the derived key is 32 bytes long.

# -> test_encrypt_decrypt_gcm
# Encrypts a plaintext with a key, then decrypts it.
# Asserts that the decrypted text matches the original plaintext.

# -> test_hash_and_verify_password
# Hashes a password and verifies that the correct password passes verification.
# Verifies that an incorrect password does not pass verification.
class TestCryptoUtils(unittest.TestCase):
    def test_key_derivation(self):
        password = "TestPassword123!"
        salt = b"1234567890abcdef"
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_encrypt_decrypt_gcm(self):
        key = b"A" * 32
        plaintext = b"SecretData"
        enc, nonce = encrypt_gcm(plaintext, key)
        dec = decrypt_gcm(enc, key, nonce)
        self.assertEqual(dec, plaintext)

    def test_hash_and_verify_password(self):
        password = "StrongPassword!"
        hash_dict = hash_password(password)
        self.assertTrue(verify_password(password, hash_dict))
        self.assertFalse(verify_password("WrongPassword", hash_dict))

if __name__ == "__main__":
    unittest.main()