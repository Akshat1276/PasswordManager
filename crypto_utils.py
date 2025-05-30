from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import hashlib
import hmac

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive a 32-byte AES key from the password using PBKDF2 with SHA256."""
    return PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

def encrypt_gcm(plaintext: bytes, key: bytes) -> tuple:
    """Encrypt plaintext using AES-GCM. Returns (ciphertext, nonce/iv)."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Store tag with ciphertext for authentication
    enc = base64.b64encode(tag + ciphertext)
    return enc, cipher.nonce

def decrypt_gcm(enc_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-GCM encrypted data using nonce/iv."""
    raw = base64.b64decode(enc_data)
    tag, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def hash_password(password: str, salt: bytes = None, iterations: int = 200_000) -> dict:
    if salt is None:
        salt = get_random_bytes(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    return {
        "salt": salt.hex(),
        "hash": hash_bytes.hex(),
        "iterations": iterations
    }

def verify_password(password: str, hash_dict: dict) -> bool:
    salt = bytes.fromhex(hash_dict["salt"])
    iterations = hash_dict.get("iterations", 200_000)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    return hmac.compare_digest(hash_bytes.hex(), hash_dict["hash"])