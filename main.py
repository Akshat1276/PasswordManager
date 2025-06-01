import os
import getpass
import json
from password_manager.crypto_utils import derive_key, hash_password, verify_password

MASTER_PASS_FILE = "master_pass.json"

def set_master_password():
    password = getpass.getpass("Set a master password: ")
    hash_dict = hash_password(password)
    with open(MASTER_PASS_FILE, "w") as f:
        json.dump(hash_dict, f)
    print("Master password set.")

def verify_master_password():
    if not os.path.exists(MASTER_PASS_FILE):
        print("No master password set.")
        return None
    with open(MASTER_PASS_FILE, "r") as f:
        hash_dict = json.load(f)
    password = getpass.getpass("Enter master password: ")
    if verify_password(password, hash_dict):
        print("Access granted.")
        # Derive encryption key for use after login
        salt = bytes.fromhex(hash_dict["salt"])
        key = derive_key(password, salt)
        return key
    else:
        print("Access denied.")
        return None

if __name__ == "__main__":
    if not os.path.exists(MASTER_PASS_FILE):
        set_master_password()
    else:
        key = verify_master_password()
        if key:
            print("Ready to use password manager.")