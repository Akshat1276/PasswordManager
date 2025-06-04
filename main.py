import os
import getpass
import json
import time
from password_manager.crypto_utils import derive_key, hash_password, verify_password

MASTER_PASS_FILE = "master_pass.json"

def set_master_password():
    print("Set up your master password for the password manager.")
    password = input("Enter new master password: ")
    confirm = input("Confirm new master password: ")
    if password != confirm:
        print("Passwords do not match. Exiting setup.")
        return

    # Optionally, set up pass key and personal answer here
    pass_key = input("Set a pass key for sensitive actions: ")
    personal_answer = input("Set answer to your personal question (e.g., city you were born in): ")

    hash_dict = hash_password(password)
    pass_key_hash = hash_password(pass_key)
    personal_answer_hash = hash_password(personal_answer)

    # Write all info, including last_changed
    with open(MASTER_PASS_FILE, "w") as f:
        json.dump({
            "master": hash_dict,
            "pass_key": pass_key_hash,
            "personal_answer": personal_answer_hash,
            "last_changed": int(time.time())
        }, f)

    print("Master password setup complete.")

def verify_master_password():
    if not os.path.exists(MASTER_PASS_FILE):
        print("No master password set.")
        return None
    with open(MASTER_PASS_FILE, "r") as f:
        data = json.load(f)
    hash_dict = data["master"]
    password = getpass.getpass("Enter master password: ")
    if verify_password(password, hash_dict):
        print("Access granted.")
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