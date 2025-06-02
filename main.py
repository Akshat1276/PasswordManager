import os
import getpass
import json
from password_manager.crypto_utils import derive_key, hash_password, verify_password

MASTER_PASS_FILE = "master_pass.json"

def set_master_password():
    password = getpass.getpass("Set a master password: ")
    pass_key = getpass.getpass("Set a pass key (for sensitive actions): ")
    personal_answer = getpass.getpass("Which city were you born in? (case sensitive): ")
    hash_dict = hash_password(password)
    pass_key_hash = hash_password(pass_key)
    personal_answer_hash = hash_password(personal_answer)
    # Store all hashes in the same file
    with open(MASTER_PASS_FILE, "w") as f:
        json.dump({"master": hash_dict, "pass_key": pass_key_hash, "personal_answer": personal_answer_hash}, f)
    print("Master password, pass key, and personal question set.")

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