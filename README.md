# 🔐 Password Manager

A secure, cross-platform password manager built with Python and Tkinter.
It stores your credentials in an encrypted local SQLite database, protected by a master password.
The app features a modern, user-friendly GUI, strong cryptography, multi-factor protections, and productivity tools like search, password generator, and clipboard auto-clear.
It also includes robust security mechanisms such as login/forgot-password lockout, password strength meter, and regular password change reminders.

---

## 🚀 Features

- **AES-GCM (Advanced Encryption Standard in Galois/Counter mode) encryption** for all stored passwords
- **Master password** (never stored, only its hash)
- **Password strength checker** in all relevant password prompts (shows Weak/Medium/Strong)
- **Password generator** tool in password prompts
- **Clipboard copy** with auto-clear after 10 seconds
- **Searchable dashboard** for credentials
- **Multi-select and batch delete** of credentials
- **Update both username and password** for any saved service
- **Font scaling and zoom in/out** (Ctrl+Plus/Minus/Equal)
- **Show/hide password** toggle in all password prompts
- **Login lockout** after 5 failed attempts (15-minute lockout)
- **Forgot password lockout** after 5 failed attempts (15-minute lockout)
- **Prompt to change master password every 10 days** for enhanced security
- **Reset master password** (with credential re-encryption)
- **Forgot master password** (deletes all credentials, resets everything)
- **Pass key required** for sensitive actions (view, copy, update, delete)
- **Personal question/answer** for password recovery
- **Input validation:** Prevents blank or space-only entries in all prompts
- **Modern, user-friendly GUI** (Tkinter)
- **Unit tests** for core logic

---

## 📁 Folder Structure

```
PasswordManager/
│
├── password_manager/          # Main package
│   ├── __init__.py
│   ├── db.py
│   ├── manager.py
│   ├── crypto_utils.py
│   ├── gui.py
│
├── tests/                     # Unit tests
│   ├── __init__.py
│   ├── test_manager.py
│   ├── test_crypto_utils.py
│
├── main.py                    # CLI for master password setup/verification
├── requirements.txt
├── .gitignore
├── README.md
```

---

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```sh
   git clone https://github.com/Akshat1276/PasswordManager.git
   cd PasswordManager
   ```

2. **Create and activate a virtual environment (recommended):**
   ```sh
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   
   Windows Users
   ```sh
   pip install -r requirements.txt
   ```
   MacOS Users
   ```sh
   pip install -r requirements.txt
   ```
   MacOS users will probably face issues downloading tkinter library. So
   Install Homebrew (if you don't have it):  
   [https://brew.sh/](https://brew.sh/)

   Install Python with Tk support via Homebrew:**
   ```sh
   brew install python-tk
   ```

   Or, if you want to ensure your Python installation has Tkinter:
   ```sh
   brew install python
   brew install tcl-tk
   ```

---

## 🏃‍♂️ Usage

### **1. Set up your master password (first run):**
```sh
python main.py
```
- Follow the prompt to set your master password.

### **2. Launch the GUI:**
```sh
python -m password_manager.gui
```

- Log in with your master password.
- Add, search, view, copy, and delete credentials securely.

---

## 🧪 Running Tests

All core logic is covered by unit tests.

```sh
python -m unittest discover tests
```

**Test cases include:**
- Key derivation, encryption/decryption, and password hashing/verification
- Adding, retrieving, and deleting credentials

---

## 🔒 Security Notes

- All passwords are encrypted with AES-GCM and a key derived from your master password.
- The master password is never stored—only its hash and salt.
- Sensitive files (`vault.db`, `master_pass.json`) are excluded from git via `.gitignore`.

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

**Enjoy your secure password manager!**
