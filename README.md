# 🔐 Password Manager

A secure, cross-platform password manager built with Python and Tkinter.  
It stores your credentials in an encrypted local SQLite database, protected by a master password.

---

## 🚀 Features

- **AES-GCM encryption** for all stored passwords
- **Master password** (never stored, only its hash)
- **Searchable dashboard** for credentials
- **Password generator** tool
- **Clipboard copy** with auto-clear
- **Reset master password** option
- **Modern, user-friendly GUI**
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
   git clone https://github.com/yourusername/PasswordManager.git
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
   ```sh
   pip install -r requirements.txt
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
or
```sh
python password_manager/gui.py
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
