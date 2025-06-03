import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
from password_manager.crypto_utils import verify_password, derive_key, hash_password
from password_manager.manager import add_credential, get_credentials, update_credential, get_credential_by_id, delete_credential
import secrets
import string
import pyperclip
import threading
import time
import tkinter.font as tkfont

MASTER_PASS_FILE = "master_pass.json"

class LoginWindow:
    """Login window for the password manager."""

    def __init__(self, master):
        self.master = master
        self.app_font = tkfont.Font(family="Segoe UI", size=12)
        master.title("Password Manager Login")
        master.geometry("500x360")
        master.configure(bg="#f0f4f8")
        master.resizable(True, True)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=self.app_font)
        style.configure('Custom.TCheckbutton', font=self.app_font)

        self.label = ttk.Label(master, text="Enter Master Password:", font=self.app_font)
        self.label.pack(pady=(20, 10))

        self.password_entry = ttk.Entry(master, show="*", font=self.app_font)
        self.password_entry.pack(pady=5, ipadx=10, ipady=2)
        self.password_entry.focus()

        self.show_var = tk.BooleanVar(value=False)
        style = ttk.Style()
        style.configure('Custom.TCheckbutton', font=self.app_font)
        self.show_cb = ttk.Checkbutton(
            master, text="Show Password", variable=self.show_var, command=self.toggle_show_password, style='Custom.TCheckbutton'
        )
        self.show_cb.pack(pady=(0, 10))

        self.login_button = ttk.Button(master, text="Login", command=self.login, style='TButton')
        self.login_button.pack(pady=(10, 5))

        self.reset_button = ttk.Button(master, text="Reset Master Password", command=self.reset_password, style='TButton')
        self.reset_button.pack(pady=(0, 10))

        self.forgot_button = ttk.Button(master, text="Forgot Password?", command=self.forgot_password, style='TButton')
        self.forgot_button.pack(pady=(0, 10))

        self.key = None

        self.bind_zoom_keys()

    def toggle_show_password(self):
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def on_enter(self, event):
        event.widget.configure(style='Hover.TButton')

    def on_leave(self, event):
        event.widget.configure(style='TButton')

    def login(self):
        password = self.password_entry.get()
        if not os.path.exists(MASTER_PASS_FILE):
            messagebox.showerror("Error", "No master password set. Run setup first.")
            return
        with open(MASTER_PASS_FILE, "r") as f:
            data = json.load(f)
        hash_dict = data["master"]  # <-- FIX: get only the master hash dict
        if verify_password(password, hash_dict):
            salt = bytes.fromhex(hash_dict["salt"])
            self.key = derive_key(password, salt)
            messagebox.showinfo("Success", "Login successful!")
            self.master.withdraw()
            Dashboard(self.master, self.key, self.app_font)  # Pass app_font
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def reset_password(self):
        if not os.path.exists(MASTER_PASS_FILE):
            messagebox.showerror("Error", "No master password is set. Please run the setup first.")
            return

        current_password = ask_password("Reset Password", "Enter current master password:", show_generate=False)
        if current_password is None or current_password == "":
            messagebox.showerror("Error", "Reset cancelled. Current master password was not entered.")
            return

        with open(MASTER_PASS_FILE, "r") as f:
            data = json.load(f)
        hash_dict = data["master"]

        if not verify_password(current_password, hash_dict):
            messagebox.showerror("Error", "Current master password is incorrect. Please try again.")
            return

        new_password = ask_password("Reset Password", "Enter new master password:")
        if new_password is None or new_password == "":
            messagebox.showerror("Error", "Reset cancelled. New master password was not entered.")
            return

        confirm_password = ask_password("Reset Password", "Confirm new master password:")
        if confirm_password is None or confirm_password == "":
            messagebox.showerror("Error", "Reset cancelled. Confirmation password was not entered.")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match. Please try again.")
            return

        # --- REENCRYPT CREDENTIALS ---
        old_salt = bytes.fromhex(hash_dict["salt"])
        old_key = derive_key(current_password, old_salt)
        new_hash_dict = hash_password(new_password)
        new_salt = bytes.fromhex(new_hash_dict["salt"])
        new_key = derive_key(new_password, new_salt)

        # Save new master password hash
        data["master"] = new_hash_dict
        with open(MASTER_PASS_FILE, "w") as f:
            json.dump(data, f)

        # Re-encrypt all credentials with the new key
        reencrypt_all_credentials(old_key, new_key)

        messagebox.showinfo("Success", "Master password has been reset successfully. All credentials have been preserved.")

    def forgot_password(self):
        # Lockout mechanism
        lockout_file = "forgot_pw_lockout.json"
        lockout_duration = 15 * 60  # 15 minutes in seconds
        max_attempts = 5

        # Check for lockout
        if os.path.exists(lockout_file):
            with open(lockout_file, "r") as f:
                lockout_data = json.load(f)
            if lockout_data.get("locked_until", 0) > time.time():
                remaining = int(lockout_data["locked_until"] - time.time())
                mins, secs = divmod(remaining, 60)
                messagebox.showerror(
                    "Locked Out",
                    f"Too many incorrect attempts. Please try again after {mins} minutes {secs} seconds."
                )
                return
            else:
                # Reset attempts after lockout period
                os.remove(lockout_file)

        if not os.path.exists(MASTER_PASS_FILE):
            messagebox.showerror("Error", "No master password set. Run setup first.")
            return
        with open(MASTER_PASS_FILE, "r") as f:
            data = json.load(f)
        personal_answer_hash = data.get("personal_answer")
        if not personal_answer_hash:
            messagebox.showerror("Error", "Personal question not set. Cannot reset password.")
            return

        # Load or initialize attempts
        attempts = 0
        if os.path.exists(lockout_file):
            with open(lockout_file, "r") as f:
                lockout_data = json.load(f)
                attempts = lockout_data.get("attempts", 0)

        while attempts < max_attempts:
            answer = ask_password(
                "Personal Question",
                "Which city were you born in? (case sensitive):",
                show_generate=False,
                show_label="Show Text"
            )
            if not answer:
                return

            if verify_password(answer, personal_answer_hash):
                break  # Correct answer, proceed
            else:
                attempts += 1
                if attempts < max_attempts:
                    messagebox.showerror("Error", f"Incorrect answer to personal question. Attempts left: {max_attempts - attempts}")
                # Save attempts
                with open(lockout_file, "w") as f:
                    json.dump({"attempts": attempts, "locked_until": 0}, f)
        else:
            # Lock out for 15 minutes
            with open(lockout_file, "w") as f:
                json.dump({"attempts": attempts, "locked_until": time.time() + lockout_duration}, f)
            messagebox.showerror("Locked Out", "Too many incorrect attempts. Please try again after 15 minutes.")
            return

        # Reset attempts on success
        if os.path.exists(lockout_file):
            os.remove(lockout_file)

        # 2. Warn the user
        proceed = messagebox.askyesno(
            "Warning",
            "All your saved credentials will be deleted and cannot be recovered. Do you want to continue?"
        )
        if not proceed:
            return

        # 3. Delete all credentials
        from password_manager.manager import get_credentials, delete_credential
        credentials = get_credentials()
        for entry in credentials:
            entry_id = entry[0]
            delete_credential(entry_id)

        # 4. Ask the user to set up a new master password
        new_password = ask_password("Setup Master Password", "Enter new master password:")
        if not new_password:
            return
        confirm_password = ask_password("Setup Master Password", "Confirm new master password:")
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Update the master password hash, keep pass_key and personal_answer unchanged
        hash_dict = hash_password(new_password)
        with open(MASTER_PASS_FILE, "w") as f:
            json.dump({
                "master": hash_dict,
                "pass_key": data["pass_key"],
                "personal_answer": data["personal_answer"]
            }, f)

        messagebox.showinfo("Success", "Master password has been reset. All previous credentials have been deleted.")

    def set_font_size(self, size):
        style = ttk.Style()
        style.configure('TLabel', font=("Segoe UI", size))
        style.configure('TEntry', font=("Segoe UI", size))
        style.configure('TButton', font=("Segoe UI", size))

    def bind_zoom_keys(self):
        self.master.bind('<Control-plus>', self.zoom_in)
        self.master.bind('<Control-minus>', self.zoom_out)
        self.master.bind('<Control-equal>', self.zoom_in)  # For Ctrl+= as well

    def zoom_in(self, event=None):
        size = self.app_font['size'] + 2
        self.app_font.configure(size=size)

    def zoom_out(self, event=None):
        size = max(8, self.app_font['size'] - 2)
        self.app_font.configure(size=size)

class Dashboard(tk.Toplevel):
    def __init__(self, master, key, app_font):
        super().__init__(master)
        self.key = key
        self.master = master
        self.app_font = app_font
        self.title("Password Manager Dashboard")
        self.geometry("500x400")
        self.resizable(True, True)
        self.create_widgets()
        self.refresh_list()
        self.bind_zoom_keys()

    def create_widgets(self):
        search_frame = tk.Frame(self)
        search_frame.pack(fill=tk.X, pady=(10, 0), padx=10)

        tk.Label(search_frame, text="Search:", font=self.app_font).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30, font=self.app_font)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Enable extended selection mode
        self.tree = ttk.Treeview(self, columns=("Service", "Username"), show="headings", selectmode="extended")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Username", text="Username")
        self.tree.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)
        style = ttk.Style(self)
        style.configure("Treeview", font=self.app_font)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add", command=self.add_entry, font=self.app_font).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="View", command=self.view_entry, font=self.app_font).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete", command=self.delete_entry, font=self.app_font).pack(side=tk.LEFT, padx=5)
        # tk.Button(btn_frame, text="Delete Selected", command=self.delete_selected_entries, font=self.app_font).pack(side=tk.LEFT, padx=5)  # <-- REMOVE THIS LINE
        tk.Button(btn_frame, text="Copy", command=self.copy_entry, font=self.app_font).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Update", command=self.update_entry, font=self.app_font).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Logout", command=self.logout, font=self.app_font).pack(side=tk.LEFT, padx=5)

    def logout(self):
        self.destroy()
        # Clear the password entry and reset the show password checkbox in the login window when logging out
        if hasattr(self.master, "password_entry"):
            self.master.password_entry.delete(0, tk.END)
        if hasattr(self.master, "show_var"):
            self.master.show_var.set(False)
            self.master.password_entry.config(show="*")
        self.master.deiconify()

    def refresh_list(self, filter_text=""):
        for row in self.tree.get_children():
            self.tree.delete(row)
        filter_text = filter_text.lower()
        for entry in get_credentials():
            service, username = entry[1], entry[2]
            if (filter_text in service.lower()) or (filter_text in username.lower()):
                self.tree.insert("", tk.END, iid=entry[0], values=(service, username))

    def on_search(self, *args):
        filter_text = self.search_var.get()
        self.refresh_list(filter_text)

    def add_entry(self):
        service = simpledialog.askstring("Service", "Enter service name:")
        username = simpledialog.askstring("Username", "Enter username:")
        password = ask_password("Password", "Enter password:")
        if not service or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return
        add_credential(service, username, password, self.key)
        self.refresh_list(self.search_var.get())

    def view_entry(self):
        # Prompt for pass key
        pass_key = ask_password("Pass Key", "Enter your pass key for sensitive actions:", show_generate=False)
        if not pass_key:
            return
        try:
            with open(MASTER_PASS_FILE, "r") as f:
                data = json.load(f)
            pass_key_hash = data["pass_key"]
            if not verify_password(pass_key, pass_key_hash):
                messagebox.showerror("Error", "Incorrect pass key.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Could not verify pass key: {e}")
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to view.")
            return
        entry_id = int(selected[0])
        entry = get_credential_by_id(entry_id, self.key)
        if entry:
            messagebox.showinfo("Credential", f"Service: {entry['service']}\nUsername: {entry['username']}\nPassword: {entry['password']}")
        else:
            messagebox.showerror("Error", "Entry not found.")
            return

    def delete_entry(self):
        # Prompt for pass key
        pass_key = ask_password("Pass Key", "Enter your pass key for sensitive actions:", show_generate=False)
        if not pass_key:
            return
        try:
            with open(MASTER_PASS_FILE, "r") as f:
                data = json.load(f)
            pass_key_hash = data["pass_key"]
            if not verify_password(pass_key, pass_key_hash):
                messagebox.showerror("Error", "Incorrect pass key.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Could not verify pass key: {e}")
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select entries to delete.")
            return

        for item in selected:
            entry_id = int(item)
            delete_credential(entry_id)
        self.refresh_list(self.search_var.get())
        messagebox.showinfo("Deleted", "Selected entries have been deleted.")

    def copy_entry(self):
        # Prompt for pass key
        pass_key = ask_password("Pass Key", "Enter your pass key for sensitive actions:", show_generate=False)
        if not pass_key:
            return
        try:
            with open(MASTER_PASS_FILE, "r") as f:
                data = json.load(f)
            pass_key_hash = data["pass_key"]
            if not verify_password(pass_key, pass_key_hash):
                messagebox.showerror("Error", "Incorrect pass key.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Could not verify pass key: {e}")
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to copy.")
            return
        entry_id = int(selected[0])
        entry = get_credential_by_id(entry_id, self.key)
        if entry:
            copy_to_clipboard(entry['password'])
            messagebox.showinfo("Copied", "Password copied to clipboard (auto-clears in 10s).")

    def update_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to update.")
            return

        # 1. Prompt for pass key
        pass_key = ask_password("Pass Key", "Enter your pass key for sensitive actions:", show_generate=False)
        if not pass_key:
            return

        # Verify pass key
        try:
            with open(MASTER_PASS_FILE, "r") as f:
                data = json.load(f)
            pass_key_hash = data["pass_key"]
            if not verify_password(pass_key, pass_key_hash):
                messagebox.showerror("Error", "Incorrect pass key.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Could not verify pass key: {e}")
            return

        entry_id = int(selected[0])
        entry = get_credential_by_id(entry_id, self.key)
        if not entry:
            messagebox.showerror("Error", "Entry not found.")
            return

        # 2. Prompt for current password and verify
        current_password = ask_password("Current Password", f"Enter current password for {entry['service']}:")
        if not current_password:
            return
        if current_password != entry['password']:
            messagebox.showerror("Error", "Current password is incorrect.")
            return

        # 3. Prompt for new username and new password
        new_username = simpledialog.askstring("Update Username", f"Enter new username for {entry['service']}:", initialvalue=entry['username'])
        if not new_username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return

        new_password = ask_password("Update Password", f"Enter new password for {entry['service']}:")
        if not new_password:
            return

        from password_manager.manager import update_credential
        updated = update_credential(entry_id, entry['service'], new_username, new_password, self.key)
        if updated:
            messagebox.showinfo("Success", "Username and password updated successfully.")
            self.refresh_list(self.search_var.get())
        else:
            messagebox.showerror("Error", "Failed to update credentials.")

    def delete_selected_entries(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Select Entry", "Please select entries to delete.")
            return

        # Prompt for pass key
        pass_key = ask_password("Pass Key", "Enter your pass key for sensitive actions:", show_generate=False)
        if not pass_key:
            return
        try:
            with open(MASTER_PASS_FILE, "r") as f:
                data = json.load(f)
            pass_key_hash = data["pass_key"]
            if not verify_password(pass_key, pass_key_hash):
                messagebox.showerror("Error", "Incorrect pass key.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Could not verify pass key: {e}")
            return

        for item in selected_items:
            entry_id = int(item)
            delete_credential(entry_id)
        self.refresh_list(self.search_var.get())
        messagebox.showinfo("Deleted", "Selected entries have been deleted.")

    def set_font_size(self, size):
        style = ttk.Style()
        style.configure('TLabel', font=("Segoe UI", size))
        style.configure('TEntry', font=("Segoe UI", size))
        style.configure('TButton', font=("Segoe UI", size))

    def bind_zoom_keys(self):
        self.bind('<Control-plus>', self.zoom_in)
        self.bind('<Control-minus>', self.zoom_out)
        self.bind('<Control-equal>', self.zoom_in)

    def zoom_in(self, event=None):
        size = self.app_font['size'] + 2
        self.app_font.configure(size=size)

    def zoom_out(self, event=None):
        size = max(8, self.app_font['size'] - 2)
        self.app_font.configure(size=size)

class PasswordPrompt(simpledialog.Dialog):
    def __init__(self, parent, title, prompt, show_generate=True, show_label="Show Password", app_font=None):
        self.prompt = prompt
        self.password = None
        self.show_generate = show_generate
        self.show_label = show_label
        self.app_font = app_font
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.prompt, font=self.app_font).grid(row=0, column=0, columnspan=3, pady=5)
        self.var = tk.StringVar()
        self.entry = ttk.Entry(master, textvariable=self.var, show="*", font=self.app_font)
        self.entry.grid(row=1, column=0, padx=5, pady=5)
        self.entry.focus()
        self.show_var = tk.BooleanVar(value=False)
        style = ttk.Style(master)
        style.configure('Dialog.TCheckbutton', font=self.app_font)
        style.configure('TButton', font=self.app_font)
        show_cb = ttk.Checkbutton(
            master,
            text=self.show_label,
            variable=self.show_var,
            command=self.toggle_show,
            style='Dialog.TCheckbutton'
        )
        show_cb.grid(row=1, column=1, padx=5, pady=5)
        if self.show_generate:
            gen_btn = ttk.Button(master, text="Generate", command=self.generate_password, style='TButton')
            gen_btn.grid(row=1, column=2, padx=5, pady=5)
        return self.entry

    def toggle_show(self):
        if self.show_var.get():
            self.entry.config(show="")
        else:
            self.entry.config(show="*")

    def generate_password(self):
        # Default length 16, you can prompt for length if you want
        pwd = generate_password(8)
        self.var.set(pwd)

    def apply(self):
        self.password = self.var.get()

def get_encryption_key_via_gui():
    root = tk.Tk()
    style = ttk.Style()
    style.configure('Hover.TButton', background='#356AC3', foreground='#fff')
    app = LoginWindow(root)
    root.mainloop()
    return app.key
def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure password has at least one lowercase, uppercase, digit, and symbol
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
            return password
def copy_to_clipboard(text, clear_after=10):
    pyperclip.copy(text)
    def clear_clipboard():
        time.sleep(clear_after)
        # Only clear if clipboard still has the password
        if pyperclip.paste() == text:
            pyperclip.copy('')
    threading.Thread(target=clear_clipboard, daemon=True).start()

def ask_password(title, prompt, show_generate=True, show_label="Show Password"):
    root = tk._get_default_root()
    # Try to get app_font from the LoginWindow or Dashboard instance if possible
    app_font = None
    for widget in root.winfo_children():
        if hasattr(widget, 'app_font'):
            app_font = widget.app_font
            break
    dlg = PasswordPrompt(root, title, prompt, show_generate=show_generate, show_label=show_label, app_font=app_font)
    return dlg.password

def reencrypt_all_credentials(old_key, new_key):
    """
    Decrypt all credentials with old_key and re-encrypt them with new_key.
    """
    credentials = get_credentials()
    for entry in credentials:
        entry_id, service, username = entry[0], entry[1], entry[2]
        # Get decrypted password with old key
        cred = get_credential_by_id(entry_id, old_key)
        if cred is None:
            continue  # Skip if can't decrypt
        password = cred['password']
        # Update credential with new key (this will re-encrypt)
        update_credential(entry_id, service, username, password, new_key)

if __name__ == "__main__":
    key = get_encryption_key_via_gui()
    if key:
        print("Encryption key derived, ready to use password manager.")