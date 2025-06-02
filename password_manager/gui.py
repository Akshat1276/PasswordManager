import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
from password_manager.crypto_utils import verify_password, derive_key, hash_password
from password_manager.manager import add_credential, get_credentials, get_credential_by_id, delete_credential
import secrets
import string
import pyperclip
import threading
import time

MASTER_PASS_FILE = "master_pass.json"

class LoginWindow:
    """Login window for the password manager."""

    def __init__(self, master):
        self.master = master
        master.title("Password Manager Login")
        master.geometry("350x280")
        master.configure(bg="#f0f4f8")
        master.resizable(False, False)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background="#f0f4f8", font=("Segoe UI", 12))
        style.configure('TButton', font=("Segoe UI", 11), padding=6, background="#4F8EF7", foreground="#fff")
        style.map('TButton',
                  background=[('active', '#356AC3'), ('!active', '#4F8EF7')],
                  foreground=[('active', '#fff'), ('!active', '#fff')])
        style.configure('TEntry', font=("Segoe UI", 11))

        self.label = ttk.Label(master, text="Enter Master Password:")
        self.label.pack(pady=(20, 10))

        self.password_entry = ttk.Entry(master, show="*")
        self.password_entry.pack(pady=5, ipadx=10, ipady=2)
        self.password_entry.focus()

        # --- Add Show Password Checkbox ---
        self.show_var = tk.BooleanVar(value=False)
        self.show_cb = ttk.Checkbutton(
            master, text="Show Password", variable=self.show_var, command=self.toggle_show_password
        )
        self.show_cb.pack(pady=(0, 10))

        self.login_button = ttk.Button(master, text="Login", command=self.login, style='TButton')
        self.login_button.pack(pady=(10, 5))

        self.reset_button = ttk.Button(master, text="Reset Master Password", command=self.reset_password, style='TButton')
        self.reset_button.pack(pady=(0, 10))

        self.forgot_button = ttk.Button(master, text="Forgot Password?", command=self.forgot_password, style='TButton')
        self.forgot_button.pack(pady=(0, 10))

        self.key = None

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
            Dashboard(self.master, self.key)
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def reset_password(self):
        if not os.path.exists(MASTER_PASS_FILE):
            messagebox.showerror("Error", "No master password set. Run setup first.")
            return
        current_password = ask_password("Reset Password", "Enter current master password:")
        if not current_password:
            return
        with open(MASTER_PASS_FILE, "r") as f:
            hash_dict = json.load(f)
        if not verify_password(current_password, hash_dict):
            messagebox.showerror("Error", "Current password is incorrect.")
            return
        new_password = ask_password("Reset Password", "Enter new master password:")
        if not new_password:
            return
        confirm_password = ask_password("Reset Password", "Confirm new master password:")
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        new_hash_dict = hash_password(new_password)
        with open(MASTER_PASS_FILE, "w") as f:
            json.dump(new_hash_dict, f)
        messagebox.showinfo("Success", "Master password has been reset.")

    def forgot_password(self):
        if not os.path.exists(MASTER_PASS_FILE):
            messagebox.showerror("Error", "No master password set. Run setup first.")
            return
        with open(MASTER_PASS_FILE, "r") as f:
            data = json.load(f)
        personal_answer_hash = data.get("personal_answer")
        if not personal_answer_hash:
            messagebox.showerror("Error", "Personal question not set. Cannot reset password.")
            return

        # Ask the personal question
        answer = ask_password("Personal Question", "Which city were you born in? (case sensitive):", show_generate=False)
        if not answer:
            return
        from password_manager.crypto_utils import verify_password, hash_password

        if not verify_password(answer, personal_answer_hash):
            messagebox.showerror("Error", "Incorrect answer to personal question.")
            return

        # Ask for new master password
        new_password = ask_password("Reset Master Password", "Enter new master password:")
        if not new_password:
            return
        confirm_password = ask_password("Reset Master Password", "Confirm new master password:")
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Ask for new pass key
        new_pass_key = ask_password("Reset Pass Key", "Enter new pass key for sensitive actions:")
        if not new_pass_key:
            return
        confirm_pass_key = ask_password("Reset Pass Key", "Confirm new pass key:")
        if new_pass_key != confirm_pass_key:
            messagebox.showerror("Error", "Pass keys do not match.")
            return

        # Ask for new answer to personal question
        new_personal_answer = ask_password("Personal Question", "Set answer for 'Which city were you born in?' (case sensitive):", show_generate=False)
        if not new_personal_answer:
            return

        # Save new credentials
        hash_dict = hash_password(new_password)
        pass_key_hash = hash_password(new_pass_key)
        personal_answer_hash = hash_password(new_personal_answer)
        with open(MASTER_PASS_FILE, "w") as f:
            json.dump({"master": hash_dict, "pass_key": pass_key_hash, "personal_answer": personal_answer_hash}, f)
        messagebox.showinfo("Success", "Master password, pass key, and personal question have been reset.")

class Dashboard(tk.Toplevel):
    def __init__(self, master, key):
        super().__init__(master)
        self.key = key
        self.master = master  # Save reference to root window
        self.title("Password Manager Dashboard")
        self.geometry("500x400")
        self.create_widgets()
        self.refresh_list()

    def create_widgets(self):
        # --- Search Bar ---
        search_frame = tk.Frame(self)
        search_frame.pack(fill=tk.X, pady=(10, 0), padx=10)

        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # --- Treeview ---
        self.tree = ttk.Treeview(self, columns=("Service", "Username"), show="headings")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Username", text="Username")
        self.tree.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add", command=self.add_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="View", command=self.view_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Delete", command=self.delete_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Copy", command=self.copy_entry).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Update", command=self.update_entry).pack(side=tk.LEFT, padx=5)
        # Logout button
        tk.Button(btn_frame, text="Logout", command=self.logout).pack(side=tk.LEFT, padx=5)

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
            messagebox.showwarning("Select Entry", "Please select an entry to delete.")
            return
        entry_id = int(selected[0])
        delete_credential(entry_id)
        self.refresh_list(self.search_var.get())

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

        # 3. Prompt for new password
        new_password = ask_password("Update Password", f"Enter new password for {entry['service']}:")
        if not new_password:
            return
        from password_manager.manager import update_credential
        updated = update_credential(entry_id, entry['service'], entry['username'], new_password, self.key)
        if updated:
            messagebox.showinfo("Success", "Password updated successfully.")
            self.refresh_list(self.search_var.get())
        else:
            messagebox.showerror("Error", "Failed to update password.")

class PasswordPrompt(simpledialog.Dialog):
    def __init__(self, parent, title, prompt, show_generate=True):
        self.prompt = prompt
        self.password = None
        self.show_generate = show_generate
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=3, pady=5)
        self.var = tk.StringVar()
        self.entry = ttk.Entry(master, textvariable=self.var, show="*")
        self.entry.grid(row=1, column=0, padx=5, pady=5)
        self.entry.focus()
        self.show_var = tk.BooleanVar(value=False)
        show_cb = ttk.Checkbutton(master, text="Show Password", variable=self.show_var, command=self.toggle_show)
        show_cb.grid(row=1, column=1, padx=5, pady=5)
        if self.show_generate:
            gen_btn = ttk.Button(master, text="Generate", command=self.generate_password)
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

def ask_password(title, prompt, show_generate=True):
    root = tk._get_default_root()
    dlg = PasswordPrompt(root, title, prompt, show_generate=show_generate)
    return dlg.password

if __name__ == "__main__":
    key = get_encryption_key_via_gui()
    if key:
        print("Encryption key derived, ready to use password manager.")