import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
from crypto_utils import verify_password, derive_key, hash_password
from manager import add_credential, get_credentials, get_credential_by_id, delete_credential
import secrets
import string
import pyperclip
import threading
import time

MASTER_PASS_FILE = "master_pass.json"

class LoginWindow:
    def __init__(self, master):
        self.master = master
        master.title("Password Manager Login")
        master.geometry("350x200")
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

        self.login_button = ttk.Button(master, text="Login", command=self.login, style='TButton')
        self.login_button.pack(pady=(10, 5))
        self.login_button.bind("<Enter>", self.on_enter)
        self.login_button.bind("<Leave>", self.on_leave)

        self.reset_button = ttk.Button(master, text="Reset Master Password", command=self.reset_password, style='TButton')
        self.reset_button.pack(pady=(0, 10))
        self.reset_button.bind("<Enter>", self.on_enter)
        self.reset_button.bind("<Leave>", self.on_leave)

        self.key = None

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
            hash_dict = json.load(f)
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
        current_password = simpledialog.askstring("Reset Password", "Enter current master password:", show="*")
        if not current_password:
            return
        with open(MASTER_PASS_FILE, "r") as f:
            hash_dict = json.load(f)
        if not verify_password(current_password, hash_dict):
            messagebox.showerror("Error", "Current password is incorrect.")
            return
        new_password = simpledialog.askstring("Reset Password", "Enter new master password:", show="*")
        if not new_password:
            return
        confirm_password = simpledialog.askstring("Reset Password", "Confirm new master password:", show="*")
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        new_hash_dict = hash_password(new_password)
        with open(MASTER_PASS_FILE, "w") as f:
            json.dump(new_hash_dict, f)
        messagebox.showinfo("Success", "Master password has been reset.")

class Dashboard(tk.Toplevel):
    def __init__(self, master, key):
        super().__init__(master)
        self.key = key
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
        tk.Button(btn_frame, text="Generate", command=self.generate_password_dialog).pack(side=tk.LEFT, padx=5)

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
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        if not service or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return
        add_credential(service, username, password, self.key)
        self.refresh_list(self.search_var.get())

    def view_entry(self):
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
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to delete.")
            return
        entry_id = int(selected[0])
        delete_credential(entry_id)
        self.refresh_list(self.search_var.get())

    def copy_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Entry", "Please select an entry to copy.")
            return
        entry_id = int(selected[0])
        entry = get_credential_by_id(entry_id, self.key)
        if entry:
            copy_to_clipboard(entry['password'])
            messagebox.showinfo("Copied", "Password copied to clipboard (auto-clears in 10s).")

    def generate_password_dialog(self):
        length = simpledialog.askinteger("Password Length", "Enter password length (min 5):", minvalue=5, initialvalue=16)
        if length:
            pwd = generate_password(length)
            # Show generated password and option to copy
            if messagebox.askyesno("Generated Password", f"{pwd}\n\nCopy to clipboard?"):
                copy_to_clipboard(pwd)

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

if __name__ == "__main__":
    key = get_encryption_key_via_gui()
    if key:
        print("Encryption key derived, ready to use password manager.")