import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
from crypto_utils import verify_password, derive_key, hash_password

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

        # Add hover effect using event bindings
        self.login_button.bind("<Enter>", self.on_enter)
        self.login_button.bind("<Leave>", self.on_leave)

        # Reset password button
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
            self.master.destroy()
        else:
            messagebox.showerror("Error", "Incorrect master password.")

    def reset_password(self):
        if not os.path.exists(MASTER_PASS_FILE):
            messagebox.showerror("Error", "No master password set. Run setup first.")
            return
        # Ask for current password
        current_password = simpledialog.askstring("Reset Password", "Enter current master password:", show="*")
        if not current_password:
            return
        with open(MASTER_PASS_FILE, "r") as f:
            hash_dict = json.load(f)
        if not verify_password(current_password, hash_dict):
            messagebox.showerror("Error", "Current password is incorrect.")
            return
        # Ask for new password twice
        new_password = simpledialog.askstring("Reset Password", "Enter new master password:", show="*")
        if not new_password:
            return
        confirm_password = simpledialog.askstring("Reset Password", "Confirm new master password:", show="*")
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        # Save new password hash
        new_hash_dict = hash_password(new_password)
        with open(MASTER_PASS_FILE, "w") as f:
            json.dump(new_hash_dict, f)
        messagebox.showinfo("Success", "Master password has been reset.")

def get_encryption_key_via_gui():
    root = tk.Tk()
    # Add hover style for button
    style = ttk.Style()
    style.configure('Hover.TButton', background='#356AC3', foreground='#fff')
    app = LoginWindow(root)
    root.mainloop()
    return app.key

if __name__ == "__main__":
    key = get_encryption_key_via_gui()
    if key:
        print("Encryption key derived, ready to use password manager.")