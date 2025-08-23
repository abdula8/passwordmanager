import tkinter as tk
from tkinter import messagebox, ttk
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
from getpass import getpass
import pyperclip
import keyring  # Added for secure OS credential storage
from setup_helper import full_setup

# Install important libraries for this scritp, automatically
full_setup()


class SecurePasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("500x400")
        self.key = None
        self.cipher = None
        self.data_file = "passwords.enc"
        self.master_hash_file = "master.hash"
        self.master_salt = None
        self.entries = {}

        # Initialize UI
        self._init_login_screen()

    def _hash_password(self, password, salt=None):
        """Derive a key from the password using PBKDF2HMAC."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def _verify_master_password(self, password):
        """Verify the master password against the stored hash."""
        if not os.path.exists(self.master_hash_file):
            return False, None
        with open(self.master_hash_file, "rb") as f:
            stored_salt, stored_hash = f.read(16), f.read()
        derived_key, _ = self._hash_password(password, stored_salt)
        return hashlib.sha256(derived_key).digest() == stored_hash, derived_key

    def _save_master_password(self, password):
        """Save the hashed master password and salt."""
        key, salt = self._hash_password(password)
        hashed_key = hashlib.sha256(key).digest()
        with open(self.master_hash_file, "wb") as f:
            f.write(salt + hashed_key)

    def _load_encrypted_data(self):
        """Load and decrypt the stored passwords."""
        if os.path.exists(self.data_file):
            with open(self.data_file, "rb") as f:
                encrypted_data = f.read()
            try:
                decrypted_data = self.cipher.decrypt(encrypted_data)
                self.entries = json.loads(decrypted_data.decode())
            except Exception:
                messagebox.showerror("Error", "Failed to decrypt data. Wrong master password or corrupted file.")
                self.root.quit()
        else:
            self.entries = {}

    def _save_encrypted_data(self):
        """Encrypt and save the password data."""
        encrypted_data = self.cipher.encrypt(json.dumps(self.entries).encode())
        with open(self.data_file, "wb") as f:
            f.write(encrypted_data)

    def _init_login_screen(self):
        """Initialize the login screen."""
        self.login_frame = ttk.Frame(self.root, padding="10")
        self.login_frame.pack(fill="both", expand=True)

        ttk.Label(self.login_frame, text="Enter Master Password:").pack(pady=10)
        self.master_password_entry = ttk.Entry(self.login_frame, show="*")
        self.master_password_entry.pack(pady=5)
        ttk.Button(self.login_frame, text="Login", command=self._login).pack(pady=10)

        if not os.path.exists(self.master_hash_file):
            ttk.Label(self.login_frame, text="No master password set. Set one:").pack(pady=10)
            self.new_password_entry = ttk.Entry(self.login_frame, show="*")
            self.new_password_entry.pack(pady=5)
            ttk.Button(self.login_frame, text="Set Password", command=self._set_master_password).pack(pady=10)

    def _set_master_password(self):
        """Set a new master password."""
        password = self.new_password_entry.get()
        if len(password) < 12:
            messagebox.showerror("Error", "Password must be at least 12 characters long.")
            return
        self._save_master_password(password)
        self._init_encryption(password)
        self._load_main_screen()

    def _login(self):
        """Handle login attempt."""
        password = self.master_password_entry.get()
        is_valid, key = self._verify_master_password(password)
        if is_valid:
            self.key = key
            self.cipher = Fernet(self.key)
            self._load_encrypted_data()
            self.login_frame.destroy()
            self._load_main_screen()
        else:
            messagebox.showerror("Error", "Invalid master password.")

    def _init_encryption(self, password):
        """Initialize encryption with the master password."""
        self.key, _ = self._hash_password(password, self.master_salt)
        self.cipher = Fernet(self.key)

    def _load_main_screen(self):
        """Initialize the main password manager screen."""
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill="both", expand=True)

        # Add new password
        ttk.Label(self.main_frame, text="Service:").pack()
        self.service_entry = ttk.Entry(self.main_frame)
        self.service_entry.pack(pady=5)
        ttk.Label(self.main_frame, text="Username:").pack()
        self.username_entry = ttk.Entry(self.main_frame)
        self.username_entry.pack(pady=5)
        ttk.Label(self.main_frame, text="Password:").pack()
        self.password_entry = ttk.Entry(self.main_frame, show="*")
        self.password_entry.pack(pady=5)
        ttk.Button(self.main_frame, text="Add Password", command=self._add_password).pack(pady=10)
        
        # Adding Search box to search about services' passwords
        ttk.Label(self.main_frame, text="Search services:").pack()
        self.search_entry = ttk.Entry(self.main_frame)
        self.search_entry.pack(pady=5)
        # bind the typing event here
        self.search_entry.bind("<KeyRelease>", lambda e: self._search_entries())

        # Password list
        self.tree = ttk.Treeview(self.main_frame, columns=("Service", "Username", "Password"), show="headings")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.pack(fill="both", expand=True, pady=10)
        ttk.Button(self.main_frame, text="Show Password", command=self._show_password).pack(pady=5)
        
        # Create right-click context menu
        self.context_menu = tk.Menu(self.main_frame, tearoff=0)
        self.context_menu.add_command(label="Copy Password", command=self._copy_password)

        # Bind right-click to show context menu
        self.tree.bind("<Button-3>", self._show_context_menu)

        # Bind Ctrl+C and Cmd+C for copying
        self.tree.bind("<Control-c>", self._copy_password)
        self.tree.bind("<Command-c>", self._copy_password)

        self._update_treeview()

    def _search_entries(self):
        query = self.search_entry.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        # self.search_entry.bind("<KeyRelease>", lambda e: self._search_entries())
        for service, details in self.entries.items():
            if query in service.lower() or query in details["username"].lower():
                self.tree.insert("", tk.END, values=(service, details["username"], "****"))
            # self.tree.insert("", tk.END, values=(service, details["username"], "****"))

    def _add_password(self):
        """Add a new password entry."""
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if service and username and password:
            # Store password in keyring
            keyring.set_password("SecurePasswordManager", f"{service}_password", password)
            self.entries[service] = {"username": username, "password": password}
            self._save_encrypted_data()
            self._update_treeview()
            self.service_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            # Minimize password exposure in memory
            password = None
        else:
            messagebox.showerror("Error", "All fields are required.")

    def _update_treeview(self):
        """Update the Treeview with current entries."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for service, details in self.entries.items():
            self.tree.insert("", tk.END, values=(service, details["username"], "****"))
    def _show_context_menu(self, event):
        """Show the right-click context menu at the cursor position."""
        # Select the item under the cursor
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_password(self, event=None):
        """Copy the selected password to the clipboard."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select an entry to copy the password.")
            return
        service = self.tree.item(selected)["values"][0]
        password = self.entries[service]["password"]
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard.")
            password = None  # Minimize memory exposure
        else:
            messagebox.showerror("Error", "Failed to retrieve password.")

    def _show_password(self):
        """Show the selected password in-place in the Treeview, then hide after 5 seconds."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select an entry to show the password.")
            return
        service = self.tree.item(selected)["values"][0]
        # password = self.entries[service]["password"]
        password = keyring.get_password("SecurePasswordManager", f"{service}_password")
        if password:
            # Update Treeview to show the password
            self.tree.item(selected, values=(service, self.entries[service]["username"], password))
            # Schedule hiding the password after 5 seconds
            self.root.after(5000, lambda: self._hide_password(selected, service))
            password = None  # Minimize memory exposure
        else:
            messagebox.showerror("Error", "Failed to retrieve password.")

        # Update Treeview to show the password
        self.tree.item(selected, values=(service, self.entries[service]["username"], password))

        # Schedule hiding the password after 5 seconds
        self.root.after(500, lambda: self._hide_password(selected, service))
    
    def _hide_password(self, item, service):
        """Hide the password in the Treeview by reverting to asterisks."""
        if item in self.tree.get_children():  # Check if item still exists
            self.tree.item(item, values=(service, self.entries[service]["username"], "****"))
        # Note: Python's garbage collector may retain 'password' in memory.
        # For better security, use a library like 'securestring' to zero-out memory.


    # def _show_password(self):
    #     """Show the selected password."""
    #     selected = self.tree.selection()
    #     if not selected:
    #         messagebox.showwarning("Warning", "Select an entry to show the password.")
    #         return
    #     service = self.tree.item(selected)["values"][0]
    #     password = self.entries[service]["password"]
    #     messagebox.showinfo("Password", f"Service: {service}\nPassword: {password}")

    def run(self):
        """Run the application."""
        self.root.mainloop()

if __name__ == "__main__":
    app = SecurePasswordManager()
    app.run()