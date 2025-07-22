import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

# ===== Configuration =====
SALT_FILE = "salt.key"
PASSWORDS_FILE = "passwords.dat"
KEY_ITERATIONS = 100_000  # Recommended value for strong PBKDF2 security

# ===== Helper Functions =====

def generate_salt():
    """Generate a new salt and save it to disk."""
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def load_salt():
    """Load salt from file, or create a new one if it doesn't exist."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    return generate_salt()

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a secure encryption key from the master password and salt
    using PBKDF2 HMAC SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KEY_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def initialize_cipher(master_password: str) -> Fernet:
    """
    Set up the Fernet cipher object using the derived encryption key.
    """
    salt = load_salt()
    key = derive_key(master_password, salt)
    return Fernet(key)

def encrypt_data(cipher: Fernet, data: str) -> str:
    """Encrypt a string using the provided Fernet cipher."""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(cipher: Fernet, encrypted_data: str) -> str:
    """Decrypt a string using the provided Fernet cipher."""
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        print(f"Decryption failed: {e}")
        print("This may be due to an incorrect master password or corrupted data.")
        return ""

# ===== Password Management =====

def load_passwords(cipher: Fernet) -> dict:
    """
    Load and decrypt password data from file, returning as a dictionary.
    Returns an empty dict if no passwords exist or decryption fails.
    """
    if not os.path.exists(PASSWORDS_FILE):
        return {}

    try:
        with open(PASSWORDS_FILE, "r") as f:
            encrypted_content = f.read()
            if not encrypted_content:
                return {}
            decrypted_json_string = decrypt_data(cipher, encrypted_content)
            if not decrypted_json_string:
                print("Failed to decrypt password file. Check master password.")
                return {}
            return json.loads(decrypted_json_string)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        print("Error: Password file is corrupted or invalid JSON.")
        return {}
    except Exception as e:
        print(f"Unexpected error while loading passwords: {e}")
        return {}

def save_passwords(cipher: Fernet, passwords: dict):
    """
    Encrypt and write the current passwords dictionary to disk.
    """
    try:
        passwords_json_string = json.dumps(passwords)
        encrypted_content = encrypt_data(cipher, passwords_json_string)
        with open(PASSWORDS_FILE, "w") as f:
            f.write(encrypted_content)
    except Exception as e:
        print(f"Error saving passwords: {e}")

def add_password(passwords: dict):
    """
    Prompt the user to add a new password for a service.
    Stores entry in the current session (save to disk before exit).
    """
    service = input("Enter service name (e.g., Google, Facebook): ").strip()
    if not service:
        print("Service name cannot be empty.")
        return

    username = input(f"Enter username/email for {service}: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
        
    password = getpass(f"Enter password for {service} (input will be hidden): ").strip()
    if not password:
        print("Password cannot be empty.")
        return
    
    confirm_password = getpass("Confirm password: ").strip()
    if password != confirm_password:
        print("Passwords do not match. Please try again.")
        return

    if service not in passwords:
        passwords[service] = []
    passwords[service].append({"username": username, "password": password})
    print(f"Password for {service} ({username}) added successfully.")

def view_passwords(passwords: dict):
    """
    Display all stored passwords for each service.
    """
    if not passwords:
        print("No passwords stored yet.")
        return

    print("\n--- Stored Passwords ---")
    for service, entries in passwords.items():
        print(f"\nService: {service}")
        if not entries:
            print("  No entries for this service.")
            continue
        for i, entry in enumerate(entries):
            print(f"  {i+1}. Username: {entry['username']}")
            print(f"      Password: {entry['password']}")
    print("------------------------\n")

def get_master_password() -> str:
    """
    Securely prompt user for a master password and confirmation.
    Used for both initial setup and login.
    """
    while True:
        password = getpass("Enter your MASTER password: ")
        if not password:
            print("Master password cannot be empty. Please try again.")
            continue
        confirm_password = getpass("Confirm MASTER password: ")
        if password == confirm_password:
            return password
        print("Master passwords do not match. Please try again.")

# ===== Main Application Loop =====

def main():
    """
    Command-line interface for the password manager.
    Handles login, password operations, and file saving.
    """
    print("Welcome to the Python Password Manager!")

    # Authenticate and initialize cipher
    master_password = get_master_password()
    try:
        cipher = initialize_cipher(master_password)
    except Exception as e:
        print(f"Error initializing encryption: {e}")
        print("Could not derive key. Exiting.")
        return

    print("Loading passwords...")
    current_passwords = load_passwords(cipher) 

    if os.path.exists(PASSWORDS_FILE) and not current_passwords and os.path.getsize(PASSWORDS_FILE) > 0:
        print("\nFailed to decrypt existing password file.")
        print("Likely causes: wrong master password or corrupted file.")
        print("To reset, delete 'salt.key' and 'passwords.dat'. This erases all stored passwords.")
        choice = input("Continue with an empty password set (y/n)? ").lower()
        if choice != 'y':
            print("Exiting.")
            return
        current_passwords = {}

    while True:
        print("\nWhat would you like to do?")
        print("1. Add a new password")
        print("2. View stored passwords")
        print("3. Save and Exit")
        print("4. Exit without saving")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            add_password(current_passwords)
        elif choice == '2':
            view_passwords(current_passwords)
        elif choice == '3':
            print("Saving passwords...")
            save_passwords(cipher, current_passwords)
            print("Passwords saved. Exiting.")
            break
        elif choice == '4':
            print("Exiting without saving changes.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
