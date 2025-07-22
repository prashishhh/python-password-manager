# Python Password Manager

A secure, command-line password manager built with Python.  
This project demonstrates the use of strong encryption, safe password input, and local encrypted file storage for personal account management.

---

## Features

- **Master password** protection and authentication
- Secure storage using **Fernet symmetric encryption**
- Key derivation via **PBKDF2-HMAC** with salt for added security
- Add and view multiple account credentials
- Sensitive files (`salt.key`, `passwords.dat`) excluded from version control

---

## Quick Start

1. **Clone this repository:**
    ```bash
    git clone https://github.com/prashishhh/python-password-manager.git
    cd python-password-manager
    ```

2. **(Recommended) Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies:**
    ```bash
    pip install cryptography
    ```

4. **Run the application:**
    ```bash
    python password-manager.py
    ```

---

## Security Notes

- Your master password is never saved—**do not forget it!**
- Never share or upload your `salt.key` or `passwords.dat` files.
- All sensitive files are excluded from the repository via `.gitignore`.

---

## Example Usage

Welcome to the Python Password Manager!

What would you like to do?

Add a new password
View stored passwords
Save and Exit
Exit without saving


---

## License

This project is open source and free for personal use and learning.

---

**Author:** [Prashish Sapkota](https://github.com/prashishhh)

