# Security Toolkit

Three Python modules covering password security, authentication, and encryption: a password strength checker and generator, a salted-hash login system, and a password-based encryption engine.

<!-- Add a sentence or two in your own words: why you built this. -->

## What's inside

| File | What it does |
|---|---|
| `Password_Strength_Checker.py` | Scores a password by estimated entropy, length, and character variety; flags repeated characters and common sequences; rejects anything on a 10,000-entry common-password list. Also generates random passwords using Python's `secrets` module, guaranteeing at least one character from each selected type and then shuffling. |
| `Login_System.py` | `AuthManager` class that registers and logs in users. Passwords are salted and hashed with PBKDF2-HMAC-SHA256 (100,000 iterations) and stored in a local JSON file. Wrong usernames and wrong passwords return the same generic error. |
| `Crypto_utils.py` | Encrypts and decrypts bytes with a password. A key is derived with PBKDF2 (480,000 iterations, fresh 16-byte random salt each time) and used with Fernet. The salt is stored at the front of the output so decryption can re-derive the same key. A wrong password raises a clean `ValueError`. |
| `common_passwords.txt` | The 10,000 most common passwords, used by the strength checker. |

## How to run

Requires Python 3.

```bash
git clone https://github.com/JP05165/security-toolkit.git
cd security-toolkit
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Each module has a built-in demo:

```bash
python3 Password_Strength_Checker.py   # scores a sample password
python3 Login_System.py                # registers a user, then tests correct and wrong logins
python3 Crypto_utils.py                # encrypts, decrypts, and checks that a wrong password fails
```

`Login_System.py` creates a `users.json` file when it runs. It's excluded from the repo by `.gitignore`.

## Concepts used

- **Hashing vs. encryption:** passwords are hashed (one-way, only verifiable), while data is encrypted (reversible with the right key).
- **Salting:** every hash and every encryption uses a new random salt, so identical inputs never produce identical output.
- **Key derivation:** PBKDF2 turns a human password into a 32-byte key, and the high iteration count slows down brute-force attacks.
- **Cryptographically secure randomness:** `secrets` instead of `random` for anything security-related.
