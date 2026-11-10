import os 
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KDF_ITERATIONS = 480_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(data)
    return salt + token

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    salt = blob[:SALT_SIZE]
    token = blob[SALT_SIZE:]

    new_key = derive_key(password, salt)

    try:
        return Fernet(new_key).decrypt(token)
    except InvalidToken:
        raise ValueError("Decryption failed - wrong password or corrupt data")
    
if __name__ == "__main__":
    original = b"This is a secret message."
    password = "MySecurePass123!"

    encrypted = encrypt_bytes(original, password)
    print("Encrypted length:", len(encrypted))

    decrypted = decrypt_bytes(encrypted, password)
    print("Decrypted matches original:", decrypted == original)

    try:
        decrypt_bytes(encrypted, "WrongPassword")
        print("ERROR: should have raised ValueError")
    except ValueError as e:
        print("Correctly rejected wrong password:", e)