import hashlib
import os
import base64
import json

class AuthManager:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.users = self._load_users()

    def _load_users(self) -> dict:
        if not os.path.exists(self.filepath):
            return {}
        with open(self.filepath, "r") as f:
            return json.load(f)
        
    def _save_users(self):
        with open(self.filepath, "w") as f:
            json.dump(self.users, f, indent=2)
    
    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        if username in self.users:
            return False, "Username already exists"
        
        salt = os.urandom(16)
        hashed = hash_password(password, salt)

        self.users[username] = {"salt": base64.b64encode(salt).decode("utf-8"), "hash": base64.b64encode(hashed).decode("utf-8")}
        self._save_users()
        return True, "Account created"

    def login_user(self, username: str, password: str) -> tuple[bool, str]:
        if username not in self.users:
            return False, "Invalid username or password"
        stored = self.users[username]
        stored_salt = base64.b64decode(stored["salt"])
        stored_hash = base64.b64decode(stored["hash"])
        
        new_hash = hash_password(password, stored_salt)

        if stored_hash == new_hash:
            return True, "Login successful"
        else:
            return False, "Invalid username or password"

def hash_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 100000)

if __name__ == "__main__":
   manager = AuthManager("users.json")

   print(manager.register_user("jeel", "MySecurePass123!"))
   print(manager.login_user("jeel", "MySecurePass123!"))
   print(manager.login_user("jeel", "WrongPassword"))
   print(manager.register_user("jeel", "AnotherPass456!"))
   
   