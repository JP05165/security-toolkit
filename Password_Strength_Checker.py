import re
import math
import os
import string
import secrets

script_dir = os.path.dirname(__file__)
file_path = os.path.join(script_dir, "common_passwords.txt")
with open(file_path) as f:
    COMMON_PASSWORDS = {line.strip().lower() for line in f}



def calculate_entropy(password: str ) -> float:
    if len(password) == 0:
        return 0.000
    pool = 0
    capital = bool(re.search(r"[A-Z]", password))
    lowercase = bool(re.search(r"[a-z]", password))
    digits = bool(re.search(r"[0-9]", password))
    symbols = bool(re.search(r"[^a-zA-Z0-9]", password))
    if capital:
        pool += 26
    if lowercase:
        pool += 26
    if digits:
        pool+= 10
    if symbols:
        pool+= 32
    
    return len(password) * math.log2(pool)

def check_strength(password: str) -> dict:
    strength_status = 0
    if len(password) >= 12:
        strength_status += 2
    elif len(password) >= 8:
        strength_status += 1
    else:
        strength_status = 0

    has_repeat = bool(re.search(r"(.)\1{2,}", password))
    if has_repeat:
        strength_status = max(0, strength_status -1)
    has_bad_seq = bool(re.search(r"(?i)(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|qwe|wer|ert|rty|tyu|yui|uio|iop)", password))
    if has_bad_seq:
       strength_status = max(0, strength_status -1)
       
    capital = bool(re.search(r"[A-Z]", password))
    lowercase = bool(re.search(r"[a-z]", password))
    digits = bool(re.search(r"[0-9]", password))
    symbols = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety_count = sum([capital, lowercase, digits, symbols])

    if variety_count == 4:
        strength_status += 3
    elif variety_count >= 3:
        strength_status += 2
    elif variety_count >= 2:
        strength_status += 1

    is_common = password.lower() in COMMON_PASSWORDS

    if is_common:
        strength_status = 0

    entropy_bits = calculate_entropy(password)
    
    if strength_status <= 1:
        label = "Weak"
    elif strength_status <= 3:
        label = "Fair"
    else:
        label = "Strong"

    feedback = []
    if len(password) < 8:
        feedback.append("Use at least 8 characters")
    if has_repeat:
        feedback.append("Avoid using the same character more than 3 times in a row")
    if has_bad_seq:
        feedback.append("Avoid sequential patterns (e.g. abcd, 1234, qwe)")
    if is_common:
        feedback.append("This password is too common - for safety reasons choose something less predictable")

    return {
        "score": strength_status,
        "label": label,
        "entropy_bits": round(entropy_bits, 1),
        "feedback": feedback,
    }

def generate_password(length: int = 12, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(string.punctuation)

    password_chars = []
    for c in pools:
        password_chars.append(secrets.choice(c))

    all_chars = "".join(pools)
    remaining = length - len(password_chars)
    
    for _ in range(remaining):
        password_chars.append(secrets.choice(all_chars))

    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    
    password = "".join(password_chars)

    return password



if __name__ == "__main__":
    
    password = "'H28G@%6Cm"
    print(check_strength(password))


    
