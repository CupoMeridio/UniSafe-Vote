import hashlib
import os

def hash_password(password: str) -> str:
    """
    Hash a password for storing.
    Uses PBKDF2 with SHA-256 and a random salt.
    """
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ":" + pwdhash.hex()

def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Verify a stored password against one provided by the user.
    """
    try:
        salt_hex, pwdhash_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        expected_pwdhash = bytes.fromhex(pwdhash_hex)
        pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return pwdhash == expected_pwdhash
    except ValueError:
        return False
