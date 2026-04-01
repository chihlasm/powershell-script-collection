"""
Credential encryption and master password management.
Uses Fernet symmetric encryption (AES-128-CBC) from the cryptography library.
"""

import base64
import hashlib
import os

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Module-level session key (held in memory only, never written to disk)
_fernet_key = None
_fernet = None


def is_unlocked():
    """Check if the session is unlocked (master password has been provided)."""
    return _fernet is not None


def _derive_fernet_key(password, salt):
    """Derive a Fernet key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key


def hash_master_password(password):
    """Hash the master password for storage. Returns 'salt_hex:hash_hex'."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 480000)
    return salt.hex() + ":" + key.hex()


def verify_master_password(password, stored_hash):
    """Verify a password against a stored hash."""
    try:
        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 480000)
        return actual == expected
    except Exception:
        return False


def unlock(password, salt_hex):
    """Unlock the session by deriving the Fernet key from the master password."""
    global _fernet_key, _fernet
    salt = bytes.fromhex(salt_hex)
    _fernet_key = _derive_fernet_key(password, salt)
    _fernet = Fernet(_fernet_key)


def lock():
    """Lock the session by clearing the Fernet key from memory."""
    global _fernet_key, _fernet
    _fernet_key = None
    _fernet = None


def encrypt_password(plaintext):
    """Encrypt a password. Session must be unlocked."""
    if not _fernet:
        raise RuntimeError("Session is locked. Unlock with master password first.")
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_password(token):
    """Decrypt a password. Session must be unlocked."""
    if not _fernet:
        raise RuntimeError("Session is locked. Unlock with master password first.")
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise RuntimeError("Failed to decrypt. Wrong master password or corrupted data.")
