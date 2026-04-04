"""AES-256-GCM encryption/decryption for firewall secrets.

The ENCRYPTION_KEY env var is a 64-char hex string (32 bytes).
Encrypted values are stored as base64(nonce + tag + ciphertext).
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import ENCRYPTION_KEY


def _key_bytes() -> bytes:
    key = bytes.fromhex(ENCRYPTION_KEY)
    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY must be 64 hex characters (32 bytes).")
    return key


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext string; return a base64-encoded blob."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(_key_bytes())
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    # ciphertext includes the 16-byte GCM auth tag appended by cryptography
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode()


def decrypt_secret(blob: str) -> str:
    """Decrypt a base64-encoded blob; return the plaintext string."""
    raw = base64.b64decode(blob)
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(_key_bytes())
    return aesgcm.decrypt(nonce, ciphertext, None).decode()
