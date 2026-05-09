"""
crypto_utils.py — AES-256 Encryption/Decryption Utility
Secure Device Data Monitoring System
"""

import os
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# ─── Shared Secret Key (in production: exchange via RSA or DH) ───────────────
SECRET_PASSPHRASE = b"SecureMonitor2024_BIT_CSE_ICB!!!"  # 32 bytes = AES-256
AES_KEY = hashlib.sha256(SECRET_PASSPHRASE).digest()     # deterministic 256-bit key

BLOCK_SIZE = 16  # AES block size in bytes


def encrypt_data(plaintext: dict) -> bytes:
    """
    Encrypt a Python dict → AES-256 CBC encrypted bytes.
    IV is randomly generated per message and prepended to ciphertext.
    """
    raw = json.dumps(plaintext).encode("utf-8")
    iv = os.urandom(BLOCK_SIZE)                          # fresh IV every message
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(raw, BLOCK_SIZE))
    # Format: [16-byte IV] + [ciphertext], then base64 encode for socket safety
    return base64.b64encode(iv + ciphertext)


def decrypt_data(encrypted_bytes: bytes) -> dict:
    """
    Decrypt AES-256 CBC encrypted bytes → Python dict.
    Extracts IV from the first 16 bytes of the decoded payload.
    """
    raw = base64.b64decode(encrypted_bytes)
    iv = raw[:BLOCK_SIZE]
    ciphertext = raw[BLOCK_SIZE:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    return json.loads(plaintext.decode("utf-8"))


def get_key_fingerprint() -> str:
    """Return a short fingerprint of the AES key for verification display."""
    return hashlib.sha256(AES_KEY).hexdigest()[:16].upper()
