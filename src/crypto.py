"""Encrypt/decrypt small secrets stored in per-asset config (e.g. SMB
file-share password for the smb_scan add-on).

AES-256-GCM with a per-message random salt+nonce and PBKDF2-HMAC-SHA256
(310k) — same scheme as the asset/access modules. The key comes only from
ENCRYPTION_KEY (no insecure default): encryption fails closed if missing.
"""
from __future__ import annotations

import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_KEY: bytes | None = None
_SALT_LEN = 16
_NONCE_LEN = 12
_KDF_ITERATIONS = 310_000
_MIN_KEY_LEN = 32


def _get_key() -> bytes:
    global _KEY
    if _KEY is None:
        raw = os.environ.get("ENCRYPTION_KEY", "")
        if not raw:
            raise RuntimeError(
                "ENCRYPTION_KEY must be set to store secrets. Generate one with: "
                "python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(raw) < _MIN_KEY_LEN:
            raise RuntimeError(f"ENCRYPTION_KEY too short ({len(raw)} chars): minimum {_MIN_KEY_LEN}.")
        _KEY = raw.encode()
    return _KEY


def _derive(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_KDF_ITERATIONS)
    return kdf.derive(passphrase)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    salt = os.urandom(_SALT_LEN)
    key = _derive(_get_key(), salt)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return b64encode(salt + nonce + ct).decode()


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        raw = b64decode(ciphertext)
        salt = raw[:_SALT_LEN]
        nonce = raw[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
        ct = raw[_SALT_LEN + _NONCE_LEN:]
        key = _derive(_get_key(), salt)
        return AESGCM(key).decrypt(nonce, ct, None).decode()
    except Exception:
        return ""
