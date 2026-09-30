"""Password hashing + constant-time verification for the /authorize login page.

``OAUTH_LOGIN_PASSWORD`` accepts either plain text or a scrypt hash in the
format ``scrypt$<salt_b64>$<hash_b64>`` (standard base64, with padding). The
KDF parameters are fixed to Node's ``crypto.scryptSync`` defaults
(``N=16384, r=8, p=1``) so hashes are interchangeable with the NN Engine
backend; the derived-key length is taken from the stored hash, so both the
32-byte keys produced here and longer keys produced elsewhere verify.

Generate a hash with ``python -m nn_mcp_auth.hash_password``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from typing import Final

SCRYPT_PREFIX: Final[str] = "scrypt"
SCRYPT_N: Final[int] = 2**14
SCRYPT_R: Final[int] = 8
SCRYPT_P: Final[int] = 1
SCRYPT_SALT_BYTES: Final[int] = 16
SCRYPT_KEY_BYTES: Final[int] = 32
_MIN_KEY_BYTES: Final[int] = 16
_MAX_KEY_BYTES: Final[int] = 128
# 128 * r * N = 16 MiB for the defaults; leave headroom above OpenSSL's 32 MiB cap.
_SCRYPT_MAXMEM: Final[int] = 64 * 1024 * 1024


def _scrypt(password: str, salt: bytes, key_bytes: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM,
        dklen=key_bytes,
    )


def is_scrypt_hash(stored: str) -> bool:
    """Return ``True`` when ``stored`` looks like ``scrypt$...`` (well-formed or not)."""

    return stored.startswith(f"{SCRYPT_PREFIX}$")


def parse_scrypt_hash(stored: str) -> tuple[bytes, bytes] | None:
    """Decode ``scrypt$<salt_b64>$<hash_b64>`` into ``(salt, key)``.

    Returns ``None`` for anything malformed (wrong segment count, invalid
    base64, empty salt, key length outside 16-128 bytes).
    """

    parts = stored.split("$")
    if len(parts) != 3 or parts[0] != SCRYPT_PREFIX:
        return None
    try:
        salt = base64.b64decode(parts[1], validate=True)
        key = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        return None
    if not salt or not _MIN_KEY_BYTES <= len(key) <= _MAX_KEY_BYTES:
        return None
    return salt, key


def hash_login_password(password: str, *, salt: bytes | None = None) -> str:
    """Return ``scrypt$<salt_b64>$<hash_b64>`` for ``password``."""

    if not password:
        raise ValueError("password must not be empty")
    salt_bytes = salt if salt is not None else secrets.token_bytes(SCRYPT_SALT_BYTES)
    key = _scrypt(password, salt_bytes, SCRYPT_KEY_BYTES)
    salt_b64 = base64.b64encode(salt_bytes).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"{SCRYPT_PREFIX}${salt_b64}${key_b64}"


def verify_login_password(provided: str, stored: str) -> bool:
    """Compare ``provided`` with ``stored`` (plain text or scrypt hash) in constant time."""

    if not stored:
        return False
    if is_scrypt_hash(stored):
        parsed = parse_scrypt_hash(stored)
        if parsed is None:
            return False
        salt, expected = parsed
        derived = _scrypt(provided, salt, len(expected))
        return hmac.compare_digest(derived, expected)
    return hmac.compare_digest(provided.encode("utf-8"), stored.encode("utf-8"))


def login_credentials_match(
    provided_username: str,
    provided_password: str,
    *,
    username: str,
    password: str,
) -> bool:
    """Check both fields without short-circuiting, so timing never reveals which one failed."""

    if not username or not password:
        return False
    username_ok = hmac.compare_digest(provided_username.encode("utf-8"), username.encode("utf-8"))
    password_ok = verify_login_password(provided_password, password)
    return username_ok and password_ok
