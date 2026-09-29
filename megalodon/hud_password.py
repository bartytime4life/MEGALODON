"""Closed, local-only verifier for an optional operator-chosen HUD password."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from threading import BoundedSemaphore


SCHEMA = "megalodon-hud-password-v1"
MIN_LENGTH = 8
MAX_LENGTH = 64
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
_VERIFY_SLOTS = BoundedSemaphore(4)


def _password_bytes(value: str) -> bytes:
    if type(value) is not str or not MIN_LENGTH <= len(value) <= MAX_LENGTH:
        raise ValueError("HUD password must contain 8 to 64 printable ASCII characters")
    if any(not 32 <= ord(char) <= 126 for char in value):
        raise ValueError("HUD password must contain 8 to 64 printable ASCII characters")
    return value.encode("ascii")


def _derive(value: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(value, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)


@dataclass(frozen=True)
class PasswordVerifier:
    salt: bytes
    digest: bytes

    @classmethod
    def from_password(cls, password: str) -> PasswordVerifier:
        value = _password_bytes(password)
        salt = secrets.token_bytes(16)
        return cls(salt, _derive(value, salt))

    @classmethod
    def from_record(cls, record: object) -> PasswordVerifier:
        if not isinstance(record, dict) or set(record) != {"schema", "salt", "digest"} or record["schema"] != SCHEMA:
            raise ValueError("HUD password record has an unsupported shape")
        salt_hex, digest_hex = record["salt"], record["digest"]
        if (
            type(salt_hex) is not str or type(digest_hex) is not str
            or len(salt_hex) != 32 or len(digest_hex) != 64
            or any(char not in "0123456789abcdef" for char in salt_hex + digest_hex)
        ):
            raise ValueError("HUD password record has invalid verifier bytes")
        return cls(bytes.fromhex(salt_hex), bytes.fromhex(digest_hex))

    def record(self) -> dict[str, str]:
        return {"schema": SCHEMA, "salt": self.salt.hex(), "digest": self.digest.hex()}

    def verify(self, supplied: bytes) -> bool:
        if not isinstance(supplied, bytes) or not MIN_LENGTH <= len(supplied) <= MAX_LENGTH:
            return False
        if any(not 32 <= char <= 126 for char in supplied):
            return False
        if not _VERIFY_SLOTS.acquire(timeout=2):
            return False
        try:
            return hmac.compare_digest(_derive(supplied, self.salt), self.digest)
        finally:
            _VERIFY_SLOTS.release()
