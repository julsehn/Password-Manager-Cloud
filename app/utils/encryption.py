"""Encryption utilities - ported from python-password-manager src/encryption.py and src/storage.py"""
import os
import json
import base64
from typing import List
from datetime import datetime, timezone
import uuid
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Minimum iterations per OWASP 2023 guidelines
DEFAULT_ITERATIONS = 600_000


@dataclass
class PasswordEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    site: str = field(default="")
    username: str = field(default="")
    password: str = field(default="", repr=False, compare=False)
    notes: str = field(default="")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "site": self.site,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "PasswordEntry":
        e = PasswordEntry()
        e.id = d.get("id", e.id)
        e.site = str(d.get("site", "")) if d.get("site") else ""
        e.username = str(d.get("username", "")) if d.get("username") else ""
        e.password = str(d.get("password", "")) if d.get("password") else ""
        e.notes = str(d.get("notes", "")) if d.get("notes") else ""
        e.created_at = str(d.get("created_at", e.created_at)) if d.get("created_at") else e.created_at
        e.updated_at = str(d.get("updated_at", e.updated_at)) if d.get("updated_at") else e.updated_at
        return e


def derive_key(password: str, salt: bytes | None = None, iterations: int = DEFAULT_ITERATIONS) -> tuple[bytes, bytes]:
    """Derive a 32-byte key from password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt ciphertext with AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def serialize_vault(entries: List[PasswordEntry], master_password: str) -> str:
    """Serialize vault entries to encrypted JSON blob."""
    data = {"entries": [e.to_dict() for e in entries]}
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")

    key, salt = derive_key(master_password)
    nonce, ciphertext = encrypt(plaintext, key)

    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "version": "1",
    }

    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def deserialize_vault(blob: str, master_password: str) -> List[PasswordEntry]:
    """Deserialize and decrypt vault blob to entries list."""
    payload = json.loads(blob)
    salt = base64.b64decode(payload["salt"], validate=True)
    nonce = base64.b64decode(payload["nonce"], validate=True)
    ciphertext = base64.b64decode(payload["ciphertext"], validate=True)

    key, _ = derive_key(master_password, salt=salt)
    data = json.loads(decrypt(nonce, ciphertext, key).decode("utf-8"))

    entries = data.get("entries", []) if isinstance(data, dict) else []
    return [PasswordEntry.from_dict(d) for d in entries if isinstance(d, dict)]
