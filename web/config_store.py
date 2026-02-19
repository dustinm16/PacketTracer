"""Encrypted configuration storage.

Stores sensitive configuration values (API keys, credentials) using Fernet
symmetric encryption. The encryption key is derived from a master passphrase
via PBKDF2, or auto-generated and stored in a key file.
"""

import base64
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptedConfigStore:
    """Manages encrypted configuration values in SQLite.

    Config values are encrypted with Fernet using a key derived from either:
      - A user-provided passphrase (via PBKDF2)
      - An auto-generated key stored in ~/.packettracer/config.key

    The SQLite table stores: (key TEXT PK, value BLOB, updated_at REAL).
    """

    TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS encrypted_config (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL,
        updated_at REAL NOT NULL
    );
    """

    def __init__(self, db_path: str, passphrase: Optional[str] = None):
        self._db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        self._fernet = self._init_fernet(passphrase)
        self._init_db()

    def _init_fernet(self, passphrase: Optional[str]) -> Fernet:
        """Initialize Fernet cipher from passphrase or key file."""
        if passphrase:
            return self._fernet_from_passphrase(passphrase)
        return self._fernet_from_keyfile()

    def _fernet_from_passphrase(self, passphrase: str) -> Fernet:
        """Derive a Fernet key from a passphrase using PBKDF2."""
        salt_path = Path(self._db_path).parent / "config.salt"
        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = os.urandom(16)
            salt_path.write_bytes(salt)
            os.chmod(str(salt_path), 0o600)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        return Fernet(key)

    def _fernet_from_keyfile(self) -> Fernet:
        """Load or generate a Fernet key from a key file."""
        key_path = Path(self._db_path).parent / "config.key"
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
            os.chmod(str(key_path), 0o600)
        return Fernet(key)

    def _init_db(self) -> None:
        """Create the encrypted_config table if needed."""
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(self.TABLE_SQL)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def set(self, key: str, value: Any) -> None:
        """Encrypt and store a configuration value."""
        plaintext = json.dumps(value).encode()
        ciphertext = self._fernet.encrypt(plaintext)

        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO encrypted_config (key, value, updated_at) "
                "VALUES (?, ?, ?)",
                (key, ciphertext, time.time()),
            )
            conn.commit()

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve and decrypt a configuration value."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM encrypted_config WHERE key = ?", (key,)
            ).fetchone()

        if row is None:
            return default

        try:
            plaintext = self._fernet.decrypt(row[0])
            return json.loads(plaintext.decode())
        except (InvalidToken, json.JSONDecodeError):
            return default

    def delete(self, key: str) -> bool:
        """Delete a configuration value. Returns True if it existed."""
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM encrypted_config WHERE key = ?", (key,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def keys(self) -> list:
        """List all stored configuration keys (unencrypted)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT key FROM encrypted_config ORDER BY key"
            ).fetchall()
        return [r[0] for r in rows]

    def get_all(self) -> Dict[str, Any]:
        """Retrieve all config values (decrypted)."""
        result = {}
        for key in self.keys():
            val = self.get(key)
            if val is not None:
                result[key] = val
        return result

    def has(self, key: str) -> bool:
        """Check if a key exists."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM encrypted_config WHERE key = ?", (key,)
            ).fetchone()
        return row is not None
