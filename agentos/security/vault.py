"""
Credentials vault: AES-256-GCM envelope encryption (sub-milestone 1.3).

  secret  --AES-256-GCM(data key, nonce, aad)-->  ciphertext
  data key (random per secret) --AES-256-GCM(master key)-->  wrapped_dek

The associated data binds every ciphertext to its entry name, so copying one
entry's ciphertext onto another name fails the integrity check.

The master key (key-encryption key) never lives in the store that holds the
secrets. It comes from ``AGENTOS_MASTER_KEY`` (base64, 32 bytes) or a key file,
default ``~/.agentos/master.key``, created with mode 0600 on first use.

``Vault.list()`` / ``Vault.put()`` return masked metadata only. ``Vault.reveal()``
returns plaintext for in-process use (for example handing a key to LiteLLM); API
layers must never return its result.
"""

import base64
import binascii
import hashlib
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentos.storage.atomic import atomic_write_text
from agentos.storage.models import EncryptedSecretRecord, entity_key, utcnow
from agentos.storage.ports import NamedRepository

KEY_BYTES = 32
NONCE_BYTES = 12
_AAD_PREFIX = b"agentos-vault:v1:"


class VaultError(Exception):
    """Base class for vault failures."""


class VaultKeyMismatch(VaultError):
    """The entry was encrypted under a different master key."""


class VaultIntegrityError(VaultError):
    """Ciphertext or wrapped key was modified, or bound to another entry."""


class SecretNotFound(VaultError, KeyError):
    pass


class VaultFileError(VaultError):
    """The Standalone vault file exists but cannot be read or decrypted with the current master key."""


def default_master_key_path() -> Path:
    return Path(os.environ.get("AGENTOS_MASTER_KEY_FILE") or Path.home() / ".agentos" / "master.key")


@dataclass(frozen=True)
class MasterKey:
    key: bytes

    def __post_init__(self):
        if len(self.key) != KEY_BYTES:
            raise ValueError(f"master key must be {KEY_BYTES} bytes, got {len(self.key)}")

    @property
    def key_id(self) -> str:
        return "kek-" + hashlib.sha256(self.key).hexdigest()[:16]

    def __repr__(self) -> str:  # never print key material
        return f"MasterKey(key_id={self.key_id!r})"

    @classmethod
    def generate(cls) -> "MasterKey":
        return cls(AESGCM.generate_key(bit_length=256))

    @classmethod
    def from_b64(cls, value: str) -> "MasterKey":
        try:
            raw = base64.b64decode(value.strip(), altchars=b"-_", validate=False)
        except (binascii.Error, ValueError) as e:
            raise ValueError("master key is not valid base64") from e
        return cls(raw)

    def to_b64(self) -> str:
        return base64.b64encode(self.key).decode("ascii")

    @classmethod
    def load(cls, path: Optional[Path] = None, create: bool = True) -> "MasterKey":
        """``AGENTOS_MASTER_KEY`` wins; otherwise read (or create) the key file."""
        env = os.environ.get("AGENTOS_MASTER_KEY")
        if env:
            return cls.from_b64(env)
        path = Path(path) if path else default_master_key_path()
        if path.exists():
            try:
                return cls.from_b64(path.read_text(encoding="ascii"))
            except (ValueError, UnicodeDecodeError) as e:
                # Fail closed: never generate a new key over an existing (damaged) key file.
                raise VaultError(
                    f"master key file {path} exists but is not a valid 32-byte base64 key "
                    f"(it may be truncated or zero-filled). AgentOS will not replace it."
                ) from e
        if not create:
            raise VaultError(f"no master key: set AGENTOS_MASTER_KEY or create {path}")
        key = cls.generate()
        if path.exists():  # created by another process meanwhile: use it, never overwrite
            return cls.load(path, create=False)
        atomic_write_text(path, key.to_b64() + "\n", private=True, encoding="ascii")
        return key


@dataclass(frozen=True)
class SecretInfo:
    """What the vault exposes about a secret: never the value or ciphertext."""
    name: str
    provider: Optional[str]
    hint: str
    key_id: str
    created_at: datetime
    updated_at: datetime


def mask(secret: str) -> str:
    """Display hint: first 3 and last 4 characters for long keys, nothing for short ones."""
    if len(secret) < 16:
        return "****"
    return f"{secret[:3]}...{secret[-4:]}"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value)


def _aad(name: str) -> bytes:
    return _AAD_PREFIX + entity_key(name).encode("utf-8")


def encrypt_secret(master: MasterKey, name: str, secret: str, provider: Optional[str] = None) -> EncryptedSecretRecord:
    aad = _aad(name)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, secret.encode("utf-8"), aad)
    wrap_nonce = os.urandom(NONCE_BYTES)
    wrapped = wrap_nonce + AESGCM(master.key).encrypt(wrap_nonce, dek, aad)
    return EncryptedSecretRecord(
        name=name, provider=provider, key_id=master.key_id,
        wrapped_dek=_b64(wrapped), nonce=_b64(nonce), ciphertext=_b64(ciphertext), hint=mask(secret),
    )


def decrypt_secret(master: MasterKey, record: EncryptedSecretRecord) -> str:
    if record.key_id != master.key_id:
        raise VaultKeyMismatch(
            f"secret '{record.name}' was encrypted with {record.key_id}, current master key is {master.key_id}"
        )
    aad = _aad(record.name)
    try:
        wrapped = _unb64(record.wrapped_dek)
        dek = AESGCM(master.key).decrypt(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], aad)
        return AESGCM(dek).decrypt(_unb64(record.nonce), _unb64(record.ciphertext), aad).decode("utf-8")
    except (InvalidTag, ValueError, binascii.Error) as e:
        raise VaultIntegrityError(f"secret '{record.name}' failed integrity check") from e


def _info(record: EncryptedSecretRecord) -> SecretInfo:
    return SecretInfo(record.name, record.provider, record.hint, record.key_id, record.created_at, record.updated_at)


def verify_vault_file(path: Path, master: MasterKey) -> int:
    """Startup check for the Standalone vault file; returns the number of entries.

    Fails closed (VaultFileError) when the file exists but is not a JSON object (empty, zero-filled,
    truncated) or any entry does not decrypt with ``master`` (wrong key, tampered). Decrypted values
    are discarded immediately and never logged. A missing file is fine (a new vault starts empty).
    Messages name the file and the backup, never entry contents.
    """
    import json

    path = Path(path)
    if not path.exists():
        return 0
    bak = path.with_name(path.name + ".bak")
    hint = f"A previous good copy may exist at {bak}. AgentOS will not overwrite {path}; restore it or move it aside."
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("top level is not a JSON object")
    except (ValueError, UnicodeDecodeError) as e:
        raise VaultFileError(f"vault file {path} cannot be parsed ({len(raw)} bytes; it may be truncated or zero-filled). {hint}") from e
    for value in data.values():
        try:
            decrypt_secret(master, EncryptedSecretRecord.model_validate(value))
        except VaultKeyMismatch as e:
            raise VaultFileError(f"vault file {path} was encrypted with a different master key than {master.key_id}. {hint}") from e
        except (VaultIntegrityError, ValueError) as e:
            raise VaultFileError(f"vault file {path} has an entry that fails its integrity check. {hint}") from e
    return len(data)


class Vault:
    """Encrypts on the way into a credentials repository and decrypts on the way out."""

    def __init__(self, repository: NamedRepository[EncryptedSecretRecord], master_key: MasterKey):
        self._repo = repository
        self._master = master_key

    @property
    def key_id(self) -> str:
        return self._master.key_id

    async def put(self, name: str, secret: str, provider: Optional[str] = None) -> SecretInfo:
        if not secret:
            raise ValueError("secret must not be empty")
        record = encrypt_secret(self._master, name, secret, provider)
        existing = await self._repo.get(name)
        if existing is not None:
            record = record.model_copy(update={"created_at": existing.created_at, "updated_at": utcnow()})
        await self._repo.put(record)
        return _info(record)

    async def reveal(self, name: str) -> str:
        record = await self._repo.get(name)
        if record is None:
            raise SecretNotFound(name)
        return decrypt_secret(self._master, record)

    async def list(self) -> List[SecretInfo]:
        return [_info(r) for r in await self._repo.list()]

    async def get_info(self, name: str) -> Optional[SecretInfo]:
        record = await self._repo.get(name)
        return _info(record) if record else None

    async def delete(self, name: str) -> bool:
        return await self._repo.delete(name)
