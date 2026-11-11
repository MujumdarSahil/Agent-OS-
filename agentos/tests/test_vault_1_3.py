"""
test_vault_1_3.py - Credentials vault: AES-256-GCM envelope encryption (sub-milestone 1.3).

All tests [MOCK] (local files, no network) except the Mongo parametrization of
test_vault_roundtrip_on_backend, which is [LIVE] and skips without AGENTOS_MONGO_URI.
"""

import base64
import os
import uuid

import pytest
import pytest_asyncio

from agentos.security.vault import (
    MasterKey,
    SecretNotFound,
    Vault,
    VaultError,
    VaultIntegrityError,
    VaultKeyMismatch,
    decrypt_secret,
    encrypt_secret,
    mask,
)
from agentos.storage import open_storage
from agentos.storage.file import JsonFileMapRepository
from agentos.storage.models import EncryptedSecretRecord

SECRET = "sk-test-0123456789abcdefFAKEKEY"


@pytest.fixture
def master():
    return MasterKey.generate()


@pytest.fixture
def repo(tmp_path):
    return JsonFileMapRepository(tmp_path / "vault.json", EncryptedSecretRecord, private=True)


@pytest.fixture
def vault(repo, master):
    return Vault(repo, master)


def _flip_last_byte(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


@pytest.mark.asyncio
async def test_put_and_reveal_roundtrip(vault):
    info = await vault.put("openai", SECRET, provider="openai")
    assert info.hint == "sk-...EKEY"
    assert await vault.reveal("openai") == SECRET
    assert await vault.reveal("OpenAI") == SECRET  # same slug rules as every repository


@pytest.mark.asyncio
async def test_no_plaintext_in_store_listing_or_info(vault, tmp_path):
    info = await vault.put("openai", SECRET)
    stored = (tmp_path / "vault.json").read_text(encoding="utf-8")
    listed = await vault.list()
    assert SECRET not in stored
    assert SECRET not in repr(info) and SECRET not in repr(listed)
    assert not hasattr(info, "ciphertext")


@pytest.mark.asyncio
async def test_each_encryption_uses_fresh_key_and_nonce(master):
    a = encrypt_secret(master, "x", SECRET)
    b = encrypt_secret(master, "x", SECRET)
    assert a.ciphertext != b.ciphertext and a.nonce != b.nonce and a.wrapped_dek != b.wrapped_dek
    assert len(base64.b64decode(a.wrapped_dek)) == 12 + 32 + 16  # nonce + data key + GCM tag


@pytest.mark.parametrize("field", ["ciphertext", "wrapped_dek", "nonce"])
def test_tampering_is_detected(master, field):
    record = encrypt_secret(master, "openai", SECRET)
    tampered = record.model_copy(update={field: _flip_last_byte(getattr(record, field))})
    with pytest.raises(VaultIntegrityError):
        decrypt_secret(master, tampered)


def test_ciphertext_is_bound_to_its_entry_name(master):
    record = encrypt_secret(master, "openai", SECRET)
    moved = record.model_copy(update={"name": "anthropic"})
    with pytest.raises(VaultIntegrityError):
        decrypt_secret(master, moved)


def test_wrong_master_key_is_rejected(master):
    record = encrypt_secret(master, "openai", SECRET)
    other = MasterKey.generate()
    with pytest.raises(VaultKeyMismatch):
        decrypt_secret(other, record)
    # Even with a forged key_id the wrapped data key cannot be opened.
    with pytest.raises(VaultIntegrityError):
        decrypt_secret(other, record.model_copy(update={"key_id": other.key_id}))


@pytest.mark.asyncio
async def test_update_keeps_created_at_and_replaces_value(vault):
    first = await vault.put("groq", SECRET)
    second = await vault.put("groq", SECRET + "-rotated")
    assert second.created_at == first.created_at
    assert second.updated_at >= first.updated_at
    assert await vault.reveal("groq") == SECRET + "-rotated"


@pytest.mark.asyncio
async def test_missing_empty_and_delete(vault):
    with pytest.raises(SecretNotFound):
        await vault.reveal("nope")
    with pytest.raises(ValueError):
        await vault.put("empty", "")
    await vault.put("gone", SECRET)
    assert await vault.delete("gone") is True
    assert await vault.get_info("gone") is None


def test_mask_hides_short_secrets():
    assert mask("short") == "****"
    assert mask("abcdefghijklmnop") == "abc...mnop"


# ---------------------------------------------------------------------------
# Master key handling
# ---------------------------------------------------------------------------

def test_master_key_file_created_once_and_reused(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTOS_MASTER_KEY", raising=False)
    path = tmp_path / "keys" / "master.key"
    first = MasterKey.load(path)
    assert path.exists()
    assert MasterKey.load(path) == first
    if os.name != "nt":  # POSIX permission bits; Windows ACLs are not mode-based
        assert path.stat().st_mode & 0o777 == 0o600


def test_master_key_env_wins_over_file(tmp_path, monkeypatch):
    env_key = MasterKey.generate()
    monkeypatch.setenv("AGENTOS_MASTER_KEY", env_key.to_b64())
    assert MasterKey.load(tmp_path / "unused.key") == env_key
    assert not (tmp_path / "unused.key").exists()


def test_master_key_validation_and_repr(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTOS_MASTER_KEY", raising=False)
    with pytest.raises(ValueError):
        MasterKey(b"too short")
    with pytest.raises(VaultError):
        MasterKey.load(tmp_path / "absent.key", create=False)
    key = MasterKey.generate()
    assert key.to_b64() not in repr(key) and key.key_id in repr(key)


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(params=["file", "mongo"])
async def backend_storage(request, tmp_path):
    if request.param == "file":
        yield await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
        return
    uri = os.environ.get("AGENTOS_MONGO_URI")
    if not uri:
        if os.environ.get("AGENTOS_REQUIRE_LIVE_MONGO") == "1":
            pytest.fail("AGENTOS_MONGO_URI not set")
        pytest.skip("LIVE Mongo not available: set AGENTOS_MONGO_URI (see docker/compose.mongo.yml)")
    db_name = f"agentos_test_{uuid.uuid4().hex[:12]}"
    s = await open_storage(backend="mongo", mongo_uri=uri, db_name=db_name)
    yield s
    await s.close()
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(uri)
    await client.drop_database(db_name)
    await client.close()


@pytest.mark.asyncio
async def test_vault_roundtrip_on_backend(backend_storage, master):
    vault = Vault(backend_storage.credentials, master)
    await vault.put("anthropic", SECRET, provider="anthropic")
    assert await vault.reveal("anthropic") == SECRET
    raw = await backend_storage.credentials.get("anthropic")
    assert SECRET not in raw.model_dump_json()
