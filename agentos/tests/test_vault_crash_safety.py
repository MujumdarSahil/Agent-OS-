"""Vault incident 2026-11-18 (MOCK): crash-safe writes, fail-closed startup, test-home guard.

Every file here lives in pytest's tmp_path; the real ~/.agentos is never touched (the root conftest
isolates the home and its guard fails the run if the real home changes).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agentos.security.vault import MasterKey, Vault, VaultError, VaultFileError, verify_vault_file
from agentos.storage import atomic
from agentos.storage.file import CorruptStoreError, JsonFileMapRepository
from agentos.storage.models import EncryptedSecretRecord

REPO = Path(__file__).resolve().parents[2]
FAKE_NAME = "fake_canary_provider"
FAKE_SECRET = "fake-canary-secret-0123456789abcdef"


def _repo(path: Path) -> JsonFileMapRepository:
    return JsonFileMapRepository(path, EncryptedSecretRecord, private=True, backup=True)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """A vault, master key and token path inside tmp_path for create_app."""
    monkeypatch.setenv("AGENTOS_VAULT_PATH", str(tmp_path / "home" / "vault.json"))
    monkeypatch.setenv("AGENTOS_MASTER_KEY_FILE", str(tmp_path / "home" / "master.key"))
    monkeypatch.setenv("AGENTOS_API_TOKEN_FILE", str(tmp_path / "home" / "api.token"))
    monkeypatch.delenv("AGENTOS_MASTER_KEY", raising=False)
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-crash-safety")
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return tmp_path / "home", project


# ---------------------------------------------------------------- atomic writes

def test_atomic_write_uses_temp_in_same_folder_fsync_and_os_replace(tmp_path, monkeypatch):
    target = tmp_path / "vault.json"
    calls = {"replace": [], "fsync": 0}
    real_fsync = os.fsync

    def spy_replace(src, dst):
        calls["replace"].append((src, dst))
        os.replace(src, dst)

    def spy_fsync(fd):
        calls["fsync"] += 1
        real_fsync(fd)

    monkeypatch.setattr(atomic, "_replace", spy_replace)
    monkeypatch.setattr(atomic.os, "fsync", spy_fsync)
    atomic.atomic_write_text(target, '{"a": 1}')
    assert target.read_text(encoding="utf-8") == '{"a": 1}'
    (src, dst), = calls["replace"]
    assert Path(src).parent == tmp_path and Path(dst) == target  # temp file in the same folder
    assert calls["fsync"] >= 1
    assert not list(tmp_path.glob(".*.tmp"))  # no temp left behind


def test_failure_before_replace_leaves_the_original_intact(tmp_path, monkeypatch):
    target = tmp_path / "vault.json"
    target.write_text('{"old": true}', encoding="utf-8")

    def boom(src, dst):
        raise OSError("simulated crash before rename")

    monkeypatch.setattr(atomic, "_replace", boom)
    with pytest.raises(OSError):
        atomic.atomic_write_text(target, '{"new": true}')
    assert target.read_text(encoding="utf-8") == '{"old": true}'


def test_process_killed_mid_write_leaves_the_original_intact(tmp_path):
    """A real process is killed (os._exit) after the temp file is written, right before the rename."""
    target = tmp_path / "vault.json"
    original = json.dumps({"keep": "me"}).encode()
    target.write_bytes(original)
    script = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {str(REPO)!r})
        from agentos.storage import atomic
        atomic._replace = lambda src, dst: os._exit(9)   # killed between fsync and rename
        atomic.atomic_write_text({str(target)!r}, '{{"new": "' + 'x' * 200000 + '"}}', backup=True)
    """)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=120)
    assert proc.returncode == 9
    assert target.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="the locked-file retry applies to Windows only")
def test_replace_retries_while_the_file_is_locked(tmp_path, monkeypatch):
    target = tmp_path / "f.json"
    attempts = {"n": 0}

    def flaky(src, dst):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise PermissionError("sharing violation")
        os.replace(src, dst)

    monkeypatch.setattr(atomic, "_replace", flaky)
    monkeypatch.setattr(atomic, "REPLACE_BASE_DELAY_S", 0.001)
    atomic.atomic_write_text(target, "{}")
    assert attempts["n"] == 3 and target.read_text() == "{}"


# ---------------------------------------------------------------- vault file: .bak and fail closed

@pytest.mark.asyncio
async def test_bak_keeps_the_previous_good_version(tmp_path):
    path = tmp_path / "vault.json"
    vault = Vault(_repo(path), MasterKey.generate())
    await vault.put(FAKE_NAME, FAKE_SECRET)
    first = path.read_bytes()
    assert not (tmp_path / "vault.json.bak").exists()  # nothing to back up on the first write
    await vault.put(FAKE_NAME + "_2", FAKE_SECRET)
    bak = tmp_path / "vault.json.bak"
    assert bak.read_bytes() == first
    assert set(json.loads(bak.read_bytes())) == {FAKE_NAME}


@pytest.mark.asyncio
async def test_zero_filled_vault_is_never_overwritten(tmp_path):
    path = tmp_path / "vault.json"
    path.write_bytes(b"\x00" * 11049)
    vault = Vault(_repo(path), MasterKey.generate())
    with pytest.raises(CorruptStoreError) as e:
        await vault.put(FAKE_NAME, FAKE_SECRET)
    assert str(path) in str(e.value) and "vault.json.bak" in str(e.value)
    with pytest.raises(CorruptStoreError):
        await vault.list()
    assert path.read_bytes() == b"\x00" * 11049  # untouched
    assert not (tmp_path / "vault.json.bak").exists()  # a damaged file is never copied over the backup


@pytest.mark.parametrize("content", [b"\x00" * 64, b"", b'{"truncated": ', b"[]"])
def test_verify_vault_file_fails_closed_on_damage(tmp_path, content):
    path = tmp_path / "vault.json"
    path.write_bytes(content)
    with pytest.raises(VaultFileError) as e:
        verify_vault_file(path, MasterKey.generate())
    assert str(path) in str(e.value) and "vault.json.bak" in str(e.value)


@pytest.mark.asyncio
async def test_verify_vault_file_fails_closed_on_wrong_master_key(tmp_path):
    path = tmp_path / "vault.json"
    await Vault(_repo(path), MasterKey.generate()).put(FAKE_NAME, FAKE_SECRET)
    with pytest.raises(VaultFileError) as e:
        verify_vault_file(path, MasterKey.generate())
    assert "different master key" in str(e.value)
    assert FAKE_SECRET not in str(e.value)


def test_missing_vault_file_is_fine(tmp_path):
    assert verify_vault_file(tmp_path / "vault.json", MasterKey.generate()) == 0


def test_zero_filled_vault_refuses_to_start(isolated):
    home, project = isolated
    home.mkdir(parents=True)
    (home / "vault.json").write_bytes(b"\x00" * 11049)
    from agentos_server.app import create_app

    with pytest.raises(RuntimeError) as e:
        create_app(project_path=str(project))
    msg = str(e.value)
    assert "Vault check failed" in msg and str(home / "vault.json") in msg and "vault.json.bak" in msg
    assert (home / "vault.json").read_bytes() == b"\x00" * 11049


@pytest.mark.asyncio
async def test_good_vault_starts(isolated):
    home, project = isolated
    master = MasterKey.load(create=True)  # created in the isolated home
    await Vault(_repo(home / "vault.json"), master).put(FAKE_NAME, FAKE_SECRET)
    from agentos_server.app import create_app

    app = create_app(project_path=str(project))
    assert app.state.vault is not None


def test_zero_filled_master_key_fails_closed(isolated):
    home, project = isolated
    home.mkdir(parents=True)
    (home / "master.key").write_bytes(b"\x00" * 46)
    with pytest.raises(VaultError) as e:
        MasterKey.load(create=True)
    assert str(home / "master.key") in str(e.value)
    assert (home / "master.key").read_bytes() == b"\x00" * 46  # never replaced by a new key
    from agentos_server.app import create_app

    with pytest.raises(RuntimeError, match="Failed to load vault master key"):
        create_app(project_path=str(project))


def test_new_master_key_and_token_are_written_atomically(isolated, monkeypatch):
    home, _ = isolated
    replaced = []
    monkeypatch.setattr(atomic, "_replace", lambda s, d: (replaced.append(Path(d).name), os.replace(s, d)))
    MasterKey.load(create=True)
    monkeypatch.delenv("AGENTOS_API_TOKEN", raising=False)
    from agentos_server.auth import get_or_create_api_token

    token = get_or_create_api_token()
    assert replaced == ["master.key", "api.token"]
    assert (home / "api.token").read_text(encoding="ascii").strip() == token


# ---------------------------------------------------------------- the test-home guard

def test_session_isolation_points_every_path_into_the_temp_home():
    from agentos.security.vault import default_master_key_path
    from agentos.storage.file import default_vault_path
    from agentos_server.auth import default_token_path

    home = Path.home()
    assert home == Path(os.path.expanduser("~"))
    assert "agentos-test-home-" in str(home)  # the temp test home, not the real profile
    for p in (default_vault_path(), default_master_key_path(), default_token_path()):
        assert str(p).startswith(str(home)), p


def _run_guarded(tmp_path: Path, test_body: str) -> subprocess.CompletedProcess:
    fake_real_home = tmp_path / "fake-real-home"
    (fake_real_home / ".agentos").mkdir(parents=True)
    (fake_real_home / ".agentos" / "vault.json").write_text("{}", encoding="utf-8")
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (inner / "test_inner.py").write_text(textwrap.dedent(test_body), encoding="utf-8")
    env = {**os.environ, "AGENTOS_TEST_GUARD_REAL_HOME": str(fake_real_home), "FAKE_REAL_HOME": str(fake_real_home)}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--noconftest", "-p", "conftest", "-p", "no:cacheprovider",
         "-c", str(inner / "pytest.ini"), "--rootdir", str(inner), str(inner / "test_inner.py")],
        cwd=str(REPO), env=env, capture_output=True, text=True, timeout=300,
    )


def test_guard_fails_the_run_when_a_test_writes_to_the_real_home(tmp_path):
    proc = _run_guarded(tmp_path, """
        import os, pathlib
        def test_writes_real_home():
            p = pathlib.Path(os.environ["FAKE_REAL_HOME"]) / ".agentos" / "vault.json"
            p.write_text('{"changed": true}', encoding="utf-8")
    """)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "AGENTOS HOME GUARD" in out and "modified:" in out and "vault.json" in out


def test_guard_passes_when_the_real_home_is_untouched(tmp_path):
    proc = _run_guarded(tmp_path, """
        from pathlib import Path
        def test_writes_temp_home_only():
            (Path.home() / ".agentos").mkdir(parents=True, exist_ok=True)
            (Path.home() / ".agentos" / "vault.json").write_text("{}", encoding="utf-8")
    """)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "AGENTOS HOME GUARD" not in out
