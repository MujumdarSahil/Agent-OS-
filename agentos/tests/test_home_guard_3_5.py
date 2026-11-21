"""3.5 Part 0a: real-home guard (MOCK; no network, no model).

The "real home" here is always a FAKE home in tmp_path (AGENTOS_GUARD_REAL_HOME); nothing in the user's real
~/.agentos is opened, listed or read.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentos.core import home_guard
from agentos.core.home_guard import RealHomeForbidden, check_path, is_in_real_home


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "fake-real-home"
    (home / ".agentos").mkdir(parents=True)
    monkeypatch.setenv("AGENTOS_GUARD_REAL_HOME", str(home))
    monkeypatch.setenv("AGENTOS_FORBID_REAL_HOME", "1")
    return home


def test_conftest_turns_the_guard_on_for_the_session():
    assert os.environ.get("AGENTOS_FORBID_REAL_HOME") == "1"


def test_real_home_does_not_come_from_home_env(monkeypatch):
    """The conftest moved HOME/USERPROFILE to a temp folder; the guard must still know the OS account's home."""
    monkeypatch.delenv("AGENTOS_GUARD_REAL_HOME", raising=False)
    roots = home_guard.forbidden_roots()
    assert roots, "no real home found"
    assert all(not r.startswith(os.path.normcase(str(Path.home()))) for r in roots)


@pytest.mark.parametrize("rel", [".agentos", ".agentos/vault.json", ".agentos/master.key", ".agentos/api.token",
                                 ".agentos/workspace", ".agentos/data/sandbox"])
def test_guard_on_refuses_real_home_paths(fake_home, rel):
    with pytest.raises(RealHomeForbidden, match="AGENTOS_FORBID_REAL_HOME"):
        check_path(fake_home / rel, "test path")


def test_guard_on_refuses_dotdot_and_case_variants(fake_home):
    sneaky = fake_home / "other" / ".." / ".agentos" / "vault.json"
    assert is_in_real_home(sneaky)
    if os.name == "nt":
        assert is_in_real_home(str(fake_home / ".AGENTOS" / "x"))


def test_guard_on_allows_temp_paths(fake_home, tmp_path):
    ok = tmp_path / "isolated" / ".agentos" / "vault.json"
    assert check_path(ok, "vault") == ok
    assert check_path(fake_home / "not-agentos" / "x") is not None  # elsewhere in the home is fine


def test_guard_on_refuses_symlink_into_real_home(fake_home, tmp_path):
    link = tmp_path / "innocent"
    try:
        os.symlink(fake_home / ".agentos", link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks is not permitted here")
    with pytest.raises(RealHomeForbidden):
        check_path(link / "vault.json", "vault")


def test_guard_off_is_unchanged(fake_home, monkeypatch):
    monkeypatch.setenv("AGENTOS_FORBID_REAL_HOME", "0")
    p = fake_home / ".agentos" / "vault.json"
    assert check_path(p) == p


def test_every_resolver_refuses(fake_home, monkeypatch):
    from agentos.core.locations import data_dir, resolve_project_dir
    from agentos.security.vault import MasterKey, default_master_key_path
    from agentos.storage.file import default_vault_path, open_file_storage
    from agentos_server.auth import default_token_path

    bad = fake_home / ".agentos"
    monkeypatch.setenv("AGENTOS_VAULT_PATH", str(bad / "vault.json"))
    monkeypatch.setenv("AGENTOS_MASTER_KEY_FILE", str(bad / "master.key"))
    monkeypatch.setenv("AGENTOS_API_TOKEN_FILE", str(bad / "api.token"))
    monkeypatch.setenv("AGENTOS_DATA_DIR", str(bad / "data"))
    monkeypatch.delenv("AGENTOS_MASTER_KEY", raising=False)
    for fn in (default_vault_path, default_master_key_path, default_token_path, data_dir):
        with pytest.raises(RealHomeForbidden):
            fn()
    with pytest.raises(RealHomeForbidden):
        MasterKey.load(bad / "master.key")
    with pytest.raises(RealHomeForbidden):
        open_file_storage(str(bad / "workspace"))
    with pytest.raises(RealHomeForbidden):
        resolve_project_dir(str(bad / "workspace"))
    assert not any(bad.iterdir()), "nothing may be created in the (fake) real home"


def test_create_app_refuses_real_home_project(fake_home, monkeypatch):
    from agentos_server.app import create_app

    with pytest.raises(RealHomeForbidden):
        create_app(str(fake_home / ".agentos" / "workspace"))


def test_create_app_works_with_temp_paths(fake_home, tmp_path):
    from agentos_server.app import create_app

    proj = tmp_path / "proj"
    proj.mkdir()
    assert create_app(str(proj)).state.project_path == str(proj)


def test_cli_refuses_with_clear_error(fake_home, monkeypatch):
    from typer.testing import CliRunner

    from agentos.cli.main import app

    monkeypatch.setenv("AGENTOS_PROJECT", str(fake_home / ".agentos" / "workspace"))
    res = CliRunner().invoke(app, ["users", "create-admin", "--username", "x", "--password-stdin"], input="y\n")
    assert res.exit_code == 2
    assert "AGENTOS_FORBID_REAL_HOME" in res.output
