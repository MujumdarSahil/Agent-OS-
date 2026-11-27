"""3.5 Part 0b: `agentos users create-admin` and the server resolve the SAME data location (MOCK, temp paths only).

Before: the CLI used AGENTOS_PROJECT/cwd + AGENTOS_STORAGE, main.py used cwd-with-config/default workspace +
AGENTOS_MONGO_URI, so an admin created with the CLI could be invisible to the server ("No users yet").
"""

from __future__ import annotations

import asyncio
import os

import pytest
from httpx import ASGITransport, AsyncClient
from typer.testing import CliRunner

from agentos.access import passwords as pw

PASSWORD = "violet-harbor-lantern-42"
UI = {"Origin": "http://localhost:5173", "Host": "localhost"}


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.delenv("AGENTOS_PROJECT", raising=False)
    monkeypatch.setenv("AGENTOS_API_TOKEN", "location-test-legacy-token")
    return tmp_path


def _create_admin(*args: str, cwd: str | None = None):
    from agentos.cli.main import app

    old = os.getcwd()
    try:
        if cwd:
            os.chdir(cwd)
        return CliRunner().invoke(app, ["users", "create-admin", "--username", "owner", "--password-stdin", *args],
                                  input=PASSWORD + "\n")
    finally:
        os.chdir(old)


async def _server_login(project: str) -> int:
    from agentos_server.app import create_app

    app = create_app(project)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        r = await c.post("/api/v2/auth/login", json={"username": "owner", "password": PASSWORD}, headers=UI)
    return r.status_code


def test_cli_admin_can_log_in_to_server_via_agentos_project(env, monkeypatch):
    project = env / "proj"
    project.mkdir()
    monkeypatch.setenv("AGENTOS_PROJECT", str(project))  # what main.py sets for the server
    elsewhere = env / "elsewhere"
    elsewhere.mkdir()
    res = _create_admin(cwd=str(elsewhere))  # run from another folder: must still use AGENTOS_PROJECT
    assert res.exit_code == 0, res.output
    assert f"Data location: {project} (file storage)" in res.output.replace("\n", "")
    assert PASSWORD not in res.output
    assert asyncio.run(_server_login(str(project))) == 200


def test_cli_admin_cwd_with_config_matches_launcher(env):
    project = env / "cwdproj"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    res = _create_admin(cwd=str(project))
    assert res.exit_code == 0, res.output
    assert asyncio.run(_server_login(str(project))) == 200


def test_resolver_order_matches_launcher(env, monkeypatch):
    import main as launcher

    from agentos.core.locations import default_workspace, resolve_project_dir

    a, b = env / "a", env / "b"
    a.mkdir()
    b.mkdir()
    (b / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    monkeypatch.setenv("AGENTOS_PROJECT", str(a))
    assert resolve_project_dir(str(b)) == str(b)  # --project wins
    assert resolve_project_dir() == str(a)  # then AGENTOS_PROJECT
    monkeypatch.delenv("AGENTOS_PROJECT")
    monkeypatch.chdir(b)
    assert resolve_project_dir() == str(b) == launcher.resolve_project(None)  # then cwd with config
    monkeypatch.chdir(a)
    assert resolve_project_dir() == str(default_workspace())  # then the default workspace (temp home in tests)


def test_mongo_location_never_prints_the_uri(monkeypatch):
    pytest.importorskip("pymongo")
    from agentos.core.locations import describe_data_location

    monkeypatch.setenv("AGENTOS_MONGO_URI", "mongodb://user:not-a-real-pass@127.0.0.1:1/?replicaSet=rs0")
    monkeypatch.setenv("AGENTOS_MONGO_DB", "tenant_a")
    text = describe_data_location("/ignored")
    assert "tenant_a" in text and "not-a-real-pass" not in text and "mongodb://" not in text
