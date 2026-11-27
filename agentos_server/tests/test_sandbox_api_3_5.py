"""3.5 sandbox API (MOCK: fake backends, temp project): status, roles, audited settings, test button, tool picker."""

from __future__ import annotations

import pytest

from agentos.access import passwords as pw
from agentos.sandbox import SandboxResult
from agentos_server.tests.test_access_api_3_4 import LEGACY, client, make_app, user_with_token


class Fake:
    def __init__(self, name, kinds, ok):
        self.name, self.kinds, self.ok = name, kinds, ok

    def status(self):
        return {"available": self.ok, "detail": "fake", "kinds": list(self.kinds)}

    def available(self):
        return self.ok

    def run(self, kind, payload, files_in, limits, run_label="", image=""):
        return SandboxResult(exit_code=0, stdout="42\n", stderr="", backend=self.name, runtime_id="sha256:fake")


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", LEGACY)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.delenv("AGENTOS_V1_NO_AUTH", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return tmp_path


def _fake(app, docker=False, wasm=False):
    app.state.sandbox.docker = Fake("docker", ("python", "shell"), docker)
    app.state.sandbox.wasm = Fake("wasm", ("python",), wasm)


@pytest.mark.asyncio
async def test_status_none_and_picker_hides_code_tools(project):
    app = make_app(project)
    _fake(app)
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:
        st = (await c.get("/api/v2/sandbox/status")).json()
        assert st["effective"] == {"python": None, "shell": None} and st["tools"] == []
        assert "unavailable" in st["summary"]
        names = [o["name"] for o in (await c.get("/api/v2/agents/tool-options")).json()]
        assert not {"python_exec", "shell_exec", "file_read", "file_write"} & set(names)
        r = await c.post("/api/v2/sandbox/test")
        assert r.status_code == 200 and r.json()["ok"] is False and "NOT run" in r.json()["error"]


@pytest.mark.asyncio
async def test_picker_follows_backend_support(project):
    app = make_app(project)
    _fake(app, wasm=True)
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:
        names = [o["name"] for o in (await c.get("/api/v2/agents/tool-options")).json()]
        assert {"python_exec", "file_read", "file_write"} <= set(names) and "shell_exec" not in names
        _fake(app, docker=True)
        names = [o["name"] for o in (await c.get("/api/v2/agents/tool-options")).json()]
        assert {"python_exec", "shell_exec", "file_read", "file_write"} <= set(names)
        r = await c.post("/api/v2/sandbox/test")
        assert r.json()["ok"] is True and r.json()["backend"] == "docker"


@pytest.mark.asyncio
async def test_settings_are_admin_only_validated_and_audited(project):
    app = make_app(project)
    _fake(app, wasm=True)
    viewer = await user_with_token(app, "vic", "viewer")
    async with client(app, Authorization=f"Bearer {viewer}") as c:
        assert (await c.get("/api/v2/sandbox/status")).status_code == 200
        assert (await c.get("/api/v2/sandbox/settings")).status_code == 403
        assert (await c.put("/api/v2/sandbox/settings", json={"backend": "off"})).status_code == 403
        assert (await c.post("/api/v2/sandbox/test")).status_code == 403
        assert (await c.post("/api/v2/sandbox/wasm/install")).status_code == 403
    admin = await user_with_token(app, "ada", "admin")
    async with client(app, Authorization=f"Bearer {admin}") as c:
        s = (await c.get("/api/v2/sandbox/settings")).json()
        bad = await c.put("/api/v2/sandbox/settings", json={**s, "default_image": "python:latest"})
        assert bad.status_code == 400
        bad2 = await c.put("/api/v2/sandbox/settings", json={**s, "limits": {**s["limits"], "timeout_s": 0}})
        assert bad2.status_code == 400
        s["backend"] = "off"
        s["limits"]["timeout_s"] = 10
        ok = await c.put("/api/v2/sandbox/settings", json=s)
        assert ok.status_code == 200
        st = (await c.get("/api/v2/sandbox/status")).json()
        assert st["mode"] == "off" and st["tools"] == [] and st["limits"]["timeout_s"] == 10
    entries = [e for e in await app.state.audit.entries() if e["action"] == "sandbox.settings.update"]
    assert len(entries) == 1
    d = entries[0]["details"]
    assert d["old"]["backend"] == "auto" and d["new"]["backend"] == "off" and d["new"]["limits.timeout_s"] == 10
    assert (project / ".agentos" / "state" / "sandbox.json").is_file()


@pytest.mark.asyncio
async def test_test_button_is_audited(project):
    app = make_app(project)
    _fake(app, wasm=True)
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:
        r = await c.post("/api/v2/sandbox/test")
        assert r.json()["ok"] is True and r.json()["backend"] == "wasm"
    assert any(e["action"] == "sandbox.test" for e in await app.state.audit.entries())
