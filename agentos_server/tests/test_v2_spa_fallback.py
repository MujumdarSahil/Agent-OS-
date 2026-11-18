"""2.4d-fix (MOCK): single-port SPA fallback.

App routes (e.g. /flows/<id>) return the UI's index.html; /api/*, /hooks/* and /ws keep their own
responses (unknown /api paths still 404 JSON); a missing asset still 404s; token and Host checks
still apply.
"""

import pytest
from starlette.testclient import TestClient

from agentos_server.app import create_app

TOKEN = "test-token-spa-fallback"
INDEX = "<!doctype html><title>AgentOS UI marker</title>"


@pytest.fixture
def client(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(INDEX, encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log('ok')", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    monkeypatch.setenv("AGENTOS_UI_DIST", str(dist))
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    with TestClient(create_app(project_path=str(project)), base_url="http://localhost") as c:
        yield c


@pytest.mark.parametrize("route", ["/", "/flows", "/flows/uc07_support_desk", "/providers", "/flows/a/b"])
def test_app_routes_return_the_ui(client, route):
    r = client.get(route)
    assert r.status_code == 200 and "AgentOS UI marker" in r.text


def test_real_assets_served_and_missing_assets_404(client):
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/missing.js").status_code == 404


def test_api_hooks_ws_paths_are_never_the_ui(client):
    auth = {"Authorization": f"Bearer {TOKEN}"}
    unknown_api = client.get("/api/v2/does-not-exist", headers=auth)
    assert unknown_api.status_code == 404 and unknown_api.json() == {"detail": "Not Found"}
    assert client.get("/api/nope/deeper", headers=auth).status_code == 404
    hook = client.post("/hooks/not-a-real-secret-path", content="{}", headers={"Content-Type": "application/json"})
    assert hook.status_code == 404 and hook.json() == {"detail": "Not Found"}
    ws = client.get("/ws/runs/x")
    assert ws.status_code == 404 and "AgentOS UI marker" not in ws.text


def test_auth_and_host_checks_still_apply(client):
    assert client.get("/api/v2/flows").status_code == 401  # no token
    assert client.get("/api/v2/flows", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    bad_host = client.get("/flows/uc07_support_desk", headers={"Host": "evil.example"})
    assert bad_host.status_code in (400, 403) and "AgentOS UI marker" not in bad_host.text
    bad_host_api = client.get("/api/v2/flows", headers={"Host": "evil.example", "Authorization": f"Bearer {TOKEN}"})
    assert bad_host_api.status_code in (400, 403)
