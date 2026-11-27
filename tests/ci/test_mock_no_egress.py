"""3.4 Part 0a (MOCK): MOCK mode makes ZERO outbound model requests, even with provider keys present.

Regression test for the 2026-11-20 finding (a MOCK server sent use case 07's tickets to a paid provider): every
provider key and base-URL variable in PROVIDER_REGISTRY gets a dummy value, the project has a .env with dummy keys,
and use case 07's support-desk flow runs through the real server app and its in-process worker. A socket guard
refuses and records every non-loopback connection and DNS lookup, and LiteLLM's completion entry points fail the
test if called. The urgent ticket must still reach the approval card, answered by the scripted model.
"""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[2]
UC07 = ROOT / "examples" / "usecases" / "07-support-desk-copilot"
TOKEN = "mock-no-egress-test-token"
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class EgressGuard:
    def __init__(self, monkeypatch):
        self.attempts: list[str] = []
        real_connect = socket.socket.connect
        real_getaddrinfo = socket.getaddrinfo
        guard = self

        def connect(sock, address):
            host = address[0] if isinstance(address, tuple) else str(address)
            if host not in _LOOPBACK:
                guard.attempts.append(f"connect {host}")
                raise OSError("egress blocked by test")
            return real_connect(sock, address)

        def getaddrinfo(host, *a, **kw):
            if host not in _LOOPBACK and host is not None:
                guard.attempts.append(f"dns {host}")
                raise socket.gaierror("egress blocked by test")
            return real_getaddrinfo(host, *a, **kw)

        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


class FakeLookup:
    """Stands in for the http_request node's network (UC07's customer lookup), so the run makes no HTTP at all."""

    def __init__(self):
        from agentos.flows.net_guard import HttpRequestTransport, RawResponse

        self.calls = 0

        def send(method, target, path, headers, body, timeout_s, max_bytes):
            self.calls += 1
            return RawResponse(200, {"content-type": "application/json"}, b'{"id": 1, "name": "Test"}')

        self.transport = HttpRequestTransport(allowlist=[], resolver=lambda h, p: ["104.21.0.10"], sender=send)


@pytest.fixture
def env(tmp_path, monkeypatch):
    from agentos.llm.provider_registry import PROVIDER_REGISTRY

    for prov in PROVIDER_REGISTRY:
        for var in (prov.get("api_key_env"), prov.get("api_base_env")):
            if var:
                value = "http://127.0.0.1:9/never" if var == prov.get("api_base_env") else "dummy-not-a-real-key"
                monkeypatch.setenv(var, value)
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-not-a-real-key")
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    monkeypatch.delenv("AGENTOS_SKIP_DOTENV", raising=False)  # the .env below IS loaded; MOCK must still hold
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    (project / ".env").write_text("OPENAI_API_KEY=dummy-from-dotenv\nGROQ_API_KEY=dummy-from-dotenv\n",
                                  encoding="utf-8")

    import litellm

    def forbidden(*a, **kw):
        raise AssertionError("MOCK mode called LiteLLM")

    for name in ("completion", "acompletion", "responses", "text_completion"):
        if hasattr(litellm, name):
            monkeypatch.setattr(litellm, name, forbidden)
    import agentos.llm.router_llm as rl

    monkeypatch.setattr(rl, "_completion", forbidden)
    return str(project)


@pytest.mark.asyncio
async def test_mock_run_of_uc07_through_server_makes_no_outbound_model_request(env, monkeypatch):
    from agentos.flows.proxy import MockTransport
    from agentos_server.app import create_app

    app = create_app(project_path=env)
    lookup, outbox = FakeLookup(), MockTransport()
    app.state.transport_registry = {"send_email": outbox, "http_request": lookup.transport}
    flow = json.loads((UC07 / "flows" / "support_desk.flow.json").read_text(encoding="utf-8"))
    ticket = json.loads((UC07 / "inputs" / "tickets.json").read_text(encoding="utf-8"))["urgent"]

    guard = EgressGuard(monkeypatch)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                               headers={"Authorization": f"Bearer {TOKEN}", "Host": "localhost"}) as c:
            assert (await c.post("/api/v2/flows", json=flow)).status_code == 201
            pub = await c.post(f"/api/v2/flows/{flow['id']}/publish", json={"note": "test publish"})
            assert pub.status_code == 200, pub.text
            r = await c.post(f"/api/v2/flows/{flow['id']}/runs", json={"inputs": ticket})
            assert r.status_code == 201, r.text
            run_id = r.json()["run_id"]
            status = ""
            for _ in range(400):
                status = (await c.get(f"/api/v2/flows/{flow['id']}/runs/{run_id}")).json()["status"]
                if status in ("waiting", "succeeded", "failed", "cancelled"):
                    break
                await asyncio.sleep(0.05)
            events = (await c.get(f"/api/v2/flows/{flow['id']}/runs/{run_id}/events")).json()

    events = events.get("events", events) if isinstance(events, dict) else events
    llm_calls = [e["data"] for e in events if e["type"] == "llm_call"]
    waiting = [e["data"] for e in events if e["type"] == "node_waiting"]
    assert guard.attempts == [], f"outbound connections attempted in MOCK mode: {guard.attempts}"
    assert status == "waiting", f"run status {status!r}"
    assert waiting and waiting[0]["node_id"] == "oncall_approval"
    assert llm_calls and all(c["provider"] == "mock" and c["mock"] is True for c in llm_calls)
    assert lookup.calls == 1 and outbox.sent_calls == []


def test_no_import_time_dotenv_loading_in_the_packages():
    """.env is loaded in one place only (agentos/core/dotenv_loader.py), at startup."""
    offenders = []
    for pkg in ("agentos", "agentos_server"):
        for path in (ROOT / pkg).rglob("*.py"):
            if "tests" in path.parts or path.name == "dotenv_loader.py":
                continue
            if "load_dotenv(" in path.read_text(encoding="utf-8", errors="replace"):
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
