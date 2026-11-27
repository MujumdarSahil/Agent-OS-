"""3.4 access through the real app (MOCK, file storage, temp home): permissions on every route, sessions, CSRF,
login, API tokens, WebSocket, bootstrap, legacy token, audit actor, separation of duties.

scrypt cost is lowered by monkeypatching the module constant (there is no env knob to do it).
"""

from __future__ import annotations

import asyncio
import re
import statistics
import time

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from agentos.access import passwords as pw
from agentos.access.permissions import ROLES, allows
from agentos.tests.test_restructure_1_1b import _route_table, _v2_route_table
from agentos_server.permissions_table import PERMISSIONS

LEGACY = "access-test-legacy-token"
PASSWORD = "violet-harbor-lantern-42"
UI = {"Origin": "http://localhost:5173", "Host": "localhost"}
MW_DENY = re.compile(r"^Forbidden: (requires the|this route declares no permission)")

APPROVAL_FLOW = {
    "id": "sod_flow", "name": "sod", "entrypoint": "hook",
    "nodes": {
        "hook": {"id": "hook", "type": "webhook_trigger", "config": {}},
        "gate": {"id": "gate", "type": "approval",
                 "config": {"prompt": "Review", "approves": {"sink_node": "send", "args": ["to", "body"]}}},
        "send": {"id": "send", "type": "send_email", "config": {}},
    },
    "edges": [{"source": "hook", "target": "gate", "arg_mapping": {"to": "payload", "body": "payload"}},
              {"source": "gate", "target": "send", "arg_mapping": {"to": "to", "body": "body"}}],
}


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    monkeypatch.setattr(pw, "LOG_N", 10)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", LEGACY)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.delenv("AGENTOS_V1_NO_AUTH", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return tmp_path


def make_app(project):
    from agentos_server.app import create_app

    return create_app(str(project))


def client(app, **headers) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://localhost",
                       headers={"Host": "localhost", **headers})


async def user_with_token(app, username: str, role: str) -> str:
    svc = app.state.access
    if await svc.find_user(username) is None:
        await svc.create_user(username, None, role, PASSWORD)
    u = await svc.find_user(username)
    raw, _ = await svc.create_token(u["id"], f"{username}-pat", 30)
    return raw


async def login(c: AsyncClient, username: str, password: str = PASSWORD) -> dict:
    r = await c.post("/api/v2/auth/login", json={"username": username, "password": password}, headers=UI)
    assert r.status_code == 200, r.text
    return r.json()["me"]


# ------------------------------------------------------------------ route table


def test_every_route_declares_a_permission(project):
    app = make_app(project)
    routes = {(m, p) for p, m in _route_table(app) + _v2_route_table(app)}
    missing = sorted(r for r in routes if r not in PERMISSIONS)
    assert missing == [], f"routes without a declared permission (deny by default, add them): {missing}"
    stale = sorted(k for k in PERMISSIONS if k not in routes)
    assert stale == [], f"permission entries for routes that do not exist: {stale}"


def _concrete(path: str) -> str:
    return re.sub(r"\{version\}", "1", re.sub(r"\{(?!version)[^}]+\}", "x", path))


@pytest.mark.asyncio
async def test_role_matrix_on_every_route(project):
    """Generated from the route table: each role gets 403 exactly where its role lacks the capability."""
    app = make_app(project)
    tokens = {role: await user_with_token(app, f"m-{role}", role) for role in ROLES}
    http_routes = [(m, p) for p, m in _route_table(app) + _v2_route_table(app) if m != "WS"]
    wrong = []
    for role, token in tokens.items():
        async with client(app, Authorization=f"Bearer {token}") as c:
            for method, path in http_routes:
                cap = PERMISSIONS[(method, path)]
                r = await c.request(method, _concrete(path), json={})
                body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                detail = body.get("detail") if isinstance(body, dict) else ""
                denied = r.status_code == 403 and isinstance(detail, str) and bool(MW_DENY.match(detail))
                if denied == allows(role, cap) or r.status_code == 401:
                    wrong.append((role, method, path, cap, r.status_code))
    assert wrong == []


@pytest.mark.asyncio
async def test_unauthenticated_gets_401_on_every_non_public_route(project):
    app = make_app(project)
    async with client(app) as c:
        for p, m in _route_table(app) + _v2_route_table(app):
            if m == "WS" or PERMISSIONS[(m, p)] == "public":
                continue
            r = await c.request(m, _concrete(p), json={})
            assert r.status_code == 401, (m, p, r.status_code)


@pytest.mark.asyncio
async def test_deny_by_default_for_an_undeclared_route(project):
    app = make_app(project)

    async def secret_thing():
        return {"leak": True}

    app.add_api_route("/api/v2/zz-undeclared", secret_thing, methods=["GET"])
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:  # even the admin
        r = await c.get("/api/v2/zz-undeclared")
    assert r.status_code == 403 and "declares no permission" in r.json()["detail"]


# ------------------------------------------------------------------ bootstrap and legacy token


@pytest.mark.asyncio
async def test_setup_requires_the_local_token_and_runs_once(project):
    app = make_app(project)
    body = {"username": "admin", "password": PASSWORD}
    async with client(app) as c:
        assert (await c.get("/api/v2/auth/status")).json()["setup_required"] is True
        assert (await c.post("/api/v2/auth/setup", json=body, headers=UI)).status_code == 401
        r = await c.post("/api/v2/auth/setup", json=body, headers={**UI, "Authorization": "Bearer wrong"})
        assert r.status_code == 401
        r = await c.post("/api/v2/auth/setup", json={**body, "password": "short"},
                         headers={**UI, "Authorization": f"Bearer {LEGACY}"})
        assert r.status_code == 400
        r = await c.post("/api/v2/auth/setup", json=body, headers={**UI, "Authorization": f"Bearer {LEGACY}"})
        assert r.status_code == 200 and r.json()["me"]["role"] == "admin" and "agentos_session" in r.cookies
        r = await c.post("/api/v2/auth/setup", json={**body, "username": "second"},
                         headers={**UI, "Authorization": f"Bearer {LEGACY}"})
        assert r.status_code == 409
        assert (await c.get("/api/v2/auth/status")).json()["setup_required"] is False


@pytest.mark.asyncio
async def test_legacy_token_keeps_working_and_can_be_disabled(project):
    app = make_app(project)
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:
        assert (await c.get("/api/v2/flows")).status_code == 200  # scripts unchanged
        assert (await c.put("/api/v2/access/legacy-token", json={"enabled": False})).status_code == 409  # no admin yet
        r = await c.get("/api/v2/access/legacy-token")
        assert r.json() == {"enabled": True, "source": "env", "path": None, "can_rotate": False}
        assert LEGACY not in r.text
        assert (await c.post("/api/v2/access/legacy-token/rotate")).status_code == 409  # from the env var
    await app.state.access.create_user("boss", None, "admin", PASSWORD)
    async with client(app) as c:
        me = await login(c, "boss")
        h = {**UI, "X-AgentOS-CSRF": me["csrf_token"]}
        assert (await c.put("/api/v2/access/legacy-token", json={"enabled": False}, headers=h)).status_code == 200
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:
        assert (await c.get("/api/v2/flows")).status_code == 401
    actions = [e["action"] for e in await app.state.audit.entries()]
    assert "legacy_token.disable" in actions


@pytest.mark.asyncio
async def test_legacy_token_rotation_from_file(project, monkeypatch, tmp_path):
    from agentos_server.auth import get_or_create_api_token

    monkeypatch.delenv("AGENTOS_API_TOKEN")
    monkeypatch.setenv("AGENTOS_API_TOKEN_FILE", str(tmp_path / "home" / "api.token"))
    old = get_or_create_api_token()
    app = make_app(project)
    async with client(app, Authorization=f"Bearer {old}") as c:
        r = await c.post("/api/v2/access/legacy-token/rotate", headers=UI)
        assert r.status_code == 200
        new = r.json()["token"]
        assert new != old and (tmp_path / "home" / "api.token").read_text(encoding="ascii").strip() == new
        assert (await c.get("/api/v2/flows")).status_code == 401  # old one is dead
    async with client(app, Authorization=f"Bearer {new}") as c:
        assert (await c.get("/api/v2/flows")).status_code == 200


# ------------------------------------------------------------------ login


@pytest.mark.asyncio
async def test_no_user_enumeration(project):
    app = make_app(project)
    await app.state.access.create_user("real", None, "viewer", PASSWORD)
    await app.state.access.warm()
    async with client(app) as c:
        a = await c.post("/api/v2/auth/login", json={"username": "real", "password": "wrong-password-xyz"}, headers=UI)
        b = await c.post("/api/v2/auth/login", json={"username": "ghost", "password": "wrong-password-xyz"}, headers=UI)
        assert (a.status_code, a.json()) == (b.status_code, b.json()) == (401, {"detail": "Invalid username or password"})

        async def timed(name: str) -> float:
            t = time.perf_counter()
            await c.post("/api/v2/auth/login", json={"username": name, "password": "wrong-password-xyz"},
                         headers={**UI, "X-Forwarded-For": name})
            return time.perf_counter() - t

        app.state.login_limiter.retry_after = lambda ip, user: 0  # timing only; the limiter is tested separately
        real = statistics.median([await timed("real") for _ in range(7)])
        ghost = statistics.median([await timed("ghost") for _ in range(7)])
    assert 0.5 < ghost / real < 2.0, (real, ghost)  # both paths do one scrypt


@pytest.mark.asyncio
async def test_login_rate_limit_and_audit(project):
    app = make_app(project)
    await app.state.access.create_user("rita", None, "viewer", PASSWORD)
    async with client(app) as c:
        for _ in range(5):
            r = await c.post("/api/v2/auth/login", json={"username": "rita", "password": "nope-nope-nope"}, headers=UI)
            assert r.status_code == 401
        r = await c.post("/api/v2/auth/login", json={"username": "rita", "password": PASSWORD}, headers=UI)
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1  # even the right password must wait
    await app.state.auth_failures.flush(app)
    failed = [e for e in await app.state.audit.entries() if e["action"] == "auth.login_failed"]
    assert failed and failed[-1]["details"]["count"] == 5 and "rita" not in str(failed)


@pytest.mark.asyncio
async def test_password_rules_on_create(project):
    app = make_app(project)
    async with client(app, Authorization=f"Bearer {LEGACY}") as c:
        for bad in ("short1", "password1234", "newuser12345"):
            r = await c.post("/api/v2/users", json={"username": "newuser12345", "role": "viewer", "password": bad})
            assert r.status_code == 400, bad
            assert bad not in r.text
        r = await c.post("/api/v2/users", json={"username": "newuser12345", "role": "viewer", "password": PASSWORD})
        assert r.status_code == 201 and "password_hash" not in r.text and PASSWORD not in r.text
        assert (await c.post("/api/v2/users", json={"username": "NEWUSER12345", "role": "viewer",
                                                     "password": PASSWORD})).status_code == 409


# ------------------------------------------------------------------ sessions and CSRF


@pytest.mark.asyncio
async def test_session_cookie_flags_logout_and_csrf(project):
    app = make_app(project)
    await app.state.access.create_user("bea", None, "builder", PASSWORD)
    async with client(app) as c:
        r = await c.post("/api/v2/auth/login", json={"username": "bea", "password": PASSWORD}, headers=UI)
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
        assert "secure" not in cookie  # plain http on localhost; https sets Secure
        csrf = r.json()["me"]["csrf_token"]
        flow = {**APPROVAL_FLOW, "id": "csrf_flow"}
        assert (await c.post("/api/v2/flows", json=flow, headers=UI)).status_code == 403  # no CSRF header
        bad_origin = {"Origin": "http://evil.example", "X-AgentOS-CSRF": csrf}
        assert (await c.post("/api/v2/flows", json=flow, headers=bad_origin)).status_code == 403
        no_origin = {"X-AgentOS-CSRF": csrf}
        assert (await c.post("/api/v2/flows", json=flow, headers=no_origin)).status_code == 403
        wrong = {**UI, "X-AgentOS-CSRF": "0" * 64}
        assert (await c.post("/api/v2/flows", json=flow, headers=wrong)).status_code == 403
        ok = {**UI, "X-AgentOS-CSRF": csrf}
        assert (await c.post("/api/v2/flows", json=flow, headers=ok)).status_code == 201
        assert (await c.get("/api/v2/flows")).status_code == 200  # reads need no CSRF header
        assert (await c.post("/api/v2/auth/logout", headers=ok)).status_code == 200
        assert (await c.get("/api/v2/flows")).status_code == 401  # session revoked server-side


@pytest.mark.asyncio
async def test_cross_site_login_post_refused(project):
    app = make_app(project)
    await app.state.access.create_user("cara", None, "viewer", PASSWORD)
    async with client(app) as c:
        r = await c.post("/api/v2/auth/login", json={"username": "cara", "password": PASSWORD},
                         headers={"Origin": "http://evil.example"})
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_password_change_revokes_other_sessions(project):
    app = make_app(project)
    await app.state.access.create_user("dan", None, "viewer", PASSWORD)
    async with client(app) as a, client(app) as b:
        me_a = await login(a, "dan")
        await login(b, "dan")
        h = {**UI, "X-AgentOS-CSRF": me_a["csrf_token"]}
        r = await a.post("/api/v2/auth/password", json={"current_password": PASSWORD,
                                                         "new_password": "fresh-orchard-river-9"}, headers=h)
        assert r.status_code == 200 and r.json()["other_sessions_revoked"] == 1
        assert (await a.get("/api/v2/auth/me")).status_code == 200
        assert (await b.get("/api/v2/auth/me")).status_code == 401


# ------------------------------------------------------------------ API tokens


@pytest.mark.asyncio
async def test_pat_create_use_revoke_expire(project):
    app = make_app(project)
    await app.state.access.create_user("eve", None, "builder", PASSWORD)
    async with client(app) as c:
        me = await login(c, "eve")
        h = {**UI, "X-AgentOS-CSRF": me["csrf_token"]}
        r = await c.post("/api/v2/auth/tokens", json={"name": "ci", "expires_in_days": 7}, headers=h)
        assert r.status_code == 201
        raw, token_id = r.json()["token"], r.json()["token_id"]
        listed = (await c.get("/api/v2/auth/tokens")).json()
        assert raw not in str(listed) and listed[0]["active"] is True
    async with client(app, Authorization=f"Bearer {raw}") as t:
        assert (await t.post("/api/v2/flows", json={**APPROVAL_FLOW, "id": "pat_flow"})).status_code == 201
        assert (await t.put("/api/v2/budgets", json={})).status_code == 403  # builder, not admin
        r = await t.post("/api/v2/auth/tokens", json={"name": "child"})
        assert r.status_code == 403  # a token cannot mint tokens
    entries = await app.state.audit.entries()
    assert any(e["action"] == "flow.save" and e["actor"] == "token:ci@eve" for e in entries)
    async with client(app) as c:
        me = await login(c, "eve")
        h = {**UI, "X-AgentOS-CSRF": me["csrf_token"]}
        assert (await c.delete(f"/api/v2/auth/tokens/{token_id}", headers=h)).status_code == 200
    async with client(app, Authorization=f"Bearer {raw}") as t:
        assert (await t.get("/api/v2/flows")).status_code == 401
    raw2 = await user_with_token(app, "eve", "builder")
    doc = next(d for d in await app.state.access.store.tokens.list() if d["name"] == "eve-pat")
    await app.state.access.store.tokens.put({**doc, "expires_ts": time.time() - 1})
    async with client(app, Authorization=f"Bearer {raw2}") as t:
        assert (await t.get("/api/v2/flows")).status_code == 401


@pytest.mark.asyncio
async def test_disabling_a_user_kills_sessions_and_tokens(project):
    app = make_app(project)
    raw = await user_with_token(app, "fay", "viewer")
    async with client(app) as c:
        await login(c, "fay")
        async with client(app, Authorization=f"Bearer {LEGACY}") as admin:
            fay = await app.state.access.find_user("fay")
            assert (await admin.put(f"/api/v2/users/{fay['id']}", json={"disabled": True})).status_code == 200
        assert (await c.get("/api/v2/auth/me")).status_code == 401
    async with client(app, Authorization=f"Bearer {raw}") as t:
        assert (await t.get("/api/v2/flows")).status_code == 401
    actions = [(e["action"], e["actor"]) for e in await app.state.audit.entries()]
    assert ("user.disable", "legacy-local-token") in actions


# ------------------------------------------------------------------ WebSocket


def test_websocket_with_session_cookie_and_with_pat(project):
    app = make_app(project)
    from agentos.storage.models import RunRecord

    with TestClient(app, base_url="http://localhost") as tc:
        tc.portal.call(app.state.storage.runs.put, RunRecord(run_id="r", mission_name="f", flow_id="f",
                                                             status="succeeded"))
        tc.portal.call(app.state.access.create_user, "gus", None, "viewer", PASSWORD)
        r = tc.post("/api/v2/auth/login", json={"username": "gus", "password": PASSWORD}, headers=UI)
        assert r.status_code == 200
        url = "/api/v2/flows/f/runs/r/events"
        # a browser sends the session cookie on the upgrade request; the test client's jar does not for ws://
        cookie = {"cookie": f"agentos_session={r.cookies['agentos_session']}"}
        with tc.websocket_connect(url, headers={**UI, **cookie}, subprotocols=["agentos.v1"]) as ws:
            assert ws.accepted_subprotocol == "agentos.v1"
        u = tc.portal.call(app.state.access.find_user, "gus")
        raw, _ = tc.portal.call(app.state.access.create_token, u["id"], "ws", 1)
        from starlette.websockets import WebSocketDisconnect

        fresh = TestClient(app, base_url="http://localhost")  # no cookies at all
        with fresh.websocket_connect(url, headers=dict(UI), subprotocols=[f"agentos.token.{raw}", "agentos.v1"]) as ws:
            assert ws.accepted_subprotocol == "agentos.v1"  # PAT in the subprotocol
        with pytest.raises(WebSocketDisconnect) as exc:
            with fresh.websocket_connect(url, headers=dict(UI), subprotocols=["agentos.v1"]):  # no credentials
                pass
        assert exc.value.code == 4401
        with pytest.raises(WebSocketDisconnect) as exc:
            with fresh.websocket_connect(url, headers={**UI, "Origin": "http://evil.example"},
                                         subprotocols=[f"agentos.token.{raw}", "agentos.v1"]):
                pass
        assert exc.value.code == 4401


# ------------------------------------------------------------------ approvals: who decided, separation of duties


async def _waiting_run(app, c: AsyncClient, flow_id: str) -> str:
    assert (await c.post("/api/v2/flows", json={**APPROVAL_FLOW, "id": flow_id})).status_code == 201
    assert (await c.post(f"/api/v2/flows/{flow_id}/publish")).status_code == 200
    r = await c.post(f"/api/v2/flows/{flow_id}/runs", json={"inputs": {"payload": "ops@corp.local"}})
    run_id = r.json()["run_id"]
    for _ in range(200):
        if (await c.get(f"/api/v2/flows/{flow_id}/runs/{run_id}")).json()["status"] == "waiting":
            return run_id
        await asyncio.sleep(0.05)
    raise AssertionError("run did not reach the approval")


@pytest.mark.asyncio
@pytest.mark.parametrize("sod", [False, True])
async def test_decided_by_and_separation_of_duties(project, monkeypatch, sod):
    from agentos.flows.proxy import MockTransport

    monkeypatch.setenv("AGENTOS_INPROCESS_WORKER", "1")
    if sod:
        (project / "agentos.config.yaml").write_text("preferred_tags: []\nsecurity:\n  separation_of_duties: true\n",
                                                     encoding="utf-8")
    app = make_app(project)
    app.state.transport_registry = {"send_email": MockTransport()}
    admin_pat = await user_with_token(app, "ada", "admin")
    approver_pat = await user_with_token(app, "abe", "approver")
    async with app.router.lifespan_context(app):
        async with client(app, Authorization=f"Bearer {admin_pat}") as c:
            run_id = await _waiting_run(app, c, f"sod_{sod}")
            r = await c.post(f"/api/v2/flows/sod_{sod}/runs/{run_id}/approve", json={"node_id": "gate", "decision": True})
            if sod:
                assert r.status_code == 403 and "Separation of duties" in r.json()["detail"]
                async with client(app, Authorization=f"Bearer {approver_pat}") as a:
                    r = await a.post(f"/api/v2/flows/sod_{sod}/runs/{run_id}/approve",
                                     json={"node_id": "gate", "decision": True})
            assert r.status_code == 200, r.text
            events = (await c.get(f"/api/v2/flows/sod_{sod}/runs/{run_id}/events")).json()
            run = (await c.get(f"/api/v2/flows/sod_{sod}/runs/{run_id}")).json()
    events = events.get("events", events) if isinstance(events, dict) else events
    decided = next(e["data"] for e in events if e["type"] == "approval_decision")["decided_by"]
    started = next(e["data"] for e in events if e["type"] == "run_started").get("started_by")
    assert decided["username"] == ("abe" if sod else "ada")
    assert started["username"] == "ada" and run["started_by"]["username"] == "ada"
