"""
Use case 11: users, login and roles (3.4). MOCK only: the real AgentOS app runs in this process (no network,
no model, emails go to MockTransport). Every AgentOS path (vault, master key, token file, data) is a temp folder.

Benign
  setup      -> the first admin is created with the local API token (only possible while no user exists)
  team       -> the admin creates a builder, an approver and a viewer
  workflow   -> the builder publishes and starts a flow; it waits at the approval; the approver approves;
                one email goes out; the run records who started it and who decided

Attacks (each must be refused)
  viewer approves            -> 403 (role)
  cross-site request         -> 403 (wrong Origin, or no CSRF header, even with the session cookie)
  user enumeration           -> unknown user and wrong password get the same answer
  brute force                -> 429 with Retry-After after 5 failures
  revoked API token          -> 401
  separation of duties       -> whoever published a version cannot approve its runs (admin flag)
  second setup               -> 409 once a user exists

Run:  python examples/usecases/11-access-roles/run.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Isolation first, before any agentos import (CLAUDE.md rule 13): nothing touches the real ~/.agentos.
_HOME = Path(tempfile.mkdtemp(prefix="agentos-uc11-"))
os.environ.update({
    "AGENTOS_VAULT_PATH": str(_HOME / ".agentos" / "vault.json"),
    "AGENTOS_MASTER_KEY_FILE": str(_HOME / ".agentos" / "master.key"),
    "AGENTOS_API_TOKEN_FILE": str(_HOME / ".agentos" / "api.token"),
    "AGENTOS_DATA_DIR": str(_HOME / "data"),
    "AGENTOS_SKIP_DOTENV": "1",
    "AGENTOS_MOCK_LLM": "1",
    "AGENTOS_INPROCESS_WORKER": "1",
    "AGENTOS_INTERNAL_DOMAINS": "corp.local",
    "AGENTOS_API_TOKEN": "uc11-local-token-for-this-demo-only",
})
os.environ.pop("AGENTOS_MONGO_URI", None)
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient  # noqa: E402

from agentos.flows.proxy import MockTransport  # noqa: E402

LOCAL_TOKEN = os.environ["AGENTOS_API_TOKEN"]
UI = {"Origin": "http://localhost:5173", "Host": "localhost"}
PASSWORDS = {"admin": "uc11-admin-harbor-lantern", "bob": "uc11-builder-orchard-river",
             "ann": "uc11-approver-meadow-stone", "vic": "uc11-viewer-copper-window"}
FLOW = {
    "id": "uc11_flow", "name": "uc11", "entrypoint": "hook",
    "nodes": {
        "hook": {"id": "hook", "type": "webhook_trigger", "config": {}},
        "gate": {"id": "gate", "type": "approval",
                 "config": {"prompt": "Send this?", "approves": {"sink_node": "send", "args": ["to", "body"]}}},
        "send": {"id": "send", "type": "send_email", "config": {}},
    },
    "edges": [{"source": "hook", "target": "gate", "arg_mapping": {"to": "payload", "body": "payload"}},
              {"source": "gate", "target": "send", "arg_mapping": {"to": "to", "body": "body"}}],
}


def client(app, **headers) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                       headers={"Host": "localhost", **headers})


async def login(app, name: str) -> tuple[AsyncClient, dict]:
    c = client(app)
    r = await c.post("/api/v2/auth/login", json={"username": name, "password": PASSWORDS[name]}, headers=UI)
    assert r.status_code == 200, r.text
    return c, {**UI, "X-AgentOS-CSRF": r.json()["me"]["csrf_token"]}


async def waiting_run(c: AsyncClient, h: dict, flow_id: str) -> str:
    r = await c.post(f"/api/v2/flows/{flow_id}/runs", json={"inputs": {"payload": "ops@corp.local"}}, headers=h)
    run_id = r.json()["run_id"]
    for _ in range(200):
        if (await c.get(f"/api/v2/flows/{flow_id}/runs/{run_id}")).json()["status"] == "waiting":
            return run_id
        await asyncio.sleep(0.05)
    raise RuntimeError("run did not reach the approval")


def report(ok: bool, text: str) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {text}")
    return ok


async def _run_usecase_async() -> bool:
    from agentos_server.app import create_app

    project = _HOME / "project"
    project.mkdir(exist_ok=True)
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    app = create_app(str(project))
    outbox = MockTransport()
    app.state.transport_registry = {"send_email": outbox}
    ok = True
    async with app.router.lifespan_context(app):
        # --- setup: first admin, only with the local token -------------------------------------------------
        async with client(app) as anon:
            no_token = await anon.post("/api/v2/auth/setup", json={"username": "admin", "password": PASSWORDS["admin"]},
                                       headers=UI)
            r = await anon.post("/api/v2/auth/setup", json={"username": "admin", "password": PASSWORDS["admin"]},
                                headers={**UI, "Authorization": f"Bearer {LOCAL_TOKEN}"})
            ok &= report(no_token.status_code == 401 and r.status_code == 200,
                         f"setup: without the local token={no_token.status_code}, with it={r.status_code} (admin created)")
            again = await anon.post("/api/v2/auth/setup", json={"username": "evil", "password": "evil-takeover-pass-1"},
                                    headers={**UI, "Authorization": f"Bearer {LOCAL_TOKEN}"})
            ok &= report(again.status_code == 409, f"second setup refused: {again.status_code}")

        # --- team ------------------------------------------------------------------------------------------
        admin, ah = await login(app, "admin")
        for name, role in (("bob", "builder"), ("ann", "approver"), ("vic", "viewer")):
            r = await admin.post("/api/v2/users", json={"username": name, "role": role, "password": PASSWORDS[name]},
                                 headers=ah)
            ok &= report(r.status_code == 201, f"team: admin created {name} ({role})")

        # --- workflow: builder publishes and starts, approver approves --------------------------------------
        bob, bh = await login(app, "bob")
        assert (await bob.post("/api/v2/flows", json=FLOW, headers=bh)).status_code == 201
        pub = await bob.post("/api/v2/flows/uc11_flow/publish", json={"note": "test publish"}, headers=bh)
        run1 = await waiting_run(bob, bh, "uc11_flow")
        bob_approve = await bob.post(f"/api/v2/flows/uc11_flow/runs/{run1}/approve",
                                     json={"node_id": "gate", "decision": True}, headers=bh)
        ok &= report(pub.status_code == 200 and bob_approve.status_code == 403,
                     f"builder publishes ({pub.status_code}) and starts a run; builder cannot approve ({bob_approve.status_code})")

        vic, vh = await login(app, "vic")
        r = await vic.post(f"/api/v2/flows/uc11_flow/runs/{run1}/approve", json={"node_id": "gate", "decision": True},
                           headers=vh)
        ok &= report(r.status_code == 403, f"attack: viewer approves -> {r.status_code}")

        ann, nh = await login(app, "ann")
        r = await ann.post(f"/api/v2/flows/uc11_flow/runs/{run1}/approve", json={"node_id": "gate", "decision": True},
                           headers=nh)
        events = (await ann.get(f"/api/v2/flows/uc11_flow/runs/{run1}/events")).json()
        events = events.get("events", events) if isinstance(events, dict) else events
        decided = next(e["data"].get("decided_by", {}) for e in events if e["type"] == "approval_decision")
        started = next(e["data"].get("started_by", {}) for e in events if e["type"] == "run_started")
        ok &= report(r.status_code == 200 and len(outbox.sent_calls) == 1 and decided.get("username") == "ann"
                     and started.get("username") == "bob",
                     f"approver approves -> {r.status_code}; emails={len(outbox.sent_calls)}; "
                     f"started_by={started.get('username')} decided_by={decided.get('username')}")

        # --- attack: cross-site requests with the builder's cookie ----------------------------------------
        flow2 = {**FLOW, "id": "uc11_csrf"}
        evil = await bob.post("/api/v2/flows", json=flow2,
                              headers={"Origin": "http://evil.example", "X-AgentOS-CSRF": bh["X-AgentOS-CSRF"]})
        no_hdr = await bob.post("/api/v2/flows", json=flow2, headers=UI)
        ok &= report(evil.status_code == 403 and no_hdr.status_code == 403,
                     f"attack: cross-site POST with the session cookie -> wrong Origin {evil.status_code}, "
                     f"no CSRF header {no_hdr.status_code}")

        # --- attack: user enumeration and brute force ------------------------------------------------------
        async with client(app) as anon:
            a = await anon.post("/api/v2/auth/login", json={"username": "ann", "password": "wrong-guess-123"}, headers=UI)
            b = await anon.post("/api/v2/auth/login", json={"username": "nobody", "password": "wrong-guess-123"},
                                headers=UI)
            ok &= report((a.status_code, a.json()) == (b.status_code, b.json()),
                         f"attack: enumeration -> both {a.status_code} {a.json()['detail']!r}")
            codes = [(await anon.post("/api/v2/auth/login", json={"username": "ann", "password": f"guess-{i:08d}"},
                                      headers=UI)).status_code for i in range(6)]
            last = await anon.post("/api/v2/auth/login", json={"username": "ann", "password": PASSWORDS["ann"]},
                                   headers=UI)
            ok &= report(429 in codes and last.status_code == 429 and "Retry-After" in last.headers,
                         f"attack: brute force -> {codes[-3:]}, then even the right password waits ({last.status_code})")

        # --- attack: revoked API token --------------------------------------------------------------------
        t = (await bob.post("/api/v2/auth/tokens", json={"name": "ci", "expires_in_days": 7}, headers=bh)).json()
        async with client(app, Authorization=f"Bearer {t['token']}") as script:
            before = (await script.get("/api/v2/flows")).status_code
            await bob.delete(f"/api/v2/auth/tokens/{t['token_id']}", headers=bh)
            after = (await script.get("/api/v2/flows")).status_code
        ok &= report(before == 200 and after == 401, f"API token works ({before}), then is revoked ({after})")

        # --- attack: separation of duties (admin flag) ----------------------------------------------------
        app.state.separation_of_duties = True  # = security.separation_of_duties: true in agentos.config.yaml
        flow3 = {**FLOW, "id": "uc11_sod"}
        await admin.post("/api/v2/flows", json=flow3, headers=ah)
        await admin.post("/api/v2/flows/uc11_sod/publish", json={"note": "test publish"}, headers=ah)
        run3 = await waiting_run(admin, ah, "uc11_sod")
        own = await admin.post(f"/api/v2/flows/uc11_sod/runs/{run3}/approve", json={"node_id": "gate", "decision": True},
                               headers=ah)
        other = await ann.post(f"/api/v2/flows/uc11_sod/runs/{run3}/approve", json={"node_id": "gate", "decision": False},
                               headers=nh)
        ok &= report(own.status_code == 403 and other.status_code == 200,
                     f"separation of duties: publisher approves own run -> {own.status_code}; another approver -> "
                     f"{other.status_code}")

        # --- audit actors ---------------------------------------------------------------------------------
        entries = await app.state.audit.entries()
        actors = {(e["action"], e["actor"]) for e in entries}
        ok &= report(("flow.publish", "bob") in actors and ("approval.decide", "ann") in actors
                     and ("user.create", "legacy-local-token") in actors,
                     "audit log names the user for each action (bob published, ann decided, setup via the local token)")
        for c in (admin, bob, ann, vic):
            await c.aclose()
    print("Use case 11:", "ALL PASS" if ok else "FAILURES")
    return bool(ok)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
