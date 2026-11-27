"""3.3 API: notification channels, alert rules, alerts (MOCK; Slack goes to a local stand-in through the sender's
test-only constructor arguments; nothing leaves the machine).

CRUD with audit before apply (503 fail closed), secrets write-only (vault; never in a response, the audit log or
the logs), Slack host pinned, rule channels must exist, test button audited with an AgentOS-written error, alerts
list + acknowledge (audited), Overview "needs you" count, publish refused -> attack alert, token auth.
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.notify.senders import SlackSender

SMTP_PASSWORD = "pw-" + "q9" * 8  # synthetic
SLACK_URL = "https://hooks.slack.com/services/T111/B111/" + "s" * 24  # synthetic
TOKEN = "test-token-notify"


class _Stand(BaseHTTPRequestHandler):
    posts: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        type(self).posts.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0))))
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def stand():
    _Stand.posts = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stand)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/hook"
    srv.shutdown()
    srv.server_close()
    t.join(timeout=5)


def _unsafe_flow(fid):
    return {"id": fid, "name": "unsafe", "entrypoint": "webhook",
            "nodes": {"webhook": {"id": "webhook", "type": "webhook_trigger", "config": {"path": "/in"}},
                      "sink": {"id": "sink", "type": "send_email", "config": {}}},
            "edges": [{"source": "webhook", "target": "sink", "arg_mapping": {"to": "payload", "body": "payload"}}]}


@pytest.mark.asyncio
async def test_channels_rules_alerts_api(tmp_path, monkeypatch, stand, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("AGENTOS_API_TOKEN", TOKEN)
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    from agentos_server.app import create_app

    app = create_app(project_path=str(tmp_path))
    app.state.notify.slack = SlackSender(_test_endpoint=stand, _test_allowlist=["127.0.0.1"])
    hdr = {"Authorization": f"Bearer {TOKEN}", "Host": "localhost"}
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost", headers=hdr) as c:
            # default rules exist, with no channel
            rules = (await c.get("/api/v2/alerts/rules")).json()["rules"]
            assert len(rules) == 6 and all(r["channels"] == [] for r in rules)

            # email: TLS rules and SSRF at save time
            bad = await c.post("/api/v2/notify/channels", json={"type": "email", "name": "m1", "host": "127.0.0.1",
                                                                "security": "none", "from_address": "a@corp.local"})
            assert bad.status_code == 400 and "plaintext" in bad.json()["detail"]
            meta = await c.post("/api/v2/notify/channels", json={"type": "email", "name": "m2",
                                                                 "host": "169.254.169.254", "from_address": "a@corp.local"})
            assert meta.status_code == 400 and "blocked address" in meta.json()["detail"]
            ok = await c.post("/api/v2/notify/channels", json={
                "type": "email", "name": "mail", "host": "127.0.0.1", "port": 2525, "security": "none",
                "allow_insecure_local": True, "username": "agentos", "password": SMTP_PASSWORD,
                "from_address": "agentos@corp.local", "alert_recipients": ["ops@corp.local"], "use_for_flows": True})
            assert ok.status_code == 201, ok.text
            body = ok.json()
            assert body["password_set"] is True and body["password_secret"] == "notify.smtp.mail"
            assert "password" not in body and await app.state.vault.reveal("notify.smtp.mail") == SMTP_PASSWORD
            assert (await c.post("/api/v2/notify/channels", json={**body, "password": "x"})).status_code == 409
            second = await c.post("/api/v2/notify/channels", json={
                "type": "email", "name": "mail2", "host": "127.0.0.1", "security": "none", "allow_insecure_local": True,
                "from_address": "b@corp.local", "use_for_flows": True})
            assert second.status_code == 400 and "already used for flows" in second.json()["detail"]

            # slack: host pinned, webhook write-only
            evil = await c.post("/api/v2/notify/channels", json={"type": "slack", "name": "ops",
                                                                 "webhook_url": "https://evil.example/services/T/B/X"})
            assert evil.status_code == 400 and "hooks.slack.com" in evil.json()["detail"]
            s = await c.post("/api/v2/notify/channels", json={"type": "slack", "name": "ops", "webhook_url": SLACK_URL,
                                                              "display_channel": "#ops", "internal": True})
            assert s.status_code == 201 and s.json()["webhook_set"] is True
            assert app.state.security_policy.slack_channels == {"ops": True}
            # update keeps the stored secret
            up = await c.put("/api/v2/notify/channels/ops", json={"display_channel": "#ops-2", "internal": False})
            assert up.status_code == 200 and up.json()["webhook_set"] and up.json()["display_channel"] == "#ops-2"
            assert app.state.security_policy.slack_channels == {"ops": False}

            # test button (audited; AgentOS-written result)
            t = await c.post("/api/v2/notify/channels/ops/test")
            assert t.json() == {"ok": True} and len(_Stand.posts) == 1
            t2 = await c.post("/api/v2/notify/channels/mail/test")  # nothing listens on 2525
            assert t2.json() == {"ok": False, "error": "could not connect to the SMTP server"}

            # rules: channels must exist; audited
            assert (await c.put("/api/v2/alerts/rules/run_failed", json={"channels": ["nope"]})).status_code == 400
            assert (await c.put("/api/v2/alerts/rules/nope", json={})).status_code == 404
            r = await c.put("/api/v2/alerts/rules/attack_blocked", json={"channels": ["ops"], "cooldown_min": 5})
            assert r.status_code == 200 and r.json()["channels"] == ["ops"]

            # publish refused -> attack_blocked alert, delivered to Slack by the worker
            assert (await c.post("/api/v2/flows", json=_unsafe_flow("unsafe_flow"))).status_code == 201
            assert (await c.post("/api/v2/flows/unsafe_flow/publish", json={"note": "test publish"})).status_code == 400
            await app.state.notify.process_due()
            alerts = (await c.get("/api/v2/alerts")).json()
            [a] = [x for x in alerts["alerts"] if x["rule"] == "attack_blocked"]
            assert a["target"] == "unsafe_flow" and a["status"] == "sent" and alerts["unacknowledged"] >= 1
            assert any("Attack blocked" in p["text"] for p in _Stand.posts)
            ov = (await c.get("/api/v2/overview")).json()
            assert ov["needs_you"]["unacknowledged_alerts"] == alerts["unacknowledged"]
            assert (await c.get("/api/v2/alerts", params={"rule": "attack_blocked", "status": "sent"})).json()["alerts"]
            ack = await c.post(f"/api/v2/alerts/{a['id']}/acknowledge")
            assert ack.status_code == 200 and ack.json()["acknowledged"] is True
            assert (await c.post("/api/v2/alerts/al_missing/acknowledge")).status_code == 404

            # audit entries for every change, metadata only
            entries = await app.state.audit.entries()
            actions = [e["action"] for e in entries]
            for act in ("notify.channel.create", "notify.channel.update", "notify.channel.test",
                        "notify.channel.test_result", "alert.rule.update", "alert.acknowledge"):
                assert act in actions, act

            # delete removes the channel from rules and its vault secret
            d = await c.delete("/api/v2/notify/channels/ops")
            assert d.status_code == 200
            assert all("ops" not in r["channels"] for r in (await c.get("/api/v2/alerts/rules")).json()["rules"])
            listed = (await c.get("/api/v2/notify/channels")).json()

            # fail closed: the audit store is not writable -> 503 and nothing changes
            store = app.state.audit.store
            shutil.rmtree(store.dir)
            store.dir.mkdir()
            store.path.mkdir()
            store._loaded = False
            r503 = await c.post("/api/v2/notify/channels", json={"type": "slack", "name": "late", "webhook_url": SLACK_URL})
            assert r503.status_code == 503
            assert [ch["name"] for ch in (await c.get("/api/v2/notify/channels")).json()["channels"]] == ["mail"]

        # no secret value in any response, audit entry or log line
        everything = json.dumps([body, s.json(), up.json(), listed, entries]) + caplog.text
        assert SMTP_PASSWORD not in everything and SLACK_URL not in everything and "s" * 24 not in everything

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                               headers={"Host": "localhost"}) as anon:
            assert (await anon.get("/api/v2/notify/channels")).status_code == 401
            assert (await anon.get("/api/v2/alerts")).status_code == 401
