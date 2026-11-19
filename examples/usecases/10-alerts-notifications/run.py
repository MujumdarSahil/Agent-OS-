"""
Use case 10: alerts and notifications (sub-milestone 3.3). MOCK: no model is called; "Slack" is a local plain-HTTP
stand-in on 127.0.0.1 reached only through the Slack sender's test-only constructor arguments (the configured
webhook URL is still checked to be https://hooks.slack.com/...). Nothing leaves the machine.

Scenarios
  benign      -> a flow posts a fixed deploy note to the Slack channel "ops": sent once, escaped, unfurling off.
  exfil       -> attacker-controlled input tries to email itself (recipient from the input): the sink rule blocks
                 it, an "Attack blocked" alert goes to the "sec" Slack channel, written by AgentOS from metadata
                 only: the attacker's text (a canary) is in the run's events but NOT in the alert.
  slack-inj   -> untrusted text with "<!channel>", "@here" and "<https://evil|click>" to a channel that is not
                 internal: refused at publish and at runtime. To an internal channel it is sent ESCAPED (no ping,
                 no link).
  host-pin    -> configuring a webhook that is not hooks.slack.com is refused.
  outbox      -> the stand-in answers 503: the alert is "retrying"; when it recovers the alert is "sent"; a
                 restart (new service over the same outbox) sends nothing again.

Run:  python examples/usecases/10-alerts-notifications/run.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from agentos.flows.engine import FlowEngine  # noqa: E402
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition  # noqa: E402
from agentos.flows.policy import SecurityPolicy  # noqa: E402
from agentos.flows.state import RunStatus  # noqa: E402
from agentos.flows.static_analyzer import StaticFlowAnalyzer  # noqa: E402
from agentos.notify.channels import ChannelError, SlackChannel  # noqa: E402
from agentos.notify.senders import SlackSender  # noqa: E402
from agentos.notify.service import (  # noqa: E402
    ChannelEmailTransport, ChannelSlackTransport, NotifyService, ObservedEvents,
)
from agentos.notify.store import notify_store_for  # noqa: E402
from agentos.storage import open_storage  # noqa: E402

CANARY = "UC10-CANARY-7f3a"
WEBHOOK = "https://hooks.slack.com/services/T0000/B0000/" + "u" * 24  # placeholder, never contacted


class MemoryVault:
    """Stand-in for the AgentOS vault (the server uses the real AES-GCM vault)."""

    def __init__(self) -> None:
        self._d: dict[str, str] = {}

    async def put(self, name, secret, provider=None):
        self._d[name] = secret

    async def reveal(self, name):
        return self._d[name]

    async def delete(self, name):
        return self._d.pop(name, None) is not None


class Stand(BaseHTTPRequestHandler):
    posts: list = []
    status = 200

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        type(self).posts.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0))))
        self.send_response(type(self).status)
        self.end_headers()


def flow(fid: str, node: NodeDefinition, mapping: dict[str, str]) -> FlowDefinition:
    return FlowDefinition(id=fid, entrypoint="trig",
                          nodes={"trig": NodeDefinition(id="trig", type="manual_trigger"), node.id: node},
                          edges=[EdgeDefinition(source="trig", target=node.id, arg_mapping=mapping)])


async def _run_usecase_async() -> bool:
    ok = True
    Stand.posts, Stand.status = [], 200
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Stand)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    stand_url = f"http://127.0.0.1:{srv.server_address[1]}/hook"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        (Path(tmp) / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        storage = await open_storage(tmp, backend="file", vault_path=str(Path(tmp) / "vault.json"))
        try:
            policy = SecurityPolicy(internal_domains={"corp.local"})
            vault = MemoryVault()

            def service() -> NotifyService:
                return NotifyService(notify_store_for(storage), vault, storage=storage, policy=policy,
                                     slack_sender=SlackSender(_test_endpoint=stand_url, _test_allowlist=["127.0.0.1"]))

            svc = service()
            await svc.ensure_default_rules()
            await svc.save_channel(SlackChannel(name="ops", display_channel="#ops", internal=False), secret_value=WEBHOOK)
            await svc.save_channel(SlackChannel(name="sec", display_channel="#security", internal=True),
                                   secret_value=WEBHOOK)
            rule = await svc.rule("attack_blocked")
            await svc.put_rule(rule.model_copy(update={"channels": ["sec"]}))
            storage.events = ObservedEvents(storage.events, svc.on_event)
            reg = {"send_email": ChannelEmailTransport(svc), "send_slack": ChannelSlackTransport(svc)}

            # benign
            note = flow("uc10_deploy_note", NodeDefinition(id="post", type="send_slack",
                                                           pinned_args={"channel": "ops", "text": "Deploy 42 finished & healthy"}), {})
            st = await FlowEngine(note, storage, policy=policy, transport_registry=reg).run(run_id="uc10_benign", inputs={})
            p = Stand.posts[-1] if Stand.posts else {}
            passed = (st.status == RunStatus.SUCCEEDED and len(Stand.posts) == 1
                      and p.get("text") == "Deploy 42 finished &amp; healthy" and p.get("unfurl_links") is False)
            print(f"[{'PASS' if passed else 'FAIL'}] benign: status={st.status.value} slack_posts={len(Stand.posts)} "
                  f"text={p.get('text')!r}")
            ok &= passed

            # exfil -> attack alert written from metadata only
            exfil = flow("uc10_exfil", NodeDefinition(id="mail", type="send_email"), {"to": "payload", "body": "payload"})
            st = await FlowEngine(exfil, storage, policy=policy, transport_registry=reg).run(
                run_id="uc10_exfil", inputs=f"{CANARY}@attacker.example")
            await svc.process_due()
            alert = next(iter(await svc.alerts_view(rule="attack_blocked")), None)
            in_events = CANARY in json.dumps([e.data for e in await storage.events.list("uc10_exfil", after_seq=0)])
            sent_text = Stand.posts[-1]["text"] if len(Stand.posts) > 1 else ""
            passed = (st.status == RunStatus.FAILED and alert is not None and alert["status"] == "sent"
                      and "Attack blocked" in sent_text and in_events and CANARY not in json.dumps(alert)
                      and CANARY not in sent_text)
            print(f"[{'PASS' if passed else 'FAIL'}] exfil: run={st.status.value} alert={alert and alert['status']} "
                  f"reason={alert and alert['reason']!r} canary_in_events={in_events} "
                  f"canary_in_alert={CANARY in json.dumps(alert)} canary_in_slack={CANARY in sent_text}")
            ok &= passed

            # slack injection: refused to a non-internal channel; escaped to an internal one
            evil = "urgent <!channel> @here open <https://evil.example|this>"
            to_ops = flow("uc10_inj_ops", NodeDefinition(id="post", type="send_slack", pinned_args={"channel": "ops"}),
                          {"text": "payload"})
            refused_publish = not StaticFlowAnalyzer(to_ops, policy).verify().is_valid
            before = len(Stand.posts)
            st = await FlowEngine(to_ops, storage, policy=policy, transport_registry=reg).run(
                run_id="uc10_inj_ops", inputs=evil)
            refused_runtime = st.status == RunStatus.FAILED
            to_sec = flow("uc10_inj_sec", NodeDefinition(id="post", type="send_slack", pinned_args={"channel": "sec"}),
                          {"text": "payload"})
            st2 = await FlowEngine(to_sec, storage, policy=policy, transport_registry=reg).run(
                run_id="uc10_inj_sec", inputs=evil)
            posted = [x["text"] for x in Stand.posts[before:] if "evil.example" in x["text"]]
            escaped = bool(posted) and "<" not in posted[-1] and "@here" not in posted[-1]
            passed = refused_publish and refused_runtime and st2.status == RunStatus.SUCCEEDED and escaped
            print(f"[{'PASS' if passed else 'FAIL'}] slack-inj: non-internal refused (publish={refused_publish}, "
                  f"runtime={refused_runtime}); internal escaped={escaped} text={posted[-1] if posted else None!r}")
            ok &= passed

            # host pinned
            try:
                await svc.save_channel(SlackChannel(name="x"), secret_value="https://evil.example/services/T/B/X")
                pinned = False
            except ChannelError:
                pinned = True
            print(f"[{'PASS' if pinned else 'FAIL'}] host-pin: non-Slack webhook refused={pinned}")
            ok &= pinned

            # outbox retry and no double send after restart
            t0 = 2_000_000_000.0
            svc.clock = lambda: t0
            Stand.status = 503
            await svc.fire("attack_blocked", "uc10_outbox", reason="a tool call was blocked by a security rule")
            await svc.process_due(now=t0)
            retrying = (await svc.alerts_view(rule="attack_blocked"))[0]["status"] == "retrying"
            Stand.status = 200
            await svc.process_due(now=t0 + 100)
            sent = (await svc.alerts_view(rule="attack_blocked"))[0]["status"] == "sent"
            n = len(Stand.posts)
            restarted = service()
            await restarted.recover()
            await restarted.process_due(now=t0 + 9999)
            passed = retrying and sent and len(Stand.posts) == n
            print(f"[{'PASS' if passed else 'FAIL'}] outbox: retrying_on_503={retrying} sent_after_recovery={sent} "
                  f"resent_after_restart={len(Stand.posts) - n}")
            ok &= passed
        finally:
            await storage.close()
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)
    print(f"\nUse case 10: {'ALL PASS' if ok else 'FAILURES'} (MOCK)")
    return ok


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
