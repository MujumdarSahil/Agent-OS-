"""3.3 notifications and alerts (MOCK models; real SMTP conversations with a LOCAL aiosmtpd server on 127.0.0.1;
a local plain-HTTP Slack stand-in reached only through the Slack sender's test-only constructor arguments).

Email: real delivery to the fixture through a flow; header injection / size / recipient / From refused before any
intent; TLS required unless allow_insecure_local (STARTTLS missing -> refused; certificate verified); SMTP host SSRF
refused; Message-ID stable; crash between intent and commit -> needs review, never resent (direct node and agent tool).
Slack: escaping; host pinned to hooks.slack.com; channel must be configured; untrusted text only to an internal
channel. Alerts: every rule type fires once; cooldown; outbox retries, dead letter, no double send after restart;
untrusted text never appears in an alert or a notification (canary); no secret value anywhere.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import socket
import ssl
import threading
from email import message_from_bytes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace as NS

import pytest
import pytest_asyncio

from agentos.flows.engine import FlowEngine
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy
from agentos.flows.rules import SinkArgumentRejected
from agentos.flows.specs import BUILTIN_NODE_SPECS, SideEffectClass
from agentos.flows.state import RunStatus
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.notify.channels import (
    ChannelError,
    EmailChannel,
    SlackChannel,
    build_message,
    check_slack_webhook_url,
    escape_slack,
    message_id,
    validate_email_args,
)
from agentos.notify.senders import DeliveryError, SlackSender
from agentos.notify.service import (
    ChannelEmailTransport,
    ChannelSlackTransport,
    NotifyService,
    ObservedEvents,
)
from agentos.notify.store import notify_store_for
from agentos.storage import open_storage

aiosmtpd = pytest.importorskip("aiosmtpd")
from aiosmtpd.controller import Controller  # noqa: E402
from aiosmtpd.smtp import AuthResult  # noqa: E402

CANARY = "ZZCANARYZZ"
SMTP_PASSWORD = "pw-" + "x7" * 8  # synthetic test credential (never a real secret)
SLACK_URL = "https://hooks.slack.com/services/T000/B000/" + "t" * 24  # synthetic


# ------------------------------------------------------------------------------------------------ fixtures

class FakeVault:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def put(self, name, secret, provider=None):
        self.data[name] = secret

    async def reveal(self, name):
        return self.data[name]

    async def delete(self, name):
        return self.data.pop(name, None) is not None

    async def list(self):
        return [NS(name=n) for n in self.data]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Handler:
    def __init__(self) -> None:
        self.messages: list[NS] = []
        self.refuse_rcpt = False

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # noqa: N802
        if self.refuse_rcpt:
            return f"550 {CANARY} mailbox unavailable"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):  # noqa: N802
        self.messages.append(NS(mail_from=envelope.mail_from, rcpt=list(envelope.rcpt_tos),
                                msg=message_from_bytes(envelope.original_content or envelope.content)))
        return "250 Message accepted"


def _auth(server, session, envelope, mechanism, auth_data):
    ok = auth_data.login == b"agentos" and auth_data.password == SMTP_PASSWORD.encode()
    return AuthResult(success=ok)


@pytest.fixture
def smtp_plain():
    """Plaintext local SMTP (no STARTTLS), AUTH allowed without TLS: only for allow_insecure_local channels."""
    h = _Handler()
    port = _free_port()
    c = Controller(h, hostname="127.0.0.1", port=port, authenticator=_auth, auth_require_tls=False)
    c.start()
    yield NS(handler=h, port=port)
    c.stop()


def _test_ca(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_p, key_p = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    return cert_p, key_p


@pytest.fixture
def smtp_tls(tmp_path):
    """STARTTLS-capable local SMTP with a self-signed certificate for 'localhost' (a test CA)."""
    cert_p, key_p = _test_ca(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(str(cert_p), str(key_p))
    h = _Handler()
    port = _free_port()
    c = Controller(h, hostname="127.0.0.1", port=port, tls_context=server_ctx, require_starttls=True)
    c.start()
    client_ctx = ssl.create_default_context(cafile=str(cert_p))  # trusts ONLY the test CA
    yield NS(handler=h, port=port, client_ctx=client_ctx)
    c.stop()


class _SlackStandIn(BaseHTTPRequestHandler):
    posts: list = []
    status = 200

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).posts.append(json.loads(body))
        self.send_response(type(self).status)
        self.end_headers()
        self.wfile.write(f"server says {CANARY}".encode())


@pytest.fixture
def slack():
    _SlackStandIn.posts = []
    _SlackStandIn.status = 200
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SlackStandIn)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield NS(url=f"http://127.0.0.1:{srv.server_address[1]}/hook", posts=_SlackStandIn.posts, cls=_SlackStandIn)
    srv.shutdown()
    srv.server_close()
    t.join(timeout=5)


@pytest_asyncio.fixture
async def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    storage = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    clock = NS(t=1_800_000_000.0)
    yield NS(storage=storage, tmp=tmp_path, clock=clock, vault=FakeVault())
    await storage.close()


def make_service(env, *, slack=None, smtp_allowlist=(), ssl_context=None, policy=None, resolver=None):
    sender = SlackSender(_test_endpoint=slack.url, _test_allowlist=["127.0.0.1"]) if slack else SlackSender()
    return NotifyService(notify_store_for(env.storage), env.vault, storage=env.storage,
                         smtp_allowlist=smtp_allowlist, clock=lambda: env.clock.t, slack_sender=sender,
                         ssl_context=ssl_context, policy=policy or SecurityPolicy(), smtp_resolver=resolver)


def email_ch(port, **kw):
    base = dict(name="mail", host="127.0.0.1", port=port, security="none", allow_insecure_local=True,
                from_address="agentos@corp.local", alert_recipients=["ops@corp.local"], use_for_flows=True)
    return EmailChannel(**{**base, **kw})


def email_flow(fid="mail_flow", pinned=None, mapping=None) -> FlowDefinition:
    nodes = {"trig": NodeDefinition(id="trig", type="manual_trigger"),
             "mail": NodeDefinition(id="mail", type="send_email", pinned_args=pinned or {})}
    edges = [EdgeDefinition(source="trig", target="mail", arg_mapping=mapping or {})]
    return FlowDefinition(id=fid, entrypoint="trig", nodes=nodes, edges=edges)


def slack_flow(pinned, mapping=None) -> FlowDefinition:
    nodes = {"trig": NodeDefinition(id="trig", type="manual_trigger"),
             "post": NodeDefinition(id="post", type="send_slack", pinned_args=pinned)}
    return FlowDefinition(id="slack_flow", entrypoint="trig", nodes=nodes,
                          edges=[EdgeDefinition(source="trig", target="post", arg_mapping=mapping or {})])


async def evs(storage, run_id, type_=None):
    return [e for e in await storage.events.list(run_id, after_seq=0) if type_ is None or e.type == type_]


# ------------------------------------------------------------------------------------------------ email

@pytest.mark.asyncio
async def test_real_email_delivered_from_a_flow_with_fixed_from_and_stable_message_id(env, smtp_plain):
    svc = make_service(env)
    await svc.save_channel(email_ch(smtp_plain.port, username="agentos"), secret_value=SMTP_PASSWORD)
    flow = email_flow(pinned={"to": "alice@corp.local", "subject": "Weekly", "body": "Hello from AgentOS"})
    st = await FlowEngine(flow, env.storage, transport_registry={"send_email": ChannelEmailTransport(svc)}).run(
        run_id="r_mail", inputs={})
    assert st.status == RunStatus.SUCCEEDED
    [m] = smtp_plain.handler.messages
    assert m.rcpt == ["alice@corp.local"] and m.mail_from == "agentos@corp.local"
    assert m.msg["From"] == "agentos@corp.local" and m.msg["Subject"] == "Weekly"
    assert m.msg.get_payload(decode=True).decode().strip() == "Hello from AgentOS"
    key = (await evs(env.storage, "r_mail", "sink_intent"))[0].data["idempotency_key"]
    assert m.msg["Message-ID"] == message_id(key)
    commit = (await evs(env.storage, "r_mail", "sink_committed"))[0].data["result"]
    assert commit["status"] == "sent" and commit["message_id"] == message_id(key)
    # the password never appears in events
    assert SMTP_PASSWORD not in json.dumps([e.data for e in await evs(env.storage, "r_mail")])


def test_message_id_is_derived_from_the_idempotency_key():
    ch = EmailChannel(name="m", host="smtp.example.com", from_address="a@corp.local")
    a = build_message(ch, ["b@corp.local"], "s", "x", "run:node:5")["Message-ID"]
    assert a == build_message(ch, ["b@corp.local"], "other", "y", "run:node:5")["Message-ID"] == message_id("run:node:5")
    assert a != message_id("run:node:6") and a.endswith("@agentos.invalid>")


@pytest.mark.asyncio
async def test_without_an_email_channel_send_email_is_simulated_and_says_so(env):
    svc = make_service(env)
    flow = email_flow(pinned={"to": "alice@corp.local", "body": "hi"})
    st = await FlowEngine(flow, env.storage, transport_registry={"send_email": ChannelEmailTransport(svc)}).run(
        run_id="r_sim", inputs={})
    assert st.status == RunStatus.SUCCEEDED
    res = (await evs(env.storage, "r_sim", "sink_committed"))[0].data["result"]
    assert res["status"] == "simulated" and res["reason"] == "simulated: no email channel configured"


@pytest.mark.asyncio
async def test_simulated_send_still_refuses_injection_and_reports_invalid_arguments(env):
    """No channel: a non-address recipient (e.g. a whole mapped payload) is simulated and SAYS a real channel would
    refuse it; header injection and a From override are refused even when only simulated."""
    t = ChannelEmailTransport(make_service(env))
    await t.avalidate({"to": {"to": "a@corp.local"}, "body": "b"})
    res = await t.asend("k", to={"to": "a@corp.local"}, body="b")
    assert res["status"] == "simulated" and res["reason"].endswith("a real email channel would refuse these arguments")
    for bad in ({"to": "a@corp.local", "subject": "x\r\nBcc: e@evil.com", "body": "b"},
                {"to": "a@corp.local", "body": "b", "from": "ceo@corp.local"}):
        with pytest.raises(SinkArgumentRejected):
            await t.avalidate(bad)
        with pytest.raises(SinkArgumentRejected):
            await t.asend("k2", **bad)


@pytest.mark.parametrize("args,match", [
    ({"to": "a@corp.local", "subject": "hi\r\nBcc: evil@x.com", "body": "b"}, "control characters"),
    ({"to": "a@corp.local\r\nBcc: evil@x.com", "body": "b"}, "control characters"),
    ({"to": "a@corp.local", "subject": "x y", "body": "b"}, "control characters"),
    ({"to": [f"u{i}@corp.local" for i in range(21)], "body": "b"}, "at most 20"),
    ({"to": "a@corp.local", "subject": "s" * 201, "body": "b"}, "longer than 200"),
    ({"to": "a@corp.local", "body": "b" * 100_001}, "larger than 100 KB"),
    ({"to": "a@corp.local", "body": "b", "from": "ceo@corp.local"}, "From is fixed"),
    ({"to": "a@corp.local", "body": "b", "bcc": "x@evil.com"}, "cannot be set by a flow"),
    ({"to": "Alice <a@corp.local>", "body": "b"}, "Display-name"),
    ({"to": "a@corp.local,b@evil.com", "body": "b"}, "Comma-joined"),
])
def test_email_hardening(args, match):
    with pytest.raises(SinkArgumentRejected, match=match):
        validate_email_args(args, None)


def test_allowed_recipient_domains():
    ch = EmailChannel(name="m", host="smtp.example.com", from_address="a@corp.local",
                      allowed_recipient_domains=["corp.local"])
    validate_email_args({"to": "x@corp.local", "body": "b"}, ch)
    with pytest.raises(SinkArgumentRejected, match="outside"):
        validate_email_args({"to": ["x@corp.local", "y@other.com"], "body": "b"}, ch)


@pytest.mark.asyncio
async def test_header_injection_through_a_flow_is_refused_before_any_intent(env, smtp_plain):
    svc = make_service(env)
    await svc.save_channel(email_ch(smtp_plain.port))
    flow = email_flow(pinned={"to": "alice@corp.local", "body": "b", "subject": "x\r\nBcc: evil@evil.com"})
    st = await FlowEngine(flow, env.storage, transport_registry={"send_email": ChannelEmailTransport(svc)}).run(
        run_id="r_inj", inputs={})
    assert st.status == RunStatus.FAILED
    assert not await evs(env.storage, "r_inj", "sink_intent") and smtp_plain.handler.messages == []
    failed = (await evs(env.storage, "r_inj", "node_failed"))[0].data
    assert failed["error_type"] == "SinkArgumentRejected"


@pytest.mark.asyncio
async def test_tls_rules(env, smtp_plain, smtp_tls):
    # config: plaintext only for a local host with the explicit flag
    with pytest.raises(ChannelError, match="plaintext"):
        EmailChannel(name="m", host="127.0.0.1", security="none", from_address="a@corp.local").check_config()
    with pytest.raises(ChannelError, match="only for a local"):
        EmailChannel(name="m", host="smtp.example.com", security="none", allow_insecure_local=True,
                     from_address="a@corp.local").check_config()
    resolver = lambda h, p: ["127.0.0.1"]  # noqa: E731
    # STARTTLS required: a server that does not offer it -> refused (no plaintext fallback)
    svc = make_service(env, smtp_allowlist=["127.0.0.1"], resolver=resolver)
    ch = email_ch(smtp_plain.port, host="localhost", security="starttls", allow_insecure_local=False)
    with pytest.raises(DeliveryError, match="does not offer STARTTLS"):
        await svc.send_email(ch, ["a@corp.local"], "s", "b", "k1")
    assert smtp_plain.handler.messages == []
    # certificate verification is ON: the system trust store does not trust the test CA
    ch_tls = email_ch(smtp_tls.port, host="localhost", security="starttls", allow_insecure_local=False)
    with pytest.raises(DeliveryError, match="certificate verification failed"):
        await svc.send_email(ch_tls, ["a@corp.local"], "s", "b", "k2")
    # with the test CA trusted, STARTTLS + hostname check succeed and the message is delivered
    ok = make_service(env, smtp_allowlist=["127.0.0.1"], resolver=resolver, ssl_context=smtp_tls.client_ctx)
    assert (await ok.send_email(ch_tls, ["a@corp.local"], "s", "b", "k3"))["status"] == "sent"
    assert len(smtp_tls.handler.messages) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("ip,reason", [("10.1.2.3", "private"), ("169.254.169.254", "cloud metadata"),
                                       ("127.0.0.1", "loopback"), ("100.64.0.1", "CGNAT")])
async def test_smtp_host_ssrf_refused(env, ip, reason):
    svc = make_service(env, resolver=lambda h, p: [ip])
    ch = EmailChannel(name="m", host="relay.example.com", from_address="a@corp.local")
    with pytest.raises(DeliveryError, match=reason):
        await svc.send_email(ch, ["a@corp.local"], "s", "b", "k")
    with pytest.raises(ChannelError, match="blocked address"):
        await svc.check_channel(ch)
    # an internal relay passes only when the admin allowlists it (not for cloud metadata via another name)
    allowed = make_service(env, resolver=lambda h, p: [ip], smtp_allowlist=["relay.example.com"])
    await allowed.check_channel(ch)


@pytest.mark.asyncio
async def test_crash_between_intent_and_commit_needs_review_and_is_never_resent(env, smtp_plain):
    svc = make_service(env)
    await svc.save_channel(email_ch(smtp_plain.port))

    class CrashAfterSend(ChannelEmailTransport):
        async def asend(self, idempotency_key, **args):
            await super().asend(idempotency_key, **args)
            raise RuntimeError("process killed after the SMTP server accepted the message")

    flow = email_flow(pinned={"to": "alice@corp.local", "body": "once"})
    await FlowEngine(flow, env.storage, transport_registry={"send_email": CrashAfterSend(svc)}).run(
        run_id="r_crash", inputs={})
    assert len(smtp_plain.handler.messages) == 1
    assert await evs(env.storage, "r_crash", "sink_intent") and not await evs(env.storage, "r_crash", "sink_committed")
    st = await FlowEngine(flow, env.storage, transport_registry={"send_email": ChannelEmailTransport(svc)}).resume(
        "r_crash")
    assert st.status == RunStatus.WAITING
    assert (await evs(env.storage, "r_crash", "run_waiting"))[-1].data["reason"] == "uncommitted_sink_needs_review"
    assert len(smtp_plain.handler.messages) == 1  # not resent

    # agent tool path: an intent without a commit for the same call -> refused, not resent
    import hashlib

    args = {"to": "alice@corp.local", "body": "agent once"}
    key = hashlib.sha256(f"r_agent:agent1:send_email:{json.dumps(args, sort_keys=True, separators=(',', ':'))}"
                         .encode()).hexdigest()
    await env.storage.events.append(run_id="r_agent", type="sink_intent",
                                    data={"sink_node": "agent1", "tool_name": "send_email", "idempotency_key": key,
                                          "args": args})
    proxy = AgentOSToolProxy(run_id="r_agent", agent_node_id="agent1", storage=env.storage,
                             policy=SecurityPolicy(internal_domains={"corp.local"}),
                             transport_registry={"send_email": ChannelEmailTransport(svc)},
                             loop=asyncio.get_running_loop())
    with pytest.raises(ValueError, match="uncommitted_sink_needs_review"):
        await proxy.invoke("agent1", "send_email", args)
    assert len(smtp_plain.handler.messages) == 1
    assert await evs(env.storage, "r_agent", "sink_needs_review")


@pytest.mark.asyncio
async def test_server_error_text_is_never_echoed(env, smtp_plain):
    svc = make_service(env)
    await svc.save_channel(email_ch(smtp_plain.port))
    smtp_plain.handler.refuse_rcpt = True
    res = await svc.test_channel("mail")
    assert res == {"ok": False, "error": "the SMTP server refused the recipient(s)"}


# ------------------------------------------------------------------------------------------------ Slack

def test_slack_escaping():
    out = escape_slack("hi @channel @HERE @everyone <!channel> <https://evil.example|click me> & <@U123>")
    assert "<" not in out and ">" not in out and "&lt;!channel&gt;" in out
    assert "&lt;https://evil.example|click me&gt;" in out and "&amp;" in out
    assert "@channel" not in out and "@​channel" in out and "@​HERE" in out and "@​everyone" in out


@pytest.mark.parametrize("url", [
    "https://evil.example/services/T/B/X", "http://hooks.slack.com/services/T/B/X",
    "https://hooks.slack.com.evil.example/services/T/B/X", "https://hooks.slack.com:8443/services/T/B/X",
    "https://user:pw@hooks.slack.com/services/T/B/X", "https://hooks.slack.com/api/other",
])
def test_slack_host_is_pinned(url):
    with pytest.raises(ChannelError):
        check_slack_webhook_url(url)


@pytest.mark.asyncio
async def test_slack_send_through_a_flow_escaped_and_unfurl_off(env, slack):
    policy = SecurityPolicy()
    svc = make_service(env, slack=slack, policy=policy)
    await svc.save_channel(SlackChannel(name="ops", display_channel="#ops", internal=True), secret_value=SLACK_URL)
    assert policy.slack_channels == {"ops": True}
    flow = slack_flow({"channel": "ops"}, mapping={"text": "payload"})  # text from the (untrusted) run input
    st = await FlowEngine(flow, env.storage, policy=policy,
                          transport_registry={"send_slack": ChannelSlackTransport(svc)}).run(
        run_id="r_slack", inputs={"payload": "alert <!channel> @here see <https://x.example|this>"})
    assert st.status == RunStatus.SUCCEEDED
    [p] = slack.posts
    assert p["unfurl_links"] is False and p["unfurl_media"] is False
    assert "<" not in p["text"] and "@​here" in p["text"]
    assert SLACK_URL not in json.dumps([e.data for e in await evs(env.storage, "r_slack")])


@pytest.mark.asyncio
async def test_slack_rules_channel_configured_and_untrusted_text_only_to_internal(env, slack):
    policy = SecurityPolicy()
    svc = make_service(env, slack=slack, policy=policy)
    await svc.save_channel(SlackChannel(name="public", internal=False), secret_value=SLACK_URL)
    reg = {"send_slack": ChannelSlackTransport(svc)}
    # untrusted text to a channel that is not internal: refused at publish and at runtime
    flow = slack_flow({"channel": "public"}, mapping={"text": "payload"})
    assert not StaticFlowAnalyzer(flow, policy).verify().is_valid
    st = await FlowEngine(flow, env.storage, policy=policy, transport_registry=reg).run(run_id="r_s1",
                                                                                       inputs={"payload": "x"})
    assert st.status == RunStatus.FAILED and slack.posts == []
    # unknown channel: refused (never simulated)
    unknown = slack_flow({"channel": "nope", "text": "fixed text"})
    res = StaticFlowAnalyzer(unknown, policy).verify()
    assert not res.is_valid and "not a configured Slack" in res.violations[0].reason
    st2 = await FlowEngine(unknown, env.storage, policy=policy, transport_registry=reg).run(run_id="r_s2", inputs={})
    assert st2.status == RunStatus.FAILED and slack.posts == []
    # channel chosen by untrusted input: refused
    chosen = slack_flow({"text": "fixed"}, mapping={"channel": "payload"})
    assert not StaticFlowAnalyzer(chosen, policy).verify().is_valid
    # trusted (pinned) text to a non-internal channel: allowed
    ok = slack_flow({"channel": "public", "text": "deploy finished"})
    assert StaticFlowAnalyzer(ok, policy).verify().is_valid
    st3 = await FlowEngine(ok, env.storage, policy=policy, transport_registry=reg).run(run_id="r_s3", inputs={})
    assert st3.status == RunStatus.SUCCEEDED and len(slack.posts) == 1


def test_send_slack_node_spec_contract():
    spec = BUILTIN_NODE_SPECS["send_slack"]
    assert spec.side_effect == SideEffectClass.EXTERNAL_SEND and spec.recipient_arg == "channel"
    assert spec.sink_rules["channel"].required_integrity == "trusted"
    assert spec.sink_rules["channel"].condition == "slack_channel_configured"
    assert spec.sink_rules["text"].condition == "text_internal_channel_only"
    assert set(spec.input_schema["required"]) == {"channel", "text"}


@pytest.mark.asyncio
async def test_slack_tampered_webhook_is_refused_at_send(env, slack):
    svc = make_service(env, slack=slack)
    await svc.save_channel(SlackChannel(name="ops"), secret_value=SLACK_URL)
    env.vault.data["notify.slack.ops"] = "https://evil.example/services/T/B/X"  # tampered after save
    with pytest.raises(DeliveryError, match="hooks.slack.com"):
        await svc.send_slack(await svc.channel("ops"), "x")
    assert slack.posts == []
    env.vault.data["notify.slack.ops"] = SLACK_URL
    slack.cls.status = 500
    res = await svc.test_channel("ops")
    assert res == {"ok": False, "error": "Slack answered HTTP 500"} and CANARY not in json.dumps(res)


# ------------------------------------------------------------------------------------------------ alerts

def ev(run_id, type_, data, seq=1):
    return NS(run_id=run_id, type=type_, data=data, seq=seq, ts=dt.datetime.now(dt.timezone.utc))


async def _with_rule_channels(svc, *channels):
    for r in await svc.rules():
        await svc.put_rule(r.model_copy(update={"channels": list(channels)}))


@pytest.mark.asyncio
async def test_defaults_have_no_channel_and_alerts_are_recorded_as_no_channel(env):
    svc = make_service(env)
    await svc.ensure_default_rules()
    rules = await svc.rules()
    assert {r.id for r in rules} == {"attack_blocked", "run_failed", "approval_waiting", "provider_down",
                                     "budget_exceeded", "audit_broken"}
    assert all(r.channels == [] and r.enabled and r.cooldown_min == 15 for r in rules)
    await svc.on_event(ev("r1", "tool_call_blocked", {"reason": "x"}))
    [a] = await svc.alerts_view()
    assert a["status"] == "no_channel" and await svc.store.outbox.list() == []


@pytest.mark.asyncio
async def test_every_rule_type_fires_once_for_its_event(env):
    svc = make_service(env)
    await svc.ensure_default_rules()
    await env.storage.events.append(run_id="r_fail", type="node_failed",
                                    data={"node_id": "n", "error": "boom", "error_type": "ValueError"})
    await svc.on_event(ev("r_att", "node_failed", {"node_id": "n", "error": "[n:to] x",
                                                   "error_type": "SinkRuleViolationError"}))
    await svc.on_event(ev("r_fail", "run_failed", {"error": "boom"}))
    await svc.on_event(ev("r_prov", "llm_call", {"status": "failed", "attempts": [
        {"provider": "groq_llama3_3", "error_class": "Timeout"},
        {"provider": "openrouter_x", "error_class": "skipped (cooldown)"}]}))
    await svc.on_event(ev("r_bud", "budget_exceeded", {"budget": "global_daily", "limit_usd": 1}))
    await svc.on_audit_verify({"status": "broken", "reason": "audit anchor missing"})
    await svc.on_publish_refused("flow_x", 2)
    await svc.on_event(ev("r_wait", "node_waiting", {"node_id": "appr", "prompt": "ok?"}))
    await env.storage.events.append(run_id="r_wait", type="node_waiting", data={"node_id": "appr"})
    env.clock.t += 31 * 60
    assert await svc.process_timers(now=dt.datetime.now(dt.timezone.utc).timestamp() + 31 * 60) == 1
    by = {}
    for a in await svc.alerts_view():
        by.setdefault(a["rule"], []).append(a)
    assert sorted(by) == ["approval_waiting", "attack_blocked", "audit_broken", "budget_exceeded",
                          "provider_down", "run_failed"]
    assert len(by["attack_blocked"]) == 2  # sink rule violation + publish refused
    assert {a["target"] for a in by["provider_down"]} == {"all_providers", "openrouter_x"}
    assert by["run_failed"][0]["reason"] == "the run failed (ValueError)"
    assert by["audit_broken"][0]["reason"] == "audit log verification: audit anchor missing"
    assert all(len(v) == 1 for k, v in by.items() if k not in ("attack_blocked", "provider_down"))


@pytest.mark.asyncio
async def test_approval_answered_in_time_does_not_alert(env):
    svc = make_service(env)
    await env.storage.events.append(run_id="r_ok", type="node_waiting", data={"node_id": "appr"})
    await env.storage.events.append(run_id="r_ok", type="approval_decision", data={"node_id": "appr"})
    svc.schedule_approval_check(0, "r_ok", "appr")
    assert await svc.process_timers(now=1) == 0 and await svc.alerts_view() == []


@pytest.mark.asyncio
async def test_cooldown_per_rule_and_target(env, slack):
    svc = make_service(env, slack=slack)
    await svc.save_channel(SlackChannel(name="ops"), secret_value=SLACK_URL)
    await _with_rule_channels(svc, "ops")
    for _ in range(3):
        await svc.on_event(ev("r1", "tool_call_blocked", {}))
    await svc.on_event(ev("r2", "budget_exceeded", {"budget": "global_daily"}))  # other rule: own alert
    [a] = [x for x in await svc.alerts_view() if x["rule"] == "attack_blocked"]
    assert a["count"] == 3 and len(await svc.store.outbox.list()) == 2
    await svc.process_due()
    assert len(slack.posts) == 2
    env.clock.t += 16 * 60  # cooldown over: a new alert and a new send
    await svc.on_event(ev("r1", "tool_call_blocked", {}))
    await svc.process_due()
    assert len([x for x in await svc.alerts_view() if x["rule"] == "attack_blocked"]) == 2 and len(slack.posts) == 3


@pytest.mark.asyncio
async def test_outbox_retries_with_backoff_then_dead_letter(env, slack):
    svc = make_service(env, slack=slack)
    await svc.save_channel(SlackChannel(name="ops"), secret_value=SLACK_URL)
    await _with_rule_channels(svc, "ops")
    slack.cls.status = 503
    await svc.on_event(ev("r1", "tool_call_blocked", {}))
    waits = []
    for _ in range(5):
        await svc.process_due()
        [e] = await svc.store.outbox.list()
        if e["status"] == "retrying":
            waits.append(e["next_ts"] - env.clock.t)
            env.clock.t = e["next_ts"]
    assert waits == [30.0, 60.0, 120.0, 240.0]
    [e] = await svc.store.outbox.list()
    assert e["status"] == "failed" and e["attempts"] == 5 and "dead letter" in e["error"]
    assert (await svc.alerts_view())[0]["status"] == "failed" and len(slack.posts) == 5
    # a retry that succeeds
    slack.cls.status = 200
    env.clock.t += 3600
    await svc.on_event(ev("r9", "run_limit_exceeded", {"limit": "calls", "used": 50, "max": 50}))
    await svc.process_due()
    assert (await svc.alerts_view(rule="budget_exceeded"))[0]["status"] == "sent"


@pytest.mark.asyncio
async def test_no_double_send_after_restart(env, slack):
    svc = make_service(env, slack=slack)
    await svc.save_channel(SlackChannel(name="ops"), secret_value=SLACK_URL)
    await _with_rule_channels(svc, "ops")
    await svc.on_event(ev("r1", "tool_call_blocked", {}))
    await svc.process_due()
    assert len(slack.posts) == 1
    # restart: a new service over the same persistent outbox delivers nothing again
    again = make_service(env, slack=slack)
    assert await again.recover() == 0
    await again.process_due(now=env.clock.t + 10_000)
    assert len(slack.posts) == 1
    # an entry the old process left in "sending" may have been delivered: never resent
    await svc.on_event(ev("r2", "budget_exceeded", {"budget": "global_daily"}))
    [pending] = [e for e in await svc.store.outbox.list() if e["status"] == "pending"]
    await svc.store.outbox.update(pending["id"], lambda d: {**d, "status": "sending"})
    third = make_service(env, slack=slack)
    assert await third.recover() == 1
    await third.process_due(now=env.clock.t + 10_000)
    assert len(slack.posts) == 1
    assert "not resent" in (await third.store.outbox.get(pending["id"]))["error"]


@pytest.mark.asyncio
async def test_untrusted_text_never_reaches_an_alert_or_a_notification(env, slack, smtp_plain):
    """Canary: an attacker controls the run input (recipient and body). The engine's violation text contains the
    attacker's recipient; the alert must not."""
    policy = SecurityPolicy(internal_domains={"corp.local"})
    svc = make_service(env, slack=slack, policy=policy)
    await svc.save_channel(email_ch(smtp_plain.port, use_for_flows=False))
    await svc.save_channel(SlackChannel(name="ops"), secret_value=SLACK_URL)
    await _with_rule_channels(svc, "ops", "mail")
    env.storage.events = ObservedEvents(env.storage.events, svc.on_event)
    flow = email_flow(fid="exfil_flow", mapping={"to": "payload", "body": "payload"})
    payload = {"payload": f"{CANARY}@evil.example"}
    st = await FlowEngine(flow, env.storage, policy=policy,
                          transport_registry={"send_email": ChannelEmailTransport(svc)}).run(
        run_id="r_canary", inputs=payload)
    assert st.status == RunStatus.FAILED
    assert CANARY in json.dumps([e.data for e in await evs(env.storage, "r_canary")])  # the events do hold it
    # synthetic events with the canary in every free-text field
    await svc.on_event(ev("r_canary", "tool_call_rejected", {"tool_name": CANARY, "reason": CANARY,
                                                             "attempted_value": CANARY}))
    await svc.on_event(ev("r_canary", "llm_call", {"status": "failed", "error": CANARY, "attempts": [
        {"provider": f"{CANARY} evil", "error_class": "skipped (cooldown)", "error": CANARY}]}))
    await svc.on_event(ev("r_canary", "budget_exceeded", {"budget": f"{CANARY} <x>", "reason": CANARY}))
    # verify() reasons are AgentOS-written; markup is stripped anyway (only [A-Za-z0-9 _.,:()-] survives)
    await svc.on_audit_verify({"status": "broken", "reason": "audit anchor missing <script>"})
    await svc.process_due()
    alerts = await svc.alerts_view()
    assert {a["rule"] for a in alerts} >= {"attack_blocked", "run_failed", "provider_down", "budget_exceeded",
                                           "audit_broken"}
    stored = json.dumps([alerts, await svc.store.outbox.list()])
    delivered = json.dumps(slack.posts) + "".join(m.msg.as_string() for m in smtp_plain.handler.messages)
    assert slack.posts and smtp_plain.handler.messages
    assert CANARY not in stored and CANARY not in delivered
    assert "<script>" not in stored and "<script>" not in delivered
