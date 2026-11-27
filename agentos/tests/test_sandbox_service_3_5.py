"""3.5 sandbox service + tool proxy (MOCK: a fake backend; no code is executed in these tests).

Fail closed with no backend (never a host subprocess), backend choice, the Docker argument list (isolation flags,
no host mounts, no socket, payload never in argv), labels (untrusted output, confidentiality join, workspace label
inherited by a later agent node), the per-run sandbox call limit, and settings validation.
"""

from __future__ import annotations

import asyncio
import json
import subprocess

import pytest
import pytest_asyncio

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy
from agentos.flows.rules import SinkRuleViolationError
from agentos.sandbox import SandboxResult, SandboxService, SandboxSettings, SandboxUnavailable
from agentos.sandbox import docker_backend
from agentos.sandbox.models import DEFAULT_IMAGE, SandboxLimits
from agentos.storage import open_storage
from agentos.usage.guard import RunLimitExceeded


class FakeBackend:
    def __init__(self, name, kinds, available=True):
        self.name, self.kinds, self._ok = name, kinds, available
        self.calls = []

    def status(self):
        return {"available": self._ok, "detail": "fake", "kinds": list(self.kinds)}

    def available(self):
        return self._ok

    def run(self, kind, payload, files_in, limits, run_label="", image=""):
        self.calls.append((kind, payload, dict(files_in)))
        files = dict(files_in)
        files["result.txt"] = b"computed"
        return SandboxResult(exit_code=0, stdout=f"ran {kind}", stderr="", files_out=files, backend=self.name,
                             runtime_id="sha256:fake")


def svc(tmp_path, docker=False, wasm=False, mode="auto"):
    s = SandboxService(tmp_path / "data", docker=FakeBackend("docker", ("python", "shell"), docker),
                       wasm=FakeBackend("wasm", ("python",), wasm))
    s._settings = SandboxSettings(backend=mode)
    return s


# ------------------------------------------------------------------ service: backend choice, fail closed

def test_no_backend_refuses_and_runs_nothing(tmp_path, monkeypatch):
    s = svc(tmp_path)
    ran = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: ran.append(a) or (_ for _ in ()).throw(AssertionError))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: ran.append(a) or (_ for _ in ()).throw(AssertionError))
    for kind in ("python", "shell"):
        with pytest.raises(SandboxUnavailable, match="NOT run"):
            s.run(kind, "print('x')")
    assert ran == []  # never a host subprocess
    assert s.available_tools() == []
    assert s.status()["effective"] == {"python": None, "shell": None}


def test_backend_choice(tmp_path):
    assert svc(tmp_path, docker=True, wasm=True).run("python", "x").backend == "docker"
    assert svc(tmp_path, wasm=True).run("python", "x").backend == "wasm"
    with pytest.raises(SandboxUnavailable, match="shell"):
        svc(tmp_path, wasm=True).run("shell", "ls")
    assert svc(tmp_path, docker=True, wasm=True, mode="wasm").run("python", "x").backend == "wasm"
    with pytest.raises(SandboxUnavailable, match="disabled by the admin"):
        svc(tmp_path, docker=True, wasm=True, mode="off").run("python", "x")
    assert svc(tmp_path, wasm=True).available_tools() == ["python_exec", "file_read", "file_write"]
    assert svc(tmp_path, docker=True).available_tools() == ["python_exec", "shell_exec", "file_read", "file_write"]


def test_settings_validation():
    with pytest.raises(ValueError):
        SandboxSettings(images=[{"ref": "python:3.12-slim"}], default_image="python:3.12-slim")  # not pinned
    with pytest.raises(ValueError):
        SandboxSettings(default_image="python@sha256:" + "a" * 64)  # not on the allowlist
    with pytest.raises(ValueError):
        SandboxLimits(timeout_s=0)
    s = SandboxSettings()
    assert s.limits.timeout_s == 30 and s.limits.memory_mb == 512 and s.limits.cpus == 1 and s.limits.pids == 64
    assert s.limits.stdout_kb == 100 and s.limits.stderr_kb == 100 and s.limits.workspace_mb == 50
    assert s.default_image == DEFAULT_IMAGE and "@sha256:" in DEFAULT_IMAGE


# ------------------------------------------------------------------ docker argument list (no daemon needed)

def test_docker_container_args_isolation_flags():
    payload = "import socket; SECRET_PAYLOAD_MARKER"
    args = docker_backend.container_args("agentos-sbx-x", DEFAULT_IMAGE, SandboxLimits(), "run1",
                                         {"kind": "python", "timeout": 30, "out_cap": 1, "err_cap": 1, "in_cap": 1})
    joined = " ".join(args)
    for flag in (["--network", "none"], ["--read-only"], ["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"],
                 ["--user", "65534:65534"], ["--pids-limit", "64"], ["--memory", "512m"], ["--memory-swap", "512m"],
                 ["--cpus", "1"]):
        i = args.index(flag[0])
        assert args[i:i + len(flag)] == flag, flag
    assert "/tmp:rw,size=16m,noexec,nosuid,nodev" in joined
    assert "/workspace:rw,size=50m" in joined
    for forbidden in ("-v", "--volume", "--mount", "--privileged", "docker.sock", "seccomp=unconfined", "--pid",
                      "host", "-e", "--env", "--env-file", "--cap-add", "--device"):
        assert forbidden not in args, forbidden
    assert "docker.sock" not in joined and "unconfined" not in joined
    assert SandboxLimits().memory_mb == 512
    assert payload not in joined  # the code goes in through stdin (tar), never in argv
    assert args[args.index(DEFAULT_IMAGE) - 1] == "python3"  # entrypoint override; image pinned by digest
    spec = json.loads(args[-1])
    assert set(spec) == {"kind", "timeout", "out_cap", "err_cap", "in_cap"}


def test_bootstrap_child_env_is_explicit_and_minimal():
    b = docker_backend.BOOTSTRAP
    assert 'env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"' in b
    assert "os.environ" not in b


def test_wasm_child_env_has_no_host_secrets(monkeypatch):
    from agentos.sandbox.wasm_backend import _child_env

    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-a-real-key-000")
    monkeypatch.setenv("AGENTOS_MASTER_KEY", "not-a-real-master-key")
    env = _child_env()
    assert set(env) <= {"SYSTEMROOT", "WINDIR", "PROCESSOR_ARCHITECTURE"}


# ------------------------------------------------------------------ proxy: labels, events, limits

@pytest_asyncio.fixture
async def storage(tmp_path):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


def proxy(storage, sandbox, node="agent1", label=None, guard=None, run_id="run_sb"):
    return AgentOSToolProxy(run_id=run_id, agent_node_id=node, storage=storage, policy=SecurityPolicy(),
                            agent_input_label=label or Label.trusted(), loop=asyncio.get_running_loop(),
                            sandbox=sandbox, usage_guard=guard)


async def events(storage, type_, run_id="run_sb"):
    return [e.data for e in await storage.events.list(run_id, after_seq=0) if e.type == type_]


@pytest.mark.asyncio
async def test_proxy_refuses_without_sandbox(storage):
    p = proxy(storage, None)
    with pytest.raises(ValueError, match="fail closed"):
        await p.invoke("agent1", "python_exec", {"code": "print(1)"})
    rej = await events(storage, "tool_call_rejected")
    assert rej and rej[0]["tool_name"] == "python_exec"
    assert await events(storage, "sandbox_exec") == []


@pytest.mark.asyncio
async def test_proxy_refuses_with_no_backend(storage, tmp_path):
    p = proxy(storage, svc(tmp_path))
    with pytest.raises(ValueError, match="no sandbox backend"):
        await p.invoke("agent1", "python_exec", {"code": "print(1)"})


@pytest.mark.asyncio
async def test_output_is_untrusted_and_confidentiality_joins_inputs(storage, tmp_path):
    s = svc(tmp_path, wasm=True)
    secret_ctx = Label.trusted(confidentiality=Confidentiality.SECRET.value, sources={"trigger"})
    p = proxy(storage, s, label=secret_ctx)
    out = await p.invoke("agent1", "python_exec", {"code": "print(42)", "files": {"in.csv": "1,2"}})
    assert out.startswith("[sandbox python via wasm: exit code 0")
    ev = (await events(storage, "sandbox_exec"))[0]
    assert ev["label"]["integrity"] == "untrusted" and ev["label"]["confidentiality"] == "secret"
    assert ev["backend"] == "wasm" and ev["runtime_id"] == "sha256:fake" and ev["exit_code"] == 0
    assert ev["files_out"] == {"in.csv": 3, "result.txt": 8}
    assert p.agent_context_label.integrity == "untrusted"
    assert p.agent_context_label.confidentiality == "secret"
    # the code is recorded as a tool argument (shown in the run panel as an untrusted value)
    called = (await events(storage, "tool_called"))[0]
    assert called["args"]["code"] == "print(42)"
    # secret in -> secret out: sending the result to an external sink is blocked by the existing rules
    with pytest.raises(SinkRuleViolationError):
        await p.invoke("agent1", "send_email", {"to": "x@example.com", "body": out})


@pytest.mark.asyncio
async def test_workspace_label_is_inherited_by_a_later_agent(storage, tmp_path):
    s = svc(tmp_path, wasm=True)
    writer = proxy(storage, s, node="writer", label=Label.trusted(confidentiality="confidential"))
    await writer.invoke("writer", "file_write", {"path": "notes/a.txt", "content": "quarterly numbers"})
    reader = proxy(storage, s, node="reader", label=Label.trusted(confidentiality="internal"))
    text = await reader.invoke("reader", "file_read", {"path": "notes/a.txt"})
    assert text == "quarterly numbers"
    rd = [e for e in await events(storage, "sandbox_file") if e["op"] == "read"][0]
    assert rd["label"]["confidentiality"] == "confidential" and rd["label"]["integrity"] == "untrusted"
    assert reader.agent_context_label.confidentiality == "confidential"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["../escape.txt", "/etc/passwd", "C:\\Windows\\win.ini", "\\\\srv\\share\\x",
                                 "a/../../b", "x.txt:ads"])
async def test_file_tools_refuse_escapes(storage, tmp_path, bad):
    p = proxy(storage, svc(tmp_path, wasm=True))
    with pytest.raises(ValueError, match="refused"):
        await p.invoke("agent1", "file_write", {"path": bad, "content": "x"})
    with pytest.raises(ValueError, match="refused"):
        await p.invoke("agent1", "file_read", {"path": bad})
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.asyncio
async def test_sandbox_call_limit_trips_the_run_guard(storage, tmp_path):
    from agentos.usage.guard import RunGuard, UsageContext
    from agentos.usage.ledger import UsageSettings

    settings = UsageSettings.model_validate({"run_limits": {"max_sandbox_calls": 2}})
    guard = RunGuard(UsageContext.default(), "run_sb", "flow", settings)
    p = proxy(storage, svc(tmp_path, wasm=True), guard=guard)
    await p.invoke("agent1", "python_exec", {"code": "1"})
    await p.invoke("agent1", "file_write", {"path": "a.txt", "content": "x"})
    with pytest.raises(RunLimitExceeded, match="sandbox calls 2/2"):
        await p.invoke("agent1", "python_exec", {"code": "2"})
    assert guard.tripped is not None
    ev = await events(storage, "run_limit_exceeded")
    assert ev == [{"limit": "sandbox_calls", "used": 2, "max": 2}]
    with pytest.raises(RunLimitExceeded):
        guard.before_attempt({"provider": "mock", "model": "m"})  # the next model call stops the run


def test_default_limit_is_20_and_flow_can_only_lower():
    from agentos.usage.ledger import UsageSettings

    s = UsageSettings()
    assert s.sandbox_limit_for("f") == 20
    s2 = UsageSettings.model_validate({"run_limits": {"max_sandbox_calls": 5,
                                                      "flows": {"f": {"max_sandbox_calls": 50}}}})
    assert s2.sandbox_limit_for("f") == 5


def test_sandbox_tools_are_agent_tools_not_flow_steps():
    from agentos.flows.models import FlowDefinition, InvalidFlowConfigError
    from agentos.flows.specs import AGENT_TOOL_TYPES, BUILTIN_NODE_SPECS, SideEffectClass

    for t in ("python_exec", "shell_exec", "file_read", "file_write"):
        assert t in AGENT_TOOL_TYPES and BUILTIN_NODE_SPECS[t].side_effect == SideEffectClass.NONE
        assert not BUILTIN_NODE_SPECS[t].sink_rules  # the code may be untrusted: that is what the sandbox is for
    with pytest.raises((InvalidFlowConfigError, ValueError)):
        FlowDefinition(id="f", name="f", entrypoint="t", nodes={
            "t": {"id": "t", "type": "manual_trigger", "config": {}},
            "x": {"id": "x", "type": "python_exec", "config": {}}}, edges=[])
