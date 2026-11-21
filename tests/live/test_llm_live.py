"""
LIVE (opt-in) check for 2.4c real models. Skipped unless AGENTOS_LIVE_LLM=1. Not collected by CI.

PowerShell, with provider keys stored in the project vault (or in the environment):
    $env:AGENTOS_LIVE_LLM="1"
    $env:AGENTOS_PROJECT="C:\\path\\to\\project"   # optional; default ~/.agentos/workspace
    .\\venv\\Scripts\\python.exe -m pytest tests/live/test_llm_live.py -q -s

1. One agent flow runs end to end through AgentOSRouterLLM.
2. The first hosted provider's key is replaced by an invalid value in THIS process only (the vault is
   not touched); the run must fall back to the next provider and succeed.
Only provider names, status and timings are recorded (docs/evidence/raw/2.4c-live.txt).
"""

import asyncio
import os
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("AGENTOS_LIVE_LLM") != "1", reason="LIVE: set AGENTOS_LIVE_LLM=1")

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "evidence" / "raw" / "2.4c-live.txt"


def _project() -> str:
    return os.environ.get("AGENTOS_PROJECT") or str(Path.home() / ".agentos" / "workspace")


async def _load_vault_keys(project: str) -> list[str]:
    from agentos.llm.provider_registry import export_vault_provider_keys
    from agentos.security.vault import MasterKey, Vault
    from agentos.storage import open_storage

    storage = await open_storage(project, backend="file")
    try:
        return await export_vault_provider_keys(Vault(storage.credentials, MasterKey.load(create=False)))
    finally:
        await storage.close()


async def _run(project: str, run_id: str):
    from agentos.flows.engine import FlowEngine
    from agentos.flows.models import FlowDefinition
    from agentos.storage import open_storage

    flow = FlowDefinition(
        id="live_agent", entrypoint="trig",
        nodes={
            "trig": {"id": "trig", "type": "manual_trigger"},
            "agent": {"id": "agent", "type": "agent", "config": {
                "role": "Support triage", "goal": "Classify a support ticket as urgent or normal",
                "backstory": "Careful support analyst", "tools": []}},
        },
        edges=[{"source": "trig", "target": "agent", "arg_mapping": {"task": "payload"}}],
    )
    storage = await open_storage(project, backend="file")
    try:
        started = time.perf_counter()
        st = await FlowEngine(flow, storage).run(
            run_id=run_id, inputs={"ticket": "My order has not arrived after two weeks. Urgent or normal?"})
        seconds = round(time.perf_counter() - started, 2)
        events = [e.data for e in await storage.events.list(run_id, after_seq=0) if e.type == "llm_call"]
        return st, events, seconds
    finally:
        await storage.close()


def _summary(label, st, events, seconds) -> str:
    lines = [f"{label}: run={st.status.value} wall={seconds}s llm_calls={len(events)}"]
    for ev in events:
        hops = [f"{a.get('provider')}: {a.get('error_class')}" for a in ev.get("attempts", [])]
        hops.append(f"{ev.get('provider')}: ok" if ev.get("status") == "ok" else str(ev.get("status")))
        lines.append(f"  {' -> '.join(hops)} ({ev.get('latency_ms')} ms)")
    return "\n".join(lines)


def test_live_agent_flow_and_fallback(monkeypatch):
    monkeypatch.delenv("AGENTOS_MOCK_LLM", raising=False)
    project = _project()
    loaded = asyncio.run(_load_vault_keys(project))

    from agentos.llm.router_llm import default_chain

    chain = [e for e in default_chain() if not e["local"]]
    assert len(chain) >= 2, f"need two or more hosted providers with keys (vault key names loaded: {loaded})"

    st1, ev1, t1 = asyncio.run(_run(project, f"live_ok_{int(time.time())}"))

    first = chain[0]
    monkeypatch.setenv(first["api_key_env"], "invalid-key-for-fallback-test")  # this process only
    st2, ev2, t2 = asyncio.run(_run(project, f"live_fallback_{int(time.time())}"))

    report = "\n".join([
        "2.4c LIVE check (provider names, status and timings only)",
        f"chain order: {', '.join(e['provider'] for e in chain)}",
        _summary("1. end-to-end", st1, ev1, t1),
        _summary(f"2. first provider ({first['provider']}) key invalid", st2, ev2, t2),
    ])
    OUT.write_text(report + "\n", encoding="utf-8")
    print(report)

    assert st1.status.value == "succeeded" and ev1 and ev1[-1]["status"] == "ok"
    assert st2.status.value == "succeeded"
    assert any(a.get("provider") == first["provider"] for ev in ev2 for a in ev.get("attempts", []))
