"""2.4c engine integration (MOCK: litellm.completion replaced; AGENTOS_MOCK_LLM unset for these tests).

- llm node makes a real call through AgentOSRouterLLM; fallback hops land in an llm_call event.
- T-13: secret-labelled input with only hosted providers -> refused, run fails with a clear reason.
- MOCK mode (AGENTOS_MOCK_LLM=1) keeps the previous stub behaviour.
"""

from pathlib import Path
from types import SimpleNamespace as NS

import pytest
import pytest_asyncio

import agentos.llm.router_llm as rl
from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.state import RunStatus
from agentos.storage import open_storage

CHAIN = [
    {"provider": "groq", "model": "groq/llama", "api_key_env": "GROQ_API_KEY", "local": False},
    {"provider": "openrouter_glm_5_2_free", "model": "openrouter/glm", "api_key_env": "OPENROUTER_API_KEY", "local": False},
]


class RateLimitError(Exception):
    pass


@pytest_asyncio.fixture
async def storage(tmp_path: Path):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


def llm_flow():
    nodes = {"trig": {"id": "trig", "type": "manual_trigger"}, "sum": {"id": "sum", "type": "llm", "config": {}}}
    return FlowDefinition(id="llm_real", entrypoint="trig", nodes=nodes,
                          edges=[{"source": "trig", "target": "sum", "arg_mapping": {"prompt": "payload"}}])


@pytest.fixture
def real_mode(monkeypatch):
    monkeypatch.delenv("AGENTOS_MOCK_LLM", raising=False)
    monkeypatch.setattr(rl, "default_chain", lambda: [dict(e) for e in CHAIN])
    calls = []

    def completion(**kw):
        calls.append(kw["model"])
        if kw["model"].startswith("groq"):
            raise RateLimitError("429")
        return NS(choices=[NS(message=NS(content="real answer", tool_calls=None))],
                  usage=NS(prompt_tokens=3, completion_tokens=2, total_tokens=5))

    monkeypatch.setattr(rl, "_completion", completion)
    return calls


@pytest.mark.asyncio
async def test_llm_node_real_call_with_fallback_event(storage, real_mode):
    st = await FlowEngine(llm_flow(), storage).run(run_id="r_llm", inputs={"text": "hi"})
    assert st.status == RunStatus.SUCCEEDED and st.node_outputs["sum"]["completion"] == "real answer"
    assert real_mode == ["groq/llama", "openrouter/glm"]
    ev = [e for e in await storage.events.list("r_llm", after_seq=0) if e.type == "llm_call"]
    assert len(ev) == 1 and ev[0].data["provider"] == "openrouter_glm_5_2_free" and ev[0].data["node_id"] == "sum"
    assert ev[0].data["attempts"][0] == {"provider": "groq", "model": "groq/llama", "error_class": "RateLimitError"}
    assert '"hi"' not in ev[0].model_dump_json()  # metadata only


@pytest.mark.asyncio
async def test_secret_input_refused_for_hosted_providers(storage, real_mode, monkeypatch):
    from agentos.flows.labels import Label

    original = FlowEngine._router_llm

    def secret_inbound(self, state, node, inbound, loop):
        return original(self, state, node, Label(integrity="untrusted", confidentiality="secret", sources={"trig"}), loop)

    monkeypatch.setattr(FlowEngine, "_router_llm", secret_inbound)
    st = await FlowEngine(llm_flow(), storage).run(run_id="r_secret", inputs={"text": "password=hunter2"})
    assert st.status == RunStatus.FAILED and "local providers" in (st.error or "")
    assert real_mode == []  # no hosted provider was called
    ev = [e for e in await storage.events.list("r_secret", after_seq=0) if e.type == "llm_call"]
    assert ev and ev[0].data["status"] == "refused"


@pytest.mark.asyncio
async def test_mock_mode_unchanged(storage, monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    st = await FlowEngine(llm_flow(), storage).run(run_id="r_mock", inputs={"text": "hi"})
    assert st.status == RunStatus.SUCCEEDED and st.node_outputs["sum"]["completion"].startswith("Completion for:")
    assert not [e for e in await storage.events.list("r_mock", after_seq=0) if e.type == "llm_call"]
