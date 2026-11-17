"""AgentOSRouterLLM (2.4c) - MOCK: litellm.completion is replaced; no network, no real keys."""

import json
from types import SimpleNamespace as NS

import pytest

import agentos.llm.router_llm as rl
from agentos.flows.rules import RuleViolation, SinkRuleViolationError
from agentos.llm.router_llm import AgentOSRouterLLM, AllProvidersFailedError, LLMRefusedError

CHAIN = [
    {"provider": "groq", "model": "groq/llama-3.3-70b", "api_key_env": "GROQ_API_KEY", "local": False},
    {"provider": "openrouter_glm_5_2_free", "model": "openrouter/glm", "api_key_env": "OPENROUTER_API_KEY", "local": False},
    {"provider": "ollama", "model": "ollama/llama3", "api_key_env": None, "local": True},
]


class RateLimitError(Exception):
    pass


def reply(content="ok", tool_calls=None, tokens=(10, 5)):
    return NS(choices=[NS(message=NS(content=content, tool_calls=tool_calls))],
              usage=NS(prompt_tokens=tokens[0], completion_tokens=tokens[1], total_tokens=sum(tokens)))


def fake(monkeypatch, behaviour):
    calls = []

    def completion(**kw):
        calls.append(kw)
        return behaviour(kw, len(calls))

    monkeypatch.setattr(rl, "_completion", completion)
    return calls


def test_fallback_records_attempts_and_metadata(monkeypatch):
    def behaviour(kw, n):
        if kw["model"].startswith("groq"):
            raise RateLimitError("429")
        return reply("summary")

    calls = fake(monkeypatch, behaviour)
    events = []
    llm = AgentOSRouterLLM(chain=CHAIN, on_call=events.append, node_id="n1",
                           key_lookup=lambda provider, env: "sk-secret-value-123")
    assert llm.call("hello") == "summary"
    ev = events[-1]
    assert ev["status"] == "ok" and ev["provider"] == "openrouter_glm_5_2_free" and ev["node_id"] == "n1"
    assert ev["attempts"] == [{"provider": "groq", "model": "groq/llama-3.3-70b", "error_class": "RateLimitError"}]
    assert ev["total_tokens"] == 15 and ev["latency_ms"] >= 0
    assert calls[0]["api_key"] == "sk-secret-value-123"
    dumped = json.dumps(events)
    assert "sk-secret" not in dumped and "hello" not in dumped and "summary" not in dumped  # metadata only


def test_preferred_model_goes_first(monkeypatch):
    calls = fake(monkeypatch, lambda kw, n: reply())
    AgentOSRouterLLM(chain=CHAIN, preferred_model="openrouter_glm_5_2_free").call("hi")
    assert calls[0]["model"] == "openrouter/glm"


def test_all_providers_failing_raises_with_hops(monkeypatch):
    def always_429(kw, n):
        raise RateLimitError("429")

    fake(monkeypatch, always_429)
    events = []
    with pytest.raises(AllProvidersFailedError, match="groq: RateLimitError"):
        AgentOSRouterLLM(chain=CHAIN[:2], on_call=events.append).call("hi")
    assert events[-1]["status"] == "failed" and len(events[-1]["attempts"]) == 2


def test_secret_input_refused_without_local_provider_and_uses_local_when_present(monkeypatch):
    calls = fake(monkeypatch, lambda kw, n: reply())
    events = []
    with pytest.raises(LLMRefusedError, match="local providers"):
        AgentOSRouterLLM(chain=CHAIN[:2], local_only=True, on_call=events.append).call("secret stuff")
    assert calls == [] and events[-1]["status"] == "refused"
    AgentOSRouterLLM(chain=CHAIN, local_only=True).call("secret stuff")
    assert [c["model"] for c in calls] == ["ollama/llama3"]


def tool_call(name, args):
    return NS(id="call_1", function=NS(name=name, arguments=json.dumps(args)))


def test_native_tool_path_runs_proxy_wrapped_functions(monkeypatch):
    monkeypatch.setattr(AgentOSRouterLLM, "supports_function_calling", lambda self: True)
    calls = fake(monkeypatch, lambda kw, n: reply("", [tool_call("lookup", {"q": "x"})]) if n == 1 else reply("final"))
    seen = []
    out = AgentOSRouterLLM(chain=CHAIN).call("go", tools=[{"type": "function", "function": {"name": "lookup"}}],
                                             available_functions={"lookup": lambda q: seen.append(q) or "found"})
    assert out == "final" and seen == ["x"] and "tools" in calls[0]
    assert calls[1]["messages"][-1] == {"role": "tool", "tool_call_id": "call_1", "content": "found"}


def test_proxy_block_is_not_retried_on_another_provider(monkeypatch):
    monkeypatch.setattr(AgentOSRouterLLM, "supports_function_calling", lambda self: True)
    calls = fake(monkeypatch, lambda kw, n: reply("", [tool_call("send_email", {"to": "attacker@evil.example"})]))

    def blocked(**kwargs):
        raise SinkRuleViolationError(RuleViolation("agent", "send_email.to", ["agent"], "untrusted recipient"))

    with pytest.raises(SinkRuleViolationError):
        AgentOSRouterLLM(chain=CHAIN).call("go", tools=[{}], available_functions={"send_email": blocked})
    assert len(calls) == 1  # no fallback to the next provider after a blocked tool call


def test_react_path_when_function_calling_unsupported(monkeypatch):
    monkeypatch.setattr(AgentOSRouterLLM, "supports_function_calling", lambda self: False)
    calls = fake(monkeypatch, lambda kw, n: reply("Thought: done\nFinal Answer: ok"))
    out = AgentOSRouterLLM(chain=CHAIN).call("go", tools=[{"type": "function"}], available_functions={})
    assert "Final Answer" in out and "tools" not in calls[0]
