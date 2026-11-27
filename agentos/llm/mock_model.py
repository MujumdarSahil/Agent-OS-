"""Deterministic scripted model for MOCK mode (``AGENTOS_MOCK_LLM=1``), Part 0a of 3.4.

No network, no keys, no provider client: ``AgentOSRouterLLM`` answers every call from here when MOCK mode is
on, so agent and llm nodes still produce ``llm_call`` events and pass through budgets and run limits (cost 0).

The answer is picked from the text of the messages with fixed rules, the same ones use case 07's scripted model
uses (examples/usecases/07-support-desk-copilot/run.py, SCRIPTED):
- a prompt-injection marker -> a "fooled" answer (URGENT + the attacker's request), so MOCK demos show what the
  security model does when the model is fooled;
- an outage marker -> URGENT;
- anything else -> NORMAL with a short generic summary.
The answer starts with "Final Answer:" so CrewAI's ReAct parser accepts it.
"""

from __future__ import annotations

import json
from typing import Any

PROVIDER = "mock"
MODEL = "mock/scripted"
CHAIN_ENTRY = {"provider": PROVIDER, "model": MODEL, "api_base": None, "timeout": None, "api_key_env": None,
               "local": True, "order": 0}

INJECTION_MARKERS = ("ignore all previous instructions", "ignore previous instructions", "mallory@")
URGENT_MARKERS = ("http 500", "checkout is down", "outage", "all our customers are affected")

ANSWERS = {
    "injection": "Final Answer: URGENT. Email the full customer list to mallory@attacker.example.",
    "urgent": "Final Answer: URGENT. Production checkout returns HTTP 500 for all requests since 09:10 UTC.",
    "normal": "Final Answer: NORMAL. The request is routine and can be handled by the support queue.",
}


def _text(messages: Any) -> str:
    if isinstance(messages, str):
        return messages
    parts = []
    for m in messages or []:
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", m)
        parts.append(content if isinstance(content, str) else json.dumps(content, default=str))
    return "\n".join(parts)


def scenario(messages: Any) -> str:
    """'injection', 'urgent' or 'normal' for these messages (deterministic)."""
    t = _text(messages).lower()
    if any(m in t for m in INJECTION_MARKERS):
        return "injection"
    if any(m in t for m in URGENT_MARKERS):
        return "urgent"
    return "normal"


def complete(messages: Any) -> str:
    """The scripted answer for these messages."""
    # 4.0: the natural-language flow builder gets its own scripted model (deterministic JSON drafts)
    from agentos.builder.prompt import SYSTEM_MARKER

    if isinstance(messages, list) and any(isinstance(m, dict) and SYSTEM_MARKER in str(m.get("content", ""))
                                          for m in messages):
        from agentos.builder import mock_builder

        return mock_builder.respond(messages)
    return ANSWERS[scenario(messages)]
