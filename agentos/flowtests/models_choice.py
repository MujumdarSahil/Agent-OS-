"""4.2 D5: which model a test run uses.

``mock``             scripted, free, offline: per-node answers from the case (``mock_responses``), else a fixed
                     default. Security cases use the 4.1 adversarial MOCK model (it always obeys the injection).
``router``           the normal fallback chain (custom_llm None): budgets, run limits, usage ledger (tagged test).
``provider/model``   the chosen model on every llm / agent / quarantined_extraction node of an isolated flow copy;
                     it must be served by an enabled provider. Real calls go through the router as above.
"""

from __future__ import annotations

import contextvars
import json
from typing import Any, Optional

from crewai.llm import BaseLLM

from agentos.flows.extraction import mock_output

MODEL_NODE_TYPES = ("llm", "agent", "quarantined_extraction")
DEFAULT_MOCK_ANSWER = "MOCK answer (scripted test model)."
EXTRACTION_PREFIX = "You classify text into fixed fields"
JUDGE_NODE = "__judge__"

# The node the engine is executing (set by the test engine; copied into the worker thread by asyncio.to_thread).
CURRENT_NODE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("agentos_test_node", default=None)


class InvalidModelChoice(ValueError):
    pass


def normalize_model(spec: Optional[str]) -> str:
    s = (spec or "mock").strip()
    if s.lower() in ("mock", "router"):
        return s.lower()
    if "/" not in s and ":" not in s:
        raise InvalidModelChoice(f"model {s!r}: use mock, router or provider/model")
    return s


def check_model_enabled(spec: str) -> None:
    """A chosen model must be served by an enabled provider (same rule as the per-node model choice)."""
    if spec in ("mock", "router"):
        return
    from agentos.llm.provider_registry import enabled_model_ids
    from agentos.llm.router_factory import get_fallback_policy_cache

    if spec not in enabled_model_ids(get_fallback_policy_cache()):
        raise InvalidModelChoice(f"model {spec!r} is not provided by an enabled provider")


def with_model(flow: dict[str, Any], spec: str) -> dict[str, Any]:
    """An isolated copy of the flow with ``config.model`` set on every model node (chosen-model runs)."""
    out = json.loads(json.dumps(flow))
    if spec in ("mock", "router"):
        return out
    for node in (out.get("nodes") or {}).values():
        if node.get("type") in MODEL_NODE_TYPES:
            node.setdefault("config", {})["model"] = spec
    return out


class ScriptedTestModel(BaseLLM):
    """MOCK: deterministic answers per node; never a network call (declares itself local, which is true)."""

    model: str = "mock/scripted"
    is_local: bool = True

    def setup(self, flow: dict[str, Any], responses: dict[str, str], allowlists: dict[str, list[str]] | None = None,
              judge: Optional[dict[str, Any]] = None) -> "ScriptedTestModel":
        object.__setattr__(self, "_nodes", flow.get("nodes") or {})
        object.__setattr__(self, "_responses", dict(responses or {}))
        object.__setattr__(self, "_allowlists", allowlists or {})
        object.__setattr__(self, "_judge", judge)
        return self

    def _node(self) -> tuple[Optional[str], dict[str, Any]]:
        nid = CURRENT_NODE.get()
        return nid, (self._nodes.get(nid) or {}) if nid else {}

    def call(self, messages: Any, *args: Any, **kwargs: Any) -> str:
        object.__setattr__(self, "_calls", int(getattr(self, "_calls", 0) or 0) + 1)
        nid, node = self._node()
        scripted = self._responses.get(nid) if nid else None
        first = ""
        if isinstance(messages, list) and messages:
            first = str(messages[0].get("content", "")) if isinstance(messages[0], dict) else str(messages[0])
        if first.startswith(EXTRACTION_PREFIX):
            if self._judge is not None:
                return json.dumps(self._judge)
            if scripted is not None:
                return scripted
            return mock_output(node.get("config") or {"fields": []}, self._allowlists)
        text = scripted if scripted is not None else DEFAULT_MOCK_ANSWER
        if node.get("type") == "agent" and "Final Answer:" not in text:
            return f"Final Answer: {text}"
        return text


def scripted_model(flow: dict[str, Any], responses: dict[str, str], allowlists: dict[str, list[str]] | None = None,
                   judge: Optional[dict[str, Any]] = None) -> ScriptedTestModel:
    return ScriptedTestModel(model="mock/scripted").setup(flow, responses, allowlists, judge)
