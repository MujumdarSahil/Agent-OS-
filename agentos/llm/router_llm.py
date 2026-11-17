"""
AgentOSRouterLLM: a CrewAI BaseLLM that calls real models through the AgentOS provider chain
(sub-milestone 2.4c).

- The chain is the router's deployment list (fallback-policy order, enabled flags, timeouts); a
  per-node preferred model is moved to the front. Each provider is tried in turn; failures are
  recorded as {provider, model, error_class} and the next one is tried.
- Keys: vault first (via an injected lookup), then the provider's environment variable.
- Both CrewAI tool paths: native function calling (when the model supports it, tool calls are
  executed through CrewAI's ``available_functions``, which are AgentOS proxy-wrapped tools) and
  ReAct text (no tools passed to the model). Once a tool has run, a later provider failure is NOT
  retried on another provider (that could repeat side effects).
- THREAT_MODEL T-13: ``local_only=True`` (secret-labelled input) restricts the chain to local
  providers; with none available the call is refused.
- ``on_call`` receives metadata only (provider, model, attempts, tokens, latency) - never keys,
  prompts or responses.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

from crewai.llms.base_llm import BaseLLM as CrewAIBaseLLM

MAX_TOOL_ROUNDS = 8


class LLMRefusedError(RuntimeError):
    """The call was refused before reaching any provider (e.g. secret data, no local provider)."""


class AllProvidersFailedError(RuntimeError):
    """Every provider in the chain failed."""


def default_chain() -> list[dict[str, Any]]:
    """Ordered provider deployments from the existing router (order, enabled flags, timeouts)."""
    from agentos.llm.router_factory import build_router

    entries = []
    for d in build_router().model_list:
        params = d.get("litellm_params", {})
        info = d.get("model_info", {}) or {}
        entries.append({
            "provider": info.get("provider") or params.get("model"),
            "model": params.get("model"),
            "api_base": params.get("api_base"),
            "timeout": params.get("request_timeout"),
            "api_key_env": info.get("api_key_env"),
            "local": bool(info.get("local")),
            "order": params.get("order", 1000),
        })
    entries.sort(key=lambda e: e["order"])
    return entries


def _to_dict_messages(messages: Any) -> list[dict[str, Any]]:
    if isinstance(messages, str):
        return [{"role": "user", "content": messages}]
    out = []
    for m in messages or []:
        if isinstance(m, dict):
            out.append(dict(m))
        elif hasattr(m, "role") and hasattr(m, "content"):
            out.append({"role": m.role, "content": m.content})
        else:
            out.append({"role": "user", "content": str(m)})
    return out


def _completion(**kwargs: Any) -> Any:
    import litellm

    return litellm.completion(**kwargs)


class AgentOSRouterLLM(CrewAIBaseLLM):
    """Fallback-aware CrewAI LLM over the AgentOS provider chain."""

    def __init__(
        self,
        preferred_model: Optional[str] = None,
        key_lookup: Optional[Callable[[str, Optional[str]], Optional[str]]] = None,
        on_call: Optional[Callable[[dict[str, Any]], None]] = None,
        local_only: bool = False,
        node_id: Optional[str] = None,
        chain: Optional[list[dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("model", preferred_model or "agentos-router")
        super().__init__(**kwargs)
        self._preferred = preferred_model
        self._key_lookup = key_lookup
        self._on_call = on_call
        self._local_only = local_only
        self._node_id = node_id
        self._chain_override = chain

    # -------------------------------------------------------------- chain

    def chain(self) -> list[dict[str, Any]]:
        chain = list(self._chain_override if self._chain_override is not None else default_chain())
        if self._preferred:
            first = [e for e in chain if self._preferred in (e["provider"], e["model"])]
            chain = first + [e for e in chain if e not in first]
        if self._local_only:
            chain = [e for e in chain if e.get("local")]
        return chain

    def supports_function_calling(self) -> bool:
        chain = self.chain()
        if not chain:
            return False
        try:
            import litellm

            return bool(litellm.supports_function_calling(model=chain[0]["model"]))
        except Exception:
            return False

    def _api_key(self, entry: dict[str, Any]) -> Optional[str]:
        env_name = entry.get("api_key_env")
        if self._key_lookup:
            try:
                key = self._key_lookup(entry["provider"], env_name)
                if key:
                    return key
            except Exception:
                pass
        if env_name:
            import os

            return os.environ.get(env_name, "").strip() or None
        return None

    def _emit(self, record: dict[str, Any]) -> None:
        if self._on_call:
            try:
                self._on_call({"node_id": self._node_id, **record})
            except Exception:
                pass

    # -------------------------------------------------------------- call

    def call(
        self,
        messages: Any,
        tools: Any = None,
        callbacks: Any = None,
        available_functions: Any = None,
        from_task: Any = None,
        from_agent: Any = None,
        response_model: Any = None,
    ) -> str:
        msgs = _to_dict_messages(messages)
        chain = self.chain()
        started = time.perf_counter()
        attempts: list[dict[str, Any]] = []
        if not chain:
            reason = (
                "secret-labelled input may only go to local providers; none is enabled"
                if self._local_only
                else "no enabled LLM provider is configured"
            )
            self._emit({"status": "refused", "provider": None, "model": None, "attempts": [], "reason": reason,
                        "latency_ms": 0, "mock": False})
            raise LLMRefusedError(reason)

        use_tools = bool(tools) and self.supports_function_calling()
        tool_ran = False
        for entry in chain:
            kwargs: dict[str, Any] = {"model": entry["model"], "messages": list(msgs), "timeout": entry.get("timeout") or 60}
            if entry.get("api_base"):
                kwargs["api_base"] = entry["api_base"]
            key = self._api_key(entry)
            if key:
                kwargs["api_key"] = key
            if use_tools:
                kwargs["tools"] = tools
            usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            try:
                resp = _completion(**kwargs)
                for _ in range(MAX_TOOL_ROUNDS):
                    self._add_usage(usage, resp)
                    message = resp.choices[0].message
                    tool_calls = getattr(message, "tool_calls", None) or []
                    if not (use_tools and tool_calls and available_functions):
                        break
                    kwargs["messages"].append({
                        "role": "assistant",
                        "content": getattr(message, "content", None) or "",
                        "tool_calls": [
                            {"id": tc.id, "type": "function",
                             "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"}}
                            for tc in tool_calls
                        ],
                    })
                    for tc in tool_calls:
                        fn = available_functions.get(tc.function.name)
                        args = json.loads(tc.function.arguments or "{}")
                        tool_ran = True
                        # Proxy-wrapped tool: security errors propagate and are never retried elsewhere.
                        result = fn(**args) if fn else f"Unknown tool {tc.function.name!r}"
                        kwargs["messages"].append({"role": "tool", "tool_call_id": tc.id, "content": str(result)})
                    resp = _completion(**kwargs)
            except Exception as err:  # provider failure (rate limit, auth, timeout, ...)
                if tool_ran or not self._is_provider_error(err):
                    self._emit({"status": "failed", "provider": entry["provider"], "model": entry["model"],
                                "attempts": attempts + [{"provider": entry["provider"], "model": entry["model"],
                                                         "error_class": type(err).__name__}],
                                "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": False})
                    raise
                attempts.append({"provider": entry["provider"], "model": entry["model"], "error_class": type(err).__name__})
                continue
            content = getattr(resp.choices[0].message, "content", None) or ""
            self._emit({"status": "ok", "provider": entry["provider"], "model": entry["model"], "attempts": attempts,
                        **usage, "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": False})
            return content

        self._emit({"status": "failed", "provider": None, "model": None, "attempts": attempts,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": False})
        hops = ", ".join(f"{a['provider']}: {a['error_class']}" for a in attempts)
        raise AllProvidersFailedError(f"all LLM providers failed ({hops})")

    @staticmethod
    def _is_provider_error(err: Exception) -> bool:
        # Security / proxy errors raised by tools are not provider failures.
        from agentos.flows.rules import PinnedArgumentOverrideError, SinkRuleViolationError

        return not isinstance(err, (SinkRuleViolationError, PinnedArgumentOverrideError))

    @staticmethod
    def _add_usage(usage: dict[str, int], resp: Any) -> None:
        u = getattr(resp, "usage", None)
        if not u:
            return
        for k in usage:
            usage[k] += int(getattr(u, k, 0) or (u.get(k, 0) if isinstance(u, dict) else 0) or 0)
