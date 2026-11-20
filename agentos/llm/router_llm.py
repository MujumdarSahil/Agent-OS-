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
  prompts or responses. A failed attempt carries ``error_message``: the provider's error text,
  truncated to 200 characters with key-like strings scrubbed (rule 6).
- Circuit breaker: a provider that failed with NotFound / Authentication / PermissionDenied (or any
  error whose text says the API key is invalid/expired - Groq sends that as 400 BadRequest), a
  decommissioned model, or a "no balance / insufficient quota" error is skipped for a long cooldown
  (AGENTOS_LLM_COOLDOWN_S, default 600 s); transient rate limits, timeouts and outages get a short
  one (AGENTOS_LLM_SHORT_COOLDOWN_S, default 60 s). Skips are recorded as "skipped (cooldown)".
- Per-attempt timeout: fallback policy ``timeout_s`` > registry ``timeout_s`` >
  AGENTOS_LLM_ATTEMPT_TIMEOUT_S > 20 s.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Callable, Optional

from crewai.llms.base_llm import BaseLLM as CrewAIBaseLLM

MAX_TOOL_ROUNDS = 8
DEFAULT_ATTEMPT_TIMEOUT_S = 20.0
ERROR_MESSAGE_MAX = 200
SKIPPED_COOLDOWN = "skipped (cooldown)"
# Only standard chat-completion message fields go to providers; strict OpenAI-compatible APIs
# (Groq, Together, DeepSeek) reject unknown properties such as CrewAI's "files"/"raw_tool_call_parts".
_MESSAGE_FIELDS = {"role", "content", "name", "tool_calls", "tool_call_id"}

_LONG_ERRORS = {"NotFoundError", "AuthenticationError", "PermissionDeniedError"}
_SHORT_ERRORS = {"RateLimitError", "Timeout", "APITimeoutError", "TimeoutError", "ServiceUnavailableError",
                 "APIConnectionError", "InternalServerError"}
_NO_BALANCE = re.compile(r"insufficient[_ ](balance|quota|funds|credit)|no (credit|balance)|quota exceeded|"
                         r"exceeded your (current )?quota|billing|payment required|out of credits", re.I)
# Some providers (e.g. Groq) answer an invalid or expired key with HTTP 400 BadRequest, not 401.
_BAD_KEY = re.compile(r"invalid[_ ]api[_ ]key|incorrect[_ ]api[_ ]key|invalid[_ ](x-)?api[-_ ]key|"
                      r"api[_ ]key[_ ](is )?(invalid|expired|not valid|revoked)|expired[_ ]api[_ ]key|"
                      r"invalid[_ ]authentication|unauthorized", re.I)
_MODEL_GONE = re.compile(r"decommissioned|model[_ ]not[_ ]found|does not exist|no longer (supported|available)|"
                         r"not a valid model|unknown model", re.I)
_KEYLIKE = re.compile(
    r"(sk|gsk|pk|rk|xai|AIza|hf|ghp|glpat|key)[-_][A-Za-z0-9_\-]{8,}"   # prefixed API keys
    r"|Bearer\s+\S+"                                                    # auth headers
    r"|[A-Za-z0-9]{32,}"                                                # long opaque tokens (hex/base62)
)

_cooldowns: dict[str, tuple[float, str]] = {}
_cooldown_lock = threading.Lock()


def mock_mode() -> bool:
    """MOCK mode (``AGENTOS_MOCK_LLM=1``): every model call is answered by agentos.llm.mock_model."""
    return os.environ.get("AGENTOS_MOCK_LLM") == "1"


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def scrub_error_message(message: Any, secrets: tuple[str, ...] = ()) -> str:
    """Provider error text safe for the event log: known secrets and key-like strings removed, max 200 chars."""
    text = " ".join(str(message or "").split())
    for s in secrets:
        if s and len(s) >= 6:
            text = text.replace(s, "[redacted]")
    text = _KEYLIKE.sub("[redacted]", text)
    return text if len(text) <= ERROR_MESSAGE_MAX else text[: ERROR_MESSAGE_MAX - 3] + "..."


def cooldown_seconds(err: BaseException) -> float:
    """0 = no cooldown (request-specific error); otherwise how long to skip this provider."""
    name, text = type(err).__name__, str(err)
    if name in _LONG_ERRORS or _BAD_KEY.search(text) or _NO_BALANCE.search(text) or _MODEL_GONE.search(text):
        return _env_float("AGENTOS_LLM_COOLDOWN_S", 600.0)
    if name in _SHORT_ERRORS or "timeout" in name.lower():
        return _env_float("AGENTOS_LLM_SHORT_COOLDOWN_S", 60.0)
    return 0.0


def _cooldown_left(provider: str) -> float:
    with _cooldown_lock:
        until, _ = _cooldowns.get(provider, (0.0, ""))
    return max(0.0, until - time.monotonic())


def _start_cooldown(provider: str, seconds: float, reason: str) -> None:
    if seconds > 0:
        with _cooldown_lock:
            _cooldowns[provider] = (time.monotonic() + seconds, reason)


def cooldown_snapshot() -> dict[str, dict[str, Any]]:
    """Read-only view of the circuit breaker: provider -> {seconds_left, error_class} (2.4e).

    In-memory and per process: it is empty after a restart and shows only this process's view.
    Contains error class names only, never error text or key material.
    """
    now = time.monotonic()
    with _cooldown_lock:
        items = list(_cooldowns.items())
    return {
        p: {"seconds_left": round(until - now, 1), "error_class": reason}
        for p, (until, reason) in items
        if until > now
    }


def reset_cooldowns() -> None:
    """Clear the circuit breaker (tests, or after the operator fixes a key)."""
    with _cooldown_lock:
        _cooldowns.clear()


def _clean_messages(msgs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for m in msgs:
        clean = {k: v for k, v in m.items() if k in _MESSAGE_FIELDS}
        if clean.get("content") is None and not clean.get("tool_calls"):
            clean["content"] = ""
        out.append(clean)
    return out


class LLMRefusedError(RuntimeError):
    """The call was refused before reaching any provider (e.g. secret data, no local provider)."""


class AllProvidersFailedError(RuntimeError):
    """Every provider in the chain failed."""


def default_chain() -> list[dict[str, Any]]:
    """Ordered provider deployments from the existing router (order, enabled flags, timeouts)."""
    from agentos.llm.provider_registry import PROVIDER_REGISTRY
    from agentos.llm.router_factory import build_router

    registry_timeout = {p["name"]: p.get("timeout_s") for p in PROVIDER_REGISTRY}
    entries = []
    for d in build_router().model_list:
        params = d.get("litellm_params", {})
        info = d.get("model_info", {}) or {}
        provider = info.get("provider") or params.get("model")
        entries.append({
            "provider": provider,
            "model": params.get("model"),
            "api_base": params.get("api_base"),
            "timeout": params.get("request_timeout") or registry_timeout.get(provider),
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
        guard: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("model", preferred_model or "agentos-router")
        super().__init__(**kwargs)
        self._guard = guard  # 3.2: agentos.usage.guard.RunGuard (run limits + budgets), or None
        self._preferred = preferred_model
        self._key_lookup = key_lookup
        self._on_call = on_call
        self._local_only = local_only
        self._node_id = node_id
        self._chain_override = chain

    # -------------------------------------------------------------- chain

    def chain(self) -> list[dict[str, Any]]:
        if mock_mode():
            # 3.4 Part 0a: MOCK mode never reaches a provider; the scripted model is the whole chain (local, $0).
            from agentos.llm import mock_model

            return [dict(mock_model.CHAIN_ENTRY)]
        chain = list(self._chain_override if self._chain_override is not None else default_chain())
        if self._preferred:
            first = [e for e in chain if self._preferred in (e["provider"], e["model"])]
            chain = first + [e for e in chain if e not in first]
        if self._local_only:
            chain = [e for e in chain if e.get("local")]
        return chain

    def supports_function_calling(self) -> bool:
        if mock_mode():
            return False  # the scripted model answers in ReAct text
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
        msgs = _clean_messages(_to_dict_messages(messages))
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
        default_timeout = _env_float("AGENTOS_LLM_ATTEMPT_TIMEOUT_S", DEFAULT_ATTEMPT_TIMEOUT_S)
        budget_block: Optional[Exception] = None  # 3.2: after a budget refusal only $0 providers may be tried
        for entry in chain:
            left = _cooldown_left(entry["provider"])
            if left > 0:
                attempts.append({"provider": entry["provider"], "model": entry["model"], "error_class": SKIPPED_COOLDOWN,
                                 "error_message": f"circuit open for another {int(left)} s"})
                continue
            if self._guard is not None:  # 3.2: run limits and budgets, before every provider attempt
                from agentos.usage.guard import BudgetExceeded, RunLimitExceeded

                try:
                    self._guard.before_attempt(entry, after_budget_block=budget_block is not None)
                except BudgetExceeded as be:
                    budget_block = budget_block or be
                    attempts.append({"provider": entry["provider"], "model": entry["model"],
                                     "error_class": "BudgetExceeded", "error_message": str(be)})
                    continue
                except RunLimitExceeded as rl:
                    self._emit({"status": "refused", "provider": None, "model": None, "attempts": attempts,
                                "reason": str(rl), "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                                "mock": False})
                    raise
            if entry["provider"] == "mock" and mock_mode():
                from agentos.llm import mock_model

                content = mock_model.complete(msgs)  # offline: no client, no key, no network
                self._emit({"status": "ok", "provider": entry["provider"], "model": entry["model"],
                            "attempts": attempts, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
                            "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": True})
                return content
            kwargs: dict[str, Any] = {"model": entry["model"], "messages": list(msgs),
                                      "timeout": float(entry.get("timeout") or default_timeout)}
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
                attempt = {"provider": entry["provider"], "model": entry["model"], "error_class": type(err).__name__,
                           "error_message": scrub_error_message(err, (key,) if key else ())}
                if tool_ran or not self._is_provider_error(err):
                    self._emit({"status": "failed", "provider": entry["provider"], "model": entry["model"],
                                "attempts": attempts + [attempt],
                                "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": False})
                    raise
                _start_cooldown(entry["provider"], cooldown_seconds(err), type(err).__name__)
                attempts.append(attempt)
                continue
            content = getattr(resp.choices[0].message, "content", None) or ""
            self._emit({"status": "ok", "provider": entry["provider"], "model": entry["model"], "attempts": attempts,
                        **usage, "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": False})
            return content

        self._emit({"status": "failed", "provider": None, "model": None, "attempts": attempts,
                    **({"reason": str(budget_block)} if budget_block is not None else {}),
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1), "mock": False})
        if budget_block is not None:  # fail closed with the budget reason (no paid provider got around it)
            raise budget_block
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
