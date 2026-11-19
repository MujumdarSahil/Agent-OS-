"""AgentOS Tool Proxy for CrewAI mediation.

Every tool call by an agent is mediated through the AgentOSToolProxy:
- CrewAI receives only wrapped tools with caching strictly disabled.
- Pinned arguments cannot be overridden by models (attempts are rejected with an event).
- Pinned arguments retain trusted config labels; LLM-supplied arguments carry the agent's
  accumulated context label (node inputs + every tool output so far).
- Sink rules are checked with the shared IFC rule engine (agentos.flows.rules).
- Sinks execute via: sink_intent -> transport(idempotency_key) -> sink_committed.
- Every call appends an append-only event to storage.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any, Callable

from crewai.tools import BaseTool
from pydantic import Field, create_model

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.policy import SecurityPolicy
from agentos.flows.rules import (
    PinnedArgumentOverrideError,
    RuleViolation,
    SinkRuleViolationError,
    evaluate_sink_argument_rule,
)
from agentos.flows.specs import SideEffectClass
from agentos.flows.tool_catalog import (
    BUILTIN_CATALOG,
    ToolCatalog,
    ToolEntry,
    ToolLookupError,
    context_after_tool_output,
)
from agentos.storage.models import EventRecord
from agentos.storage.ports import FencingTokenError, Storage


# 3.3 (0c): fetch_url limits (GET only, through net_guard)
FETCH_URL_TIMEOUT_S = 10.0
FETCH_URL_MAX_BYTES = 100_000
MOCK_FETCH_BODY = "[HTTP 200] (mock fetch_url: no network request was made)"


def sink_result_text(tool_name: str, args: dict[str, Any], result: Any) -> str:
    """What the model is told after an EXTERNAL_SEND tool call (AgentOS-written; never a server response)."""
    status = (result or {}).get("status") if isinstance(result, dict) else None
    if status == "simulated":
        return f"{tool_name}: NOT sent ({(result or {}).get('reason') or 'simulated'})"
    if tool_name == "send_email":
        return f"Email successfully dispatched to {args.get('to')}"
    if tool_name == "send_slack":
        return f"Slack message sent to channel {args.get('channel')}"
    return f"{tool_name}: sent"


async def transport_send(transport: Any, idempotency_key: str, args: dict[str, Any]) -> Any:
    """3.3: prefer a transport's async ``asend`` (real channels); fall back to the sync ``send``."""
    if hasattr(transport, "asend"):
        return await transport.asend(idempotency_key=idempotency_key, **args)
    return transport.send(idempotency_key=idempotency_key, **args)


class MockTransport:
    """Default in-memory transport recording calls with idempotency keys."""

    retry_safe = True  # in-memory dedup by idempotency key: re-sending a pending intent is harmless

    def __init__(self) -> None:
        self.sent_calls: list[dict[str, Any]] = []
        self.seen_idempotency_keys: set[str] = set()

    def send(self, idempotency_key: str, **kwargs) -> dict[str, Any]:
        if idempotency_key in self.seen_idempotency_keys:
            # Deduplicate idempotent send
            return {"status": "deduplicated", "idempotency_key": idempotency_key}

        self.seen_idempotency_keys.add(idempotency_key)
        record = {"idempotency_key": idempotency_key, **kwargs}
        self.sent_calls.append(record)
        return {"status": "sent", "idempotency_key": idempotency_key}


class AgentOSToolProxy:
    """Mediator for CrewAI tool calls enforcing Information Flow Control policies."""

    def __init__(
        self,
        run_id: str,
        agent_node_id: str,
        storage: Storage,
        policy: SecurityPolicy,
        pinned_args: dict[str, Any] | None = None,
        agent_input_label: Label | None = None,
        transport_registry: dict[str, Any] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
        track_labels: bool = True,
        lease_id: str | None = None,
        fencing_checker: Any | None = None,
        tool_catalog: ToolCatalog | None = None,
        mcp_manager: Any | None = None,
    ) -> None:
        # 2.5a: same tool-spec lookup as the static analyzer (built-ins + approved MCP tools)
        self.tool_catalog = tool_catalog or BUILTIN_CATALOG
        self.mcp_manager = mcp_manager
        self.run_id = run_id
        self.agent_node_id = agent_node_id
        self.storage = storage
        self.policy = policy
        self.pinned_args = pinned_args or {}
        self.agent_input_label = agent_input_label or Label.trusted()
        # Accumulated context label starts as input label and accumulates tool output joins
        self.agent_context_label = self.agent_input_label
        self.transport_registry = transport_registry or {"send_email": MockTransport()}
        self._loop = loop or asyncio.get_event_loop()
        self.track_labels = track_labels
        self.lease_id = lease_id
        self.fencing_checker = fencing_checker

    def _check_fencing(self) -> None:
        """Enforce fencing token before transport invocation, event appending, or state mutation."""
        if self.lease_id is not None:
            if self.fencing_checker is None:
                raise FencingTokenError(
                    f"Lease {self.lease_id!r} is active for run {self.run_id!r} but no fencing_checker configured (fail closed)"
                )
            if not self.fencing_checker(self.run_id, self.lease_id):
                raise FencingTokenError(
                    f"Lease {self.lease_id!r} has expired or been superseded for run {self.run_id!r}"
                )
        elif self.fencing_checker is not None:
            if not self.fencing_checker(self.run_id, None):
                raise FencingTokenError(
                    f"Fencing check rejected unleased execution for run {self.run_id!r}"
                )

    async def _append_event(
        self,
        type: str,
        data: dict[str, Any] | None = None,
    ) -> EventRecord:
        """Append an event carrying the worker lease_id with fencing token check."""
        self._check_fencing()
        return await self.storage.events.append(
            run_id=self.run_id,
            type=type,
            data=data,
            lease_id=self.lease_id,
        )

    def invoke_sync(self, agent_node_id: str, tool_name: str, call_args: dict[str, Any]) -> Any:
        """Synchronous entrypoint called from CrewAI worker threads."""
        future = asyncio.run_coroutine_threadsafe(
            self.invoke(agent_node_id, tool_name, call_args),
            self._loop,
        )
        return future.result()

    async def invoke(self, agent_node_id: str, tool_name: str, call_args: dict[str, Any]) -> Any:
        """Asynchronously mediate, inspect, validate, and execute an agent tool call."""
        try:
            entry = self.tool_catalog.resolve(tool_name)
        except ToolLookupError as err:
            reason = (
                f"Unknown tool {tool_name!r}: tool has no declared NodeSpec (fail closed)"
                if err.reason == "unknown" and not tool_name.startswith("mcp")
                else f"{err} (fail closed)"
            )
            await self._append_event(
                type="tool_call_rejected",
                data={"agent_node": agent_node_id, "tool_name": tool_name, "reason": reason, "lookup": err.reason},
            )
            if err.reason == "unknown" and not tool_name.startswith("mcp"):
                raise ValueError(f"Tool {tool_name!r} has no declared NodeSpec (fail closed)") from err
            raise ValueError(reason) from err

        tool_name = entry.name  # canonical (wire names from the model map back to mcp.<server>.<tool>)
        tool_spec = entry.spec

        # 1. Pinned argument verification: reject any attempt to override pinned arguments
        for p_key, p_val in self.pinned_args.items():
            arg_name = p_key
            if p_key.startswith(f"{tool_name}."):
                arg_name = p_key[len(tool_name) + 1:]

            if arg_name in call_args:
                # If LLM supplied a value differing from pinned value -> REJECT
                if call_args[arg_name] != p_val:
                    await self._append_event(
                        type="tool_call_rejected",
                        data={
                            "agent_node": agent_node_id,
                            "tool_name": tool_name,
                            "arg": arg_name,
                            "attempted_value": call_args[arg_name],
                            "pinned_value": p_val,
                            "reason": f"LLM attempted to override author-pinned argument {arg_name!r}",
                        },
                    )
                    raise PinnedArgumentOverrideError(
                        f"Cannot override author-pinned argument {arg_name!r}: configured value is {p_val!r}"
                    )

        # Build effective argument set with pinned values enforced
        final_args = dict(call_args)
        for p_key, p_val in self.pinned_args.items():
            if p_key.startswith(f"{tool_name}."):
                arg_name = p_key[len(tool_name) + 1:]
                final_args[arg_name] = p_val
            elif p_key in final_args or p_key in (tool_spec.input_schema.get("properties") or {}):
                final_args[p_key] = p_val

        # 2. Confidentiality check: Secret-labeled context cannot be routed to EXTERNAL_SEND tool
        if self.track_labels and tool_spec.side_effect == SideEffectClass.EXTERNAL_SEND:
            if self.agent_context_label.confidentiality == Confidentiality.SECRET.value:
                violation = RuleViolation(
                    node_id=agent_node_id,
                    target_arg=tool_name,
                    path=[agent_node_id, tool_name],
                    reason=(
                        f"Confidentiality violation: secret-labeled data cannot be routed "
                        f"to EXTERNAL_SEND tool {tool_name!r}."
                    ),
                )
                await self._append_event(
                    type="tool_call_blocked",
                    data={
                        "agent_node": agent_node_id,
                        "tool_name": tool_name,
                        "reason": violation.reason,
                    },
                )
                raise SinkRuleViolationError(violation)

        # 3. Check sink rules using the shared rule engine
        if self.track_labels and tool_spec.sink_rules:
            to_val = final_args.get(tool_spec.recipient_arg)
            for arg_name, rule in tool_spec.sink_rules.items():
                canonical_pinned_key = f"{tool_name}.{arg_name}"
                is_pinned = canonical_pinned_key in self.pinned_args or arg_name in self.pinned_args
                arg_label = (
                    Label.trusted(sources={agent_node_id})
                    if is_pinned
                    else self.agent_context_label
                )

                violations = evaluate_sink_argument_rule(
                    node_id=agent_node_id,
                    spec=tool_spec,
                    arg_name=canonical_pinned_key,
                    rule=rule,
                    arriving_label=arg_label,
                    effective_inbound_label=self.agent_context_label,
                    is_pinned=is_pinned,
                    is_approved=False,  # Approval cannot declassify agent context in general
                    pinned_to_val=to_val,
                    policy=self.policy,
                    path=[agent_node_id, tool_name],
                )
                if violations:
                    v = violations[0]
                    await self._append_event(
                        type="tool_call_blocked",
                        data={
                            "agent_node": agent_node_id,
                            "tool_name": tool_name,
                            "arg": arg_name,
                            "reason": v.reason,
                        },
                    )
                    raise SinkRuleViolationError(v)

        # 4. Append tool_called event (every call produces an event)
        tool_ev = await self._append_event(
            type="tool_called",
            data={
                "agent_node": agent_node_id,
                "tool_name": tool_name,
                "args": final_args,
            },
        )

        # 5. Execute tool or sink pipeline
        if entry.is_mcp:
            ret_val = await self._invoke_mcp(agent_node_id, entry, final_args)
        elif tool_spec.side_effect == SideEffectClass.EXTERNAL_SEND:
            canonical_json = json.dumps(final_args, sort_keys=True, separators=(",", ":"))
            key_raw = f"{self.run_id}:{agent_node_id}:{tool_name}:{canonical_json}"
            idempotency_key = hashlib.sha256(key_raw.encode("utf-8")).hexdigest()

            # (b) Check event log: if sink_committed exists for that key, return recorded result without sending
            events = await self.storage.events.list(self.run_id, after_seq=0)
            existing_commit = next(
                (
                    e for e in events
                    if e.type == "sink_committed"
                    and (e.data or {}).get("idempotency_key") == idempotency_key
                ),
                None,
            )
            if existing_commit:
                return sink_result_text(tool_name, final_args, (existing_commit.data or {}).get("result"))

            transport = self.transport_registry.get(tool_name)
            # 3.3: argument checks of a real channel (header injection, sizes, From) BEFORE any intent
            if transport is not None and hasattr(transport, "avalidate"):
                try:
                    await transport.avalidate(final_args)
                except ValueError as err:
                    await self._append_event(type="tool_call_blocked", data={
                        "agent_node": agent_node_id, "tool_name": tool_name, "reason": str(err)[:300]})
                    raise

            # Append sink_intent event (if not already appended for this key)
            has_intent = any(
                e.type == "sink_intent"
                and (e.data or {}).get("idempotency_key") == idempotency_key
                for e in events
            )
            if has_intent and not getattr(transport, "retry_safe", True):
                # 3.3: a real send may or may not have happened; never re-send automatically
                reason = (f"{tool_name}: an earlier call with these arguments may or may not have been sent "
                          f"(uncommitted_sink_needs_review); it is never re-sent automatically")
                await self._append_event(type="sink_needs_review",
                                         data={"agent_node": agent_node_id, "tool_name": tool_name, "reason": reason})
                raise ValueError(reason)
            if not has_intent:
                await self._append_event(
                    type="sink_intent",
                    data={
                        "sink_node": agent_node_id,
                        "tool_name": tool_name,
                        "idempotency_key": idempotency_key,
                        "args": final_args,
                    },
                )

            # Transport call with fencing check and idempotency key
            self._check_fencing()
            if transport is not None and (hasattr(transport, "send") or hasattr(transport, "asend")):
                result = await transport_send(transport, idempotency_key, final_args)
            else:
                result = {"status": "sent", "idempotency_key": idempotency_key}

            # Append sink_committed event
            await self._append_event(
                type="sink_committed",
                data={
                    "sink_node": agent_node_id,
                    "tool_name": tool_name,
                    "idempotency_key": idempotency_key,
                    "result": result,
                },
            )
            ret_val = sink_result_text(tool_name, final_args, result)
        elif tool_name == "calculator":
            # 3.1: safe arithmetic only; errors go back to the model as text (no side effect, nothing to undo)
            from agentos.flows.calculator import CalculatorError, evaluate

            try:
                ret_val = str(evaluate(final_args.get("expression")))
            except CalculatorError as err:
                ret_val = f"Calculator error: {err}"
        elif tool_name == "fetch_url":
            ret_val = await self._fetch_url(agent_node_id, final_args.get("url"))
        else:
            ret_val = f"Executed {tool_name} successfully with args: {final_args}"

        # 6. Accumulate tool output label: tool outputs are untrusted sources (shared rule, see tool_catalog;
        #    MCP outputs carry the confidentiality the admin configured)
        self.agent_context_label = context_after_tool_output(self.agent_context_label, entry)

        return ret_val

    async def _fetch_url(self, agent_node_id: str, url: Any) -> str:
        """3.3 (0c): a real GET through net_guard (SSRF checks on every hop, connect to the checked IP, redirects
        re-checked, 100 KB cap, 10 s timeout, no credentials, no cookies). The output stays UNTRUSTED (the caller
        joins the tool-output label). The event holds metadata only, never the body. MOCK mode (no injected
        transport): a canned body, event mode "mock"."""
        import os

        from agentos.flows.net_guard import HttpRequestTransport, SSRFBlockedError, url_host

        base = {"agent_node": agent_node_id, "tool_name": "fetch_url"}
        transport = self.transport_registry.get("fetch_url")
        if transport is None and os.environ.get("AGENTOS_MOCK_LLM") == "1":
            await self._append_event(type="fetch_url", data={**base, "mode": "mock", "status": 200, "bytes": 0,
                                                             "truncated": False})
            return MOCK_FETCH_BODY
        if not isinstance(url, str) or not url.strip():
            await self._append_event(type="fetch_url", data={**base, "mode": "live", "status": "error",
                                                             "error": "missing url"})
            return "fetch_url error: a url is required"
        transport = transport or HttpRequestTransport(self.policy.http_allowlist)
        self._check_fencing()
        try:
            res = await asyncio.to_thread(transport.request, "GET", url.strip(), None, None, None,
                                          FETCH_URL_TIMEOUT_S, FETCH_URL_MAX_BYTES, None)
        except SSRFBlockedError as err:
            reason = f"fetch_url refused by the network guard: {err}"[:400]
            await self._append_event(type="tool_call_blocked", data={**base, "reason": reason})
            raise
        except Exception as err:  # timeout, connection or TLS error: AgentOS-written text only
            timed_out = "timeout" in type(err).__name__.lower()
            msg = (f"the request timed out after {FETCH_URL_TIMEOUT_S:g} s" if timed_out
                   else f"could not fetch the URL ({type(err).__name__})")
            await self._append_event(type="fetch_url", data={**base, "mode": "live", "status": "error",
                                                             "error": msg})
            return f"fetch_url error: {msg}"
        body = res.get("body") or ""
        await self._append_event(type="fetch_url", data={
            **base, "mode": "live", "status": res.get("status"), "bytes": len(body.encode("utf-8")),
            "truncated": bool(res.get("truncated")), "host": url_host(res.get("final_url") or ""),
            "redirects": len(res.get("redirects") or []),
        })
        return f"[HTTP {res.get('status')}] {body}" + (" [truncated]" if res.get("truncated") else "")

    async def _invoke_mcp(self, agent_node_id: str, entry: ToolEntry, args: dict[str, Any]) -> str:
        """Call an approved MCP tool through the manager. Above read: sink_intent -> call -> sink_committed;
        an intent without a commit is never retried (MCP has no idempotency): it needs review."""
        from agentos.mcp.manager import MCPError, MCPTimeout, MCPToolChanged

        record = self.tool_catalog.server(entry.server or "")
        if self.mcp_manager is None or record is None:
            reason = f"MCP tool {entry.name!r} cannot run: no MCP manager is available in this process (fail closed)"
            await self._append_event(type="tool_call_rejected",
                                     data={"agent_node": agent_node_id, "tool_name": entry.name, "reason": reason})
            raise ValueError(reason)

        is_sink = entry.spec.side_effect != SideEffectClass.READ
        idempotency_key = None
        if is_sink:
            canonical_json = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
            idempotency_key = hashlib.sha256(
                f"{self.run_id}:{agent_node_id}:{entry.name}:{canonical_json}".encode("utf-8")
            ).hexdigest()
            events = await self.storage.events.list(self.run_id, after_seq=0)
            if any(e.type == "sink_committed" and (e.data or {}).get("idempotency_key") == idempotency_key for e in events):
                return f"{entry.name}: already executed in this run (recorded result)"
            if any(e.type == "sink_intent" and (e.data or {}).get("idempotency_key") == idempotency_key for e in events):
                reason = (f"{entry.name}: an earlier call with these arguments may or may not have run "
                          f"(uncommitted_sink_needs_review); MCP calls are never retried automatically")
                await self._append_event(type="tool_call_blocked",
                                         data={"agent_node": agent_node_id, "tool_name": entry.name, "reason": reason})
                raise ValueError(reason)
            await self._append_event(type="sink_intent", data={
                "sink_node": agent_node_id, "tool_name": entry.name, "idempotency_key": idempotency_key, "args": args,
            })

        self._check_fencing()
        base = {"agent_node": agent_node_id, "tool_name": entry.name, "server": entry.server, "tool": entry.tool}
        try:
            res = await self.mcp_manager.call_tool(record, entry.server_tool_name or "", entry.sha256 or "", args)
        except MCPToolChanged as e:
            await self._append_event(type="mcp_tool_call", data={**base, "status": "changed"})
            await self._append_event(type="tool_call_rejected", data={**base, "reason": f"{e} (fail closed)"})
            raise ValueError(str(e)) from e
        except MCPTimeout as e:
            await self._append_event(type="mcp_tool_call", data={**base, "status": "timeout", "error": str(e)[:300]})
            raise
        except MCPError as e:
            await self._append_event(type="mcp_tool_call", data={**base, "status": "error", "error": str(e)[:300]})
            raise

        await self._append_event(type="mcp_tool_call", data={
            **base, "status": res.status, "duration_ms": res.duration_ms,
            "output_bytes": res.output_bytes, "truncated": res.truncated,
        })
        if is_sink:
            await self._append_event(type="sink_committed", data={
                "sink_node": agent_node_id, "tool_name": entry.name, "idempotency_key": idempotency_key,
                "result": {"status": res.status, "output_bytes": res.output_bytes, "truncated": res.truncated},
            })
        return res.text if res.status == "ok" else f"Tool error: {res.text}"

    def create_wrapped_tool(self, tool_name: str) -> BaseTool:
        """Create a CrewAI BaseTool wrapping the proxy with caching strictly disabled.

        MCP tools are exposed under their wire name (mcp__<server>__<tool>); the model sees the admin's
        replacement description when there is one (and only property names/types), otherwise the
        server's text, in which case the agent context already started untrusted (tool_catalog)."""
        proxy = self
        entry = self.tool_catalog.try_resolve(tool_name)
        if entry is not None and entry.is_mcp:
            from agentos.mcp.catalog import wire_name

            exposed_name = wire_name(entry.server or "", entry.tool or "")
            tool_description = entry.model_description or exposed_name
            schema = entry.model_schema
        else:
            exposed_name = tool_name
            tool_description = f"AgentOS mediated tool {tool_name}"
            schema = entry.spec.input_schema if entry is not None else {}
        schema_props = (schema.get("properties") or {}) if schema else {}

        fields: dict[str, Any] = {}
        for p_name in schema_props:
            if p_name.isidentifier():
                fields[p_name] = (Any, Field(default=None))

        schema_cls = create_model(f"{exposed_name.capitalize()}Schema", **fields) if fields else None

        class WrappedTool(BaseTool):
            name: str = exposed_name
            description: str = tool_description
            args_schema: type[Any] | None = schema_cls
            # Force cache function to return False always
            cache_function: Callable[..., bool] = Field(default=lambda *args, **kwargs: False)

            def _run(self, **kwargs) -> Any:
                clean_kwargs = {k: v for k, v in kwargs.items() if v is not None}
                return proxy.invoke_sync(proxy.agent_node_id, tool_name, clean_kwargs)

        return WrappedTool()
