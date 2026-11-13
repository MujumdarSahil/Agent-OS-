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
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass
from agentos.storage.ports import Storage


class MockTransport:
    """Default in-memory transport recording calls with idempotency keys."""

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
    ) -> None:
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

    def invoke_sync(self, agent_node_id: str, tool_name: str, call_args: dict[str, Any]) -> Any:
        """Synchronous entrypoint called from CrewAI worker threads."""
        future = asyncio.run_coroutine_threadsafe(
            self.invoke(agent_node_id, tool_name, call_args),
            self._loop,
        )
        return future.result()

    async def invoke(self, agent_node_id: str, tool_name: str, call_args: dict[str, Any]) -> Any:
        """Asynchronously mediate, inspect, validate, and execute an agent tool call."""
        tool_spec = BUILTIN_NODE_SPECS.get(tool_name) or NodeSpec(type=tool_name)

        # 1. Pinned argument verification: reject any attempt to override pinned arguments
        for p_key, p_val in self.pinned_args.items():
            arg_name = p_key
            if p_key.startswith(f"{tool_name}."):
                arg_name = p_key[len(tool_name) + 1:]

            if arg_name in call_args:
                # If LLM supplied a value differing from pinned value -> REJECT
                if call_args[arg_name] != p_val:
                    await self.storage.events.append(
                        run_id=self.run_id,
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
        if tool_spec.side_effect == SideEffectClass.EXTERNAL_SEND:
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
                await self.storage.events.append(
                    run_id=self.run_id,
                    type="tool_call_blocked",
                    data={
                        "agent_node": agent_node_id,
                        "tool_name": tool_name,
                        "reason": violation.reason,
                    },
                )
                raise SinkRuleViolationError(violation)

        # 3. Check sink rules using the shared rule engine
        if tool_spec.sink_rules:
            to_val = final_args.get("to")
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
                    await self.storage.events.append(
                        run_id=self.run_id,
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
        tool_ev = await self.storage.events.append(
            run_id=self.run_id,
            type="tool_called",
            data={
                "agent_node": agent_node_id,
                "tool_name": tool_name,
                "args": final_args,
            },
        )

        # 5. Execute tool or sink pipeline
        if tool_spec.side_effect == SideEffectClass.EXTERNAL_SEND:
            idempotency_key = f"{self.run_id}:{agent_node_id}:{tool_name}:{tool_ev.seq}"
            # Append sink_intent event
            await self.storage.events.append(
                run_id=self.run_id,
                type="sink_intent",
                data={
                    "sink_node": agent_node_id,
                    "tool_name": tool_name,
                    "idempotency_key": idempotency_key,
                    "args": final_args,
                },
            )

            # Transport call with idempotency key
            transport = self.transport_registry.get(tool_name)
            if transport and hasattr(transport, "send"):
                result = transport.send(idempotency_key=idempotency_key, **final_args)
            else:
                result = {"status": "sent", "idempotency_key": idempotency_key}

            # Append sink_committed event
            await self.storage.events.append(
                run_id=self.run_id,
                type="sink_committed",
                data={
                    "sink_node": agent_node_id,
                    "tool_name": tool_name,
                    "idempotency_key": idempotency_key,
                    "result": result,
                },
            )
            ret_val = f"Email successfully dispatched to {final_args.get('to')}"
        elif tool_name == "fetch_url":
            url = final_args.get("url", "")
            ret_val = f"Simulated content from {url}: [Status 200 OK, payload: safe payload]"
        else:
            ret_val = f"Executed {tool_name} successfully with args: {final_args}"

        # 6. Accumulate tool output label: tool outputs are untrusted sources
        tool_output_label = Label.untrusted(sources={tool_name})
        self.agent_context_label = self.agent_context_label.join(tool_output_label)

        return ret_val

    def create_wrapped_tool(self, tool_name: str) -> BaseTool:
        """Create a CrewAI BaseTool wrapping the proxy with caching strictly disabled."""
        proxy = self
        tool_spec = BUILTIN_NODE_SPECS.get(tool_name) or NodeSpec(type=tool_name)
        schema_props = (tool_spec.input_schema.get("properties") or {}) if tool_spec.input_schema else {}

        fields: dict[str, Any] = {}
        for p_name in schema_props:
            fields[p_name] = (Any, Field(default=None))

        schema_cls = create_model(f"{tool_name.capitalize()}Schema", **fields) if fields else None

        class WrappedTool(BaseTool):
            name: str = tool_name
            description: str = f"AgentOS mediated tool {tool_name}"
            args_schema: type[Any] | None = schema_cls
            # Force cache function to return False always
            cache_function: Callable[..., bool] = Field(default=lambda *args, **kwargs: False)

            def _run(self, **kwargs) -> Any:
                clean_kwargs = {k: v for k, v in kwargs.items() if v is not None}
                return proxy.invoke_sync(proxy.agent_node_id, tool_name, clean_kwargs)

        return WrappedTool()
