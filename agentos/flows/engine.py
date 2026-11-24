"""AgentOS Flow Engine for event-sourced workflow execution.

Features:
- Event-sourced execution on 1.2 storage ports (storage.runs, storage.events, storage.checkpoints).
- State rebuilt from append-only events; checkpoints serve as optional verified snapshots.
- Node states: queued, running, waiting, succeeded, failed, cancelled.
- Ready nodes run concurrently (concurrent branches + join).
- Per-node timeout support.
- CrewAI execution via asyncio.to_thread (note: Python OS threads cannot be forcefully killed on cancellation;
  cancellation marks the node cancelled and halts downstream scheduling).
- Runtime validators output constrained types (bool, bounded number, allowlist canonical entry), never raw input text.
- Recipient handling: validates email formatting (rejects comma-joined and display-name formats) and normalizes case.
- Sinks: sink_intent -> transport(idempotency_key) -> sink_committed.
- Approval: run moves to waiting and is persisted with no background task held; approve(run_id, node_id, decision) resumes it.
- Provenance tracking: get_provenance_chain traces backwards from any event to originating trigger.
"""

from __future__ import annotations

import asyncio
import logging
import json
import os
import time
import uuid
from typing import Any

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.models import FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy, MockTransport, transport_send
from agentos.flows.tool_catalog import BUILTIN_CATALOG, ToolCatalog, ToolLookupError, agent_initial_context
from agentos.flows.rules import (
    RuleViolation,
    SinkRuleViolationError,
    evaluate_sink_argument_rule,
    normalize_and_validate_recipients,
)
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass
from agentos.flows.state import FlowRunState, NodeState, RunStatus
from agentos.flows import control_nodes as cn
from agentos.flows import extraction as ex
from agentos.flows.calculator import calculator_output_labels
from agentos.usage.guard import BudgetExceeded, RunLimitExceeded
from agentos.flows.net_guard import SSRFBlockedError
from agentos.storage.models import EventRecord, RunRecord
from agentos.storage.ports import FencingTokenError, Storage

# 3.4 Part 0a: CrewAI (behind the agent node) sends usage telemetry to telemetry.crewai.com by default. AgentOS
# makes no outbound connection the operator did not configure, so it is off unless explicitly enabled
# (CREWAI_DISABLE_TELEMETRY=false). CrewAI reads the variable on every telemetry call.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")


def execute_validator_runtime(
    node: NodeDefinition,
    raw_inputs: dict[str, Any],
    policy: SecurityPolicy,
    inbound: Label | None = None,
) -> tuple[dict[str, Any], Label]:
    """Execute a validator node at run time (2.5b hardening: same constraint code as quarantined extraction).

    Outputs ONLY the validated value (enum member after trimming whitespace, real bool or the exact strings
    "true"/"false", integer in [min, max], built-in pattern, or the canonical admin allowlist entry), never the
    original input. An unconstrained or incomplete config (including flows published before 2.5b) fails closed:
    ``ExtractionRejected("invalid_config")``, nothing is declassified. The label comes from the shared
    ``validator_output_labels`` (the analyzer uses the same function): trusted, the INBOUND confidentiality,
    inbound sources plus a ``declassified:validator:<node>`` marker. ``inbound`` defaults to an untrusted,
    internal label with no sources for direct callers.
    """
    inbound = inbound if inbound is not None else Label.untrusted()
    outputs = ex.run_validator(node.config, raw_inputs, policy.allowlists)
    return outputs, ex.validator_output_labels(node.id, node.config, inbound, policy.allowlists)["*"]


class FlowEngine:
    """Event-sourced runtime engine for AgentOS workflows."""

    def __init__(
        self,
        flow: FlowDefinition,
        storage: Storage,
        policy: SecurityPolicy | None = None,
        transport_registry: dict[str, Any] | None = None,
        custom_llm: Any | None = None,
        track_labels: bool = True,
        lease_id: str | None = None,
        fencing_checker: Any | None = None,
        subflow_depth: int = 0,
        max_subflow_depth: int = cn.MAX_SUBFLOW_DEPTH,
        secret_resolver: Any | None = None,
        clock: Any | None = None,
        mcp_manager: Any | None = None,
        expected_mcp_hashes: dict[str, str] | None = None,
        usage: Any | None = None,
        sandbox: Any | None = None,
    ) -> None:
        # 3.2: usage ledger, budgets and run limits (default: built-in run limits, no budgets, no ledger)
        from agentos.usage.guard import UsageContext

        # 3.5: sandbox service for the code tools (None: python_exec / shell_exec / file_* refuse, fail closed)
        self.sandbox = sandbox
        self.usage = usage or UsageContext.default()
        self._guards: dict[str, Any] = {}
        # 2.5a: MCP tools run through this manager; hashes recorded at publish are re-checked per run
        self.mcp_manager = mcp_manager
        self.expected_mcp_hashes = expected_mcp_hashes
        # 2.3: subflow nesting, vault credential resolution for http_request headers, injectable clock
        self.subflow_depth = subflow_depth
        self.max_subflow_depth = max_subflow_depth
        self.secret_resolver = secret_resolver
        self.clock = clock or time.time
        self._scopes = cn.branch_scopes(flow)
        self._control_labels: dict[str, Label | None] = {}
        self.flow = flow
        self.storage = storage
        self.policy = policy or SecurityPolicy()
        self.transport_registry = transport_registry or {"send_email": MockTransport()}
        self.custom_llm = custom_llm
        self.track_labels = track_labels
        self.lease_id = lease_id
        self.fencing_checker = fencing_checker

    def _check_fencing(self, run_id: str) -> None:
        """Requirement 1: Fencing check before state change, transport send, or event append."""
        if self.lease_id is not None:
            if self.fencing_checker is None:
                raise FencingTokenError(
                    f"Lease {self.lease_id!r} is active for run {run_id!r} but no fencing_checker configured (fail closed)"
                )
            if not self.fencing_checker(run_id, self.lease_id):
                raise FencingTokenError(
                    f"Lease {self.lease_id!r} has expired or been superseded for run {run_id!r}"
                )
        elif self.fencing_checker is not None:
            if not self.fencing_checker(run_id, None):
                raise FencingTokenError(
                    f"Fencing check rejected unleased execution for run {run_id!r}"
                )

    async def _append_event(
        self,
        run_id: str,
        type: str,
        data: dict[str, Any] | None = None,
    ) -> EventRecord:
        """Append an event carrying the worker lease_id with fencing token check."""
        self._check_fencing(run_id)
        return await self.storage.events.append(
            run_id=run_id,
            type=type,
            data=data,
            lease_id=self.lease_id,
        )

    async def run(
        self,
        run_id: str | None = None,
        inputs: dict[str, Any] | None = None,
        raise_on_error: bool = False,
        trigger: str = "manual",
        input_labels: dict[str, Any] | None = None,
    ) -> FlowRunState:
        """Execute flow graph from entrypoint.

        ``input_labels`` (label dicts per input name) is used only for trigger == "subflow", so a
        child flow keeps the labels of the values its parent passed in.
        """
        run_id = run_id or f"run_{uuid.uuid4().hex[:12]}"
        inputs = inputs or {}

        # 1. Initialize run record and append run_started event
        self._check_fencing(run_id)
        existing = await self.storage.runs.get(run_id)
        run_record = RunRecord(
            run_id=run_id,
            mission_name=self.flow.id,
            flow_id=self.flow.id,
            # keep the version the run was enqueued for (needed to re-enqueue a due wait timer)
            flow_version=existing.flow_version if existing else None,
            # 2.4d: keep what started the run (set by the route/webhook/scheduler that created it)
            trigger=(existing.trigger if existing and existing.trigger else trigger),
            # 3.4: who started it ({user_id, username}, set by the route that created the run)
            started_by=existing.started_by if existing else None,
            current_lease_id=self.lease_id,
            status=RunStatus.RUNNING.value,
        )
        await self.storage.runs.put(run_record)

        ev = await self._append_event(
            run_id=run_id,
            type="run_started",
            data={
                "flow_id": self.flow.id,
                "entrypoint": self.flow.entrypoint,
                "inputs": inputs,
                "trigger": trigger,
                **({"started_by": existing.started_by} if existing and existing.started_by else {}),
                **({"input_labels": input_labels} if trigger == "subflow" and input_labels else {}),
            },
        )

        state = FlowRunState(run_id=run_id)
        state.apply_event(ev)

        # 2. Execute flow execution loop
        return await self._execution_loop(state, raise_on_error=raise_on_error)

    async def resume(self, run_id: str, raise_on_error: bool = False) -> FlowRunState:
        """Resume flow execution from storage after an exception or process restart."""
        # 1. Check for optional checkpoint snapshot
        checkpoint = await self.storage.checkpoints.load_latest_checkpoint(run_id)
        events = await self.storage.events.list(run_id, after_seq=0)

        if checkpoint and "state" in checkpoint:
            state = FlowRunState.from_snapshot_and_events(checkpoint["state"], events)
        else:
            state = FlowRunState.rebuild_from_events(run_id, events)

        if state.status in (RunStatus.SUCCEEDED, RunStatus.CANCELLED):
            return state

        # If waiting for approval, resume cannot continue without approval decision.
        # 2.3: a due wait-node timer resumes the run.
        if state.status == RunStatus.WAITING:
            details = state.waiting_details or {}
            if details.get("reason") != "timer" or self.clock() < float(details.get("resume_at") or 0):
                return state
            nid = details["node_id"]
            fired = await self._append_event(run_id=run_id, type="timer_fired", data={"node_id": nid})
            state.apply_event(fired)
            in_lbls = state.node_input_labels.get(nid, {})
            lbl = Label.join_all(list(in_lbls.values()), default=Label.trusted())
            outputs = {**state.node_inputs.get(nid, {}), "resumed_at": self.clock()}
            succ = await self._append_event(
                run_id=run_id, type="node_succeeded",
                data={"node_id": nid, "outputs": outputs,
                      "output_labels": {"*": lbl.model_dump(mode="json"), "resumed_at": Label.trusted().model_dump(mode="json")}},
            )
            state.apply_event(succ)
            await self._update_run_status(state, RunStatus.RUNNING, resume_at=None)
            return await self._execution_loop(state, raise_on_error=raise_on_error)

        # Check for uncommitted agent sink intents (Requirement 1.c)
        # An agent node with sink_intent but no matching sink_committed must NOT be re-executed;
        # it moves to waiting with reason "uncommitted_sink_needs_review" (an LLM rerun may produce different args).
        committed_keys = {
            (e.data or {}).get("idempotency_key")
            for e in events
            if e.type == "sink_committed"
        }
        uncommitted_intents = [
            e for e in events
            if e.type == "sink_intent"
            and (
                (self.flow.nodes.get((e.data or {}).get("sink_node")) and self.flow.nodes[(e.data or {}).get("sink_node")].type == "agent")
                or bool((e.data or {}).get("tool_name"))
                # 3.3: a direct sink whose transport is a real channel (SMTP, Slack) may already have sent
                or self._sink_not_retry_safe((e.data or {}).get("sink_node"))
            )
            and (e.data or {}).get("idempotency_key") not in committed_keys
        ]

        if uncommitted_intents:
            first_uncommitted = uncommitted_intents[0]
            nid = (first_uncommitted.data or {}).get("sink_node")
            intent_key = (first_uncommitted.data or {}).get("idempotency_key")
            intent_args = (first_uncommitted.data or {}).get("args", {})

            wait_data = {
                "node_id": nid,
                "reason": "uncommitted_sink_needs_review",
                "idempotency_key": intent_key,
                "args": intent_args,
            }
            wait_ev = await self._append_event(
                run_id=state.run_id,
                type="node_waiting",
                data=wait_data,
            )
            state.apply_event(wait_ev)
            run_wait_ev = await self._append_event(
                run_id=state.run_id,
                type="run_waiting",
                data={"node_id": nid, "reason": "uncommitted_sink_needs_review"},
            )
            state.apply_event(run_wait_ev)
            await self._update_run_status(state, RunStatus.WAITING)
            return state

        # Reset failed status to running for resume attempt
        state.status = RunStatus.RUNNING
        state.error = None

        # Any node that failed or was interrupted while QUEUED or RUNNING is reset for retry
        for nid, nstate in list(state.node_states.items()):
            if nstate in (NodeState.RUNNING, NodeState.QUEUED, NodeState.FAILED):
                del state.node_states[nid]

        return await self._execution_loop(state, raise_on_error=raise_on_error)

    def _sink_not_retry_safe(self, node_id: Any) -> bool:
        node = self.flow.nodes.get(node_id) if isinstance(node_id, str) else None
        if node is None:
            return False
        transport = self.transport_registry.get(node.type)
        return transport is not None and not getattr(transport, "retry_safe", True)

    async def approve(self, run_id: str, node_id: str, decision: Any,
                      actor: dict[str, Any] | None = None) -> FlowRunState:
        """Deliver operator approval decision and resume flow execution.

        3.4: ``actor`` ({user_id, username}) is recorded as ``decided_by`` on the approval_decision event.

        Requirement 6:
        - Only for runs in waiting at the named approval node.
        - Idempotent: a second call is a no-op returning the same result.
        - Decision can be "reject" (fails/cancels run cleanly without executing sink).
        """
        events = await self.storage.events.list(run_id, after_seq=0)
        state = FlowRunState.rebuild_from_events(run_id, events)

        # Normalize requested decision
        is_approved = decision is True or str(decision).lower() in ("true", "approve", "approved")

        # Idempotency check: if an approval_decision already exists for this node
        for e in events:
            if e.type == "approval_decision" and (e.data or {}).get("node_id") == node_id:
                past_dec = (e.data or {}).get("decision")
                past_approved = past_dec is True or str(past_dec).lower() in ("true", "approve", "approved")
                if is_approved == past_approved:
                    return state
                raise ValueError(
                    f"Run {run_id!r} node {node_id!r} was already decided as {past_dec!r}"
                )

        if state.status != RunStatus.WAITING or state.waiting_node != node_id:
            raise ValueError(
                f"Run {run_id!r} is not currently waiting for approval on node {node_id!r} "
                f"(status={state.status.value!r}, waiting_node={state.waiting_node!r})"
            )

        shown_args = (state.waiting_details or {}).get("arguments", {})

        # Append approval decision event with exact argument values shown to operator
        ev = await self._append_event(
            run_id=run_id,
            type="approval_decision",
            data={
                "node_id": node_id,
                "decision": is_approved,
                "raw_decision": decision,
                "arguments": shown_args,
                **({"decided_by": actor} if actor else {}),
            },
        )
        state.apply_event(ev)

        if is_approved:
            # Approval declassifies approved arguments to trusted for downstream sink
            out_label = Label.trusted(sources={node_id})
            succ_ev = await self._append_event(
                run_id=run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": {
                        "approved": True,
                        "data": shown_args,
                        **shown_args,
                    },
                    "output_labels": {
                        "approved": out_label.model_dump(mode="json"),
                        "data": out_label.model_dump(mode="json"),
                        "*": out_label.model_dump(mode="json"),
                    },
                },
            )
            state.apply_event(succ_ev)
            # Continue flow execution
            return await self._execution_loop(state)
        else:
            # Rejection stops the flow cleanly without executing sinks
            fail_ev = await self._append_event(
                run_id=run_id,
                type="node_failed",
                data={
                    "node_id": node_id,
                    "error": "rejected_by_operator",
                },
            )
            state.apply_event(fail_ev)
            await self._update_run_status(state, RunStatus.FAILED, error="rejected_by_operator")
            return state

    async def get_provenance_chain(self, run_id: str, target_seq: int) -> list[EventRecord]:
        """Trace the provenance chain from target_seq backwards to originating trigger event."""
        all_events = await self.storage.events.list(run_id, after_seq=0)
        events_by_seq = {e.seq: e for e in all_events}

        if target_seq not in events_by_seq:
            raise ValueError(f"Event with seq {target_seq} not found in run {run_id!r}")

        target_ev = events_by_seq[target_seq]
        chain: list[EventRecord] = [target_ev]

        # Trace backwards along chronological event history for involved nodes
        curr_node = (target_ev.data or {}).get("node_id") or (target_ev.data or {}).get("agent_node")
        visited_nodes: set[str] = set()
        if curr_node:
            visited_nodes.add(curr_node)

        for seq in range(target_seq - 1, 0, -1):
            ev = events_by_seq.get(seq)
            if not ev:
                continue

            node_id = (ev.data or {}).get("node_id") or (ev.data or {}).get("agent_node")
            # If event belongs to a node that fed into visited nodes, include it
            if ev.type in ("run_started", "run_waiting"):
                chain.append(ev)
            elif node_id and (node_id in visited_nodes or not visited_nodes):
                chain.append(ev)
                # Find upstream dependencies for this node
                for edge in self.flow.edges:
                    if edge.target == node_id:
                        visited_nodes.add(edge.source)

        chain.reverse()
        return chain

    async def _execution_loop(
        self,
        state: FlowRunState,
        raise_on_error: bool = False,
    ) -> FlowRunState:
        """Drive DAG execution loop, running ready nodes concurrently until completion or wait."""
        first_exception: Exception | None = None

        while True:
            # 2.3: mark nodes on branches that were not taken as skipped (propagates downstream)
            await self._skip_dead_branches(state)

            # Identify ready nodes: un-started nodes whose upstream dependencies have succeeded
            ready_nodes = self._get_ready_nodes(state)

            if not ready_nodes:
                if state.status == RunStatus.WAITING:
                    # Flow is waiting for approval
                    await self._update_run_status(state, RunStatus.WAITING)
                    await self._save_checkpoint(state)
                    return state

                if all(cn.node_done(state, nid) for nid in self.flow.nodes):
                    # Flow finished successfully
                    ev = await self._append_event(
                        run_id=state.run_id,
                        type="run_succeeded",
                        data={"outputs": state.node_outputs},
                    )
                    state.apply_event(ev)
                    await self._update_run_status(state, RunStatus.SUCCEEDED)
                    await self._save_checkpoint(state)
                    return state

                # If any node failed and no more nodes can proceed -> run failed
                if any(
                    st == NodeState.FAILED and nid not in state.handled_failures
                    for nid, st in state.node_states.items()
                ):
                    ev = await self._append_event(
                        run_id=state.run_id,
                        type="run_failed",
                        data={"error": state.error or "Node failure halted execution"},
                    )
                    state.apply_event(ev)
                    await self._update_run_status(state, RunStatus.FAILED, error=state.error)
                    if raise_on_error and first_exception:
                        raise first_exception
                    return state

                if raise_on_error and first_exception:
                    raise first_exception
                return state

            # Mark ready nodes queued
            for nid in ready_nodes:
                q_ev = await self._append_event(
                    run_id=state.run_id,
                    type="node_queued",
                    data={"node_id": nid},
                )
                state.apply_event(q_ev)

            # Ready nodes run concurrently via asyncio.gather (two-branch + join)
            tasks = [self._execute_single_node(state, nid) for nid in ready_nodes]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for nid, res in zip(ready_nodes, results):
                if isinstance(res, Exception) and self._has_error_handler(nid) and self._is_handleable(res):
                    # 2.3: route the failure to the node's error_handler; the run continues.
                    handled_ev = await self._append_event(
                        run_id=state.run_id,
                        type="node_failed",
                        data={
                            "node_id": nid,
                            "error": str(res),
                            "handled": True,
                            "error_info": {
                                "failed_node": nid,
                                "error_type": type(res).__name__,
                                "message": str(res)[:2000],
                            },
                        },
                    )
                    state.apply_event(handled_ev)
                    continue
                if isinstance(res, Exception):
                    if first_exception is None:
                        first_exception = res
                    state.error = str(res)
                    fail_ev = await self._append_event(
                        run_id=state.run_id,
                        type="node_failed",
                        # 2.4e: error_type (class name only) lets read models tell security blocks
                        # (sink rule, pinned override, SSRF) from ordinary failures.
                        data={"node_id": nid, "error": str(res), "error_type": type(res).__name__},
                    )
                    state.apply_event(fail_ev)

            # Save progress snapshot
            await self._save_checkpoint(state)

            if state.status == RunStatus.WAITING:
                await self._update_run_status(state, RunStatus.WAITING)
                return state

            if state.error:
                ev = await self._append_event(
                    run_id=state.run_id,
                    type="run_failed",
                    data={"error": state.error},
                )
                state.apply_event(ev)
                await self._update_run_status(state, RunStatus.FAILED, error=state.error)
                if raise_on_error and first_exception:
                    raise first_exception
                return state

    async def _agent_tool_catalog(self, state: FlowRunState, node_id: str, node: NodeDefinition) -> tuple[ToolCatalog, list[Any]]:
        """2.5a: the tool catalog for an agent node, failing closed before the agent runs if an MCP tool
        is not approved now or its hash differs from the one recorded when the flow was published."""
        from agentos.mcp.catalog import is_mcp_name

        names = list(node.config.get("tools", []) or [])
        if not any(is_mcp_name(n) for n in names):
            return BUILTIN_CATALOG, [e for e in (BUILTIN_CATALOG.try_resolve(n) for n in names) if e is not None]
        repo = getattr(self.storage, "mcp_servers", None)
        catalog = ToolCatalog(await repo.list() if repo is not None else [])
        entries = []
        for name in names:
            try:
                entry = catalog.resolve(name)
            except ToolLookupError as err:
                if not is_mcp_name(name):
                    continue  # unknown bare names: rejected by the proxy if the model calls them (as before)
                await self._append_event(run_id=state.run_id, type="tool_call_rejected", data={
                    "agent_node": node_id, "tool_name": err.name, "lookup": err.reason, "reason": f"{err} (fail closed)",
                })
                raise ValueError(f"{err} (fail closed)") from err
            if entry.is_mcp and self.expected_mcp_hashes is not None:
                published = self.expected_mcp_hashes.get(entry.name)
                if published != entry.sha256:
                    await self._append_event(run_id=state.run_id, type="mcp_tool_hash_mismatch", data={
                        "agent_node": node_id, "tool_name": entry.name,
                        "published_sha256": published, "current_sha256": entry.sha256,
                    })
                    raise ValueError(f"MCP tool {entry.name!r} differs from the version this flow was published with "
                                     f"(fail closed); publish the flow again after review")
            entries.append(entry)
        return catalog, entries

    async def _run_extraction(
        self, state: FlowRunState, node: NodeDefinition, inputs: dict[str, Any], effective_inbound: Label
    ) -> tuple[dict[str, Any], dict[str, Label]]:
        """2.5b quarantined extraction (design: docs/evidence/2.5b.md).

        One direct model call (never CrewAI: no tools, function calling, memory or agent loop); the router
        makes one attempt per provider and nothing feeds invalid output back. The raw output is never passed
        on or stored: events carry only its length and sha256. Any failure goes to ``on_invalid``.
        """
        cfg = node.config
        fields = cfg.get("fields") or []
        allowlists = self.policy.allowlists
        inbound = ex.shared_inbound(self.flow, node.id, state.node_output_labels, effective_inbound)
        labels = ex.extraction_output_labels(node.id, fields, inbound)

        value = inputs.get(cfg.get("input") or "text")
        text = value if isinstance(value, str) else ("" if value is None else json.dumps(value, default=str))
        messages, truncated, input_chars = ex.build_messages(cfg, text, allowlists)
        provider: str | None = None
        model: str | None = None
        raw: Any = None
        started = time.perf_counter()
        try:
            if value is None:
                raise ex.ExtractionRejected("missing_input")
            secret = inbound.confidentiality == Confidentiality.SECRET.value
            if self.custom_llm is not None:
                # Test double / injected model: it must declare itself local for SECRET input (T-13).
                if secret and not getattr(self.custom_llm, "is_local", False):
                    raise ex.ExtractionRejected("model_refused")
                provider, model = "custom", str(getattr(self.custom_llm, "model", "custom"))
                raw = await asyncio.to_thread(self.custom_llm.call, messages)
            elif os.environ.get("AGENTOS_MOCK_LLM") == "1":
                provider, model = "mock", "mock-extraction"
                raw = ex.mock_output(cfg, allowlists)
            else:
                records: list[dict[str, Any]] = []
                guard = await self._usage_guard(state)
                router = self._router_llm(state, node, inbound, asyncio.get_running_loop(), extra_on_call=records.append,
                                          guard=guard)
                try:
                    raw = await asyncio.to_thread(router.call, messages, None)
                except (RunLimitExceeded, BudgetExceeded):
                    raise  # 3.2: the run stops with that reason (never turned into defaults)
                except Exception:
                    raise ex.ExtractionRejected("model_refused" if secret else "model_failed") from None
                finally:
                    ok = next((r for r in reversed(records) if r.get("provider")), {})
                    provider, model = ok.get("provider"), ok.get("model")
            values = ex.parse_output(raw, cfg, allowlists)
        except ex.ExtractionRejected as rej:
            raw_len, raw_sha = ex.raw_digest(raw)
            use_defaults = cfg.get("on_invalid", "fail") == "default" and rej.reason not in ("missing_input",)
            await self._append_event(run_id=state.run_id, type="extraction_rejected", data={
                "node_id": node.id, "reason": rej.reason, "field": rej.field, "provider": provider, "model": model,
                "input_chars": input_chars, "truncated": truncated, "raw_len": raw_len, "raw_sha256": raw_sha,
                "used_defaults": use_defaults,
            })
            if not use_defaults:
                raise ex.ExtractionRejected(rej.reason, rej.field,
                                            f"Quarantined extraction {node.id!r} rejected the model output "
                                            f"({rej.reason}{', field ' + rej.field if rej.field else ''})") from None
            values = ex.defaults_or_raise(cfg, allowlists)
        else:
            raw_len, raw_sha = ex.raw_digest(raw)
            await self._append_event(run_id=state.run_id, type="extraction_completed", data={
                "node_id": node.id, "fields": values, "input_chars": input_chars, "truncated": truncated,
                "provider": provider, "model": model,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                "raw_len": raw_len, "raw_sha256": raw_sha,
            })
        await self._append_event(run_id=state.run_id, type="declassified", data={
            "node_id": node.id, "kind": ex.NODE_TYPE, "fields": [f["name"] for f in fields],
            "source_sources": sorted(inbound.sources),
        })
        return values, labels

    async def _usage_guard(self, state: FlowRunState) -> Any:
        """3.2: one RunGuard per run (run limits + budgets), seeded from the run's existing llm_call events."""
        guard = self._guards.get(state.run_id)
        if guard is None:
            from agentos.usage.guard import RunGuard

            settings = await self.usage.get_settings()
            loop = asyncio.get_running_loop()
            run_id = state.run_id

            def emit(type_: str, data: dict[str, Any]) -> None:
                asyncio.run_coroutine_threadsafe(self._append_event(run_id=run_id, type=type_, data=data),
                                                 loop).result(timeout=10)

            guard = RunGuard(self.usage, run_id, self.flow.id, settings, loop=loop, emit=emit)
            guard.seed([e.get("data") or {} for e in state.event_history if e.get("type") == "llm_call"])
            self._guards[run_id] = guard
        return guard

    def _with_cost(self, record: dict[str, Any]) -> dict[str, Any]:
        """3.2: cost_usd + price_source on every llm_call record (unknown price -> null, never guessed)."""
        from agentos.usage.ledger import today_utc
        from agentos.usage.pricing import cost_usd

        out = dict(record)
        out["day"] = today_utc()
        if record.get("status") == "ok":
            price = self.usage.price(record.get("provider"), record.get("model"))
            out["cost_usd"] = cost_usd(price, int(record.get("prompt_tokens") or 0),
                                       int(record.get("completion_tokens") or 0))
            out["price_source"] = price.source
        else:
            out["cost_usd"] = 0.0  # no tokens were used: nothing to pay
            out["price_source"] = "no_tokens"
        return out

    async def _record_llm_call(self, run_id: str, record: dict[str, Any], guard: Any) -> None:
        """llm_call event, then the ledger (events are the source of truth; `agentos usage rebuild`), then the
        run guard's token count."""
        await self._append_event(run_id=run_id, type="llm_call", data=record)
        ledger = getattr(self.usage, "ledger", None)
        if ledger is not None:
            from agentos.usage.ledger import increments

            try:
                await ledger.add(increments(record, self.flow.id, record.get("day")))
            except Exception as e:  # the event is written; a lagging ledger is rebuilt from events
                logging.getLogger(__name__).warning("usage ledger update failed: %s", type(e).__name__)
        if guard is not None:
            guard.after_record(record)

    def _router_llm(
        self, state: FlowRunState, node: NodeDefinition, inbound: Label, loop: Any,
        extra_on_call: Any | None = None, guard: Any | None = None,
    ) -> Any:
        """AgentOSRouterLLM for an agent/llm node. Called from the event loop; used from worker threads."""
        from agentos.llm.router_llm import AgentOSRouterLLM

        run_id = state.run_id

        def on_call(record: dict[str, Any]) -> None:
            if extra_on_call is not None:
                extra_on_call(record)
            fut = asyncio.run_coroutine_threadsafe(
                self._record_llm_call(run_id, self._with_cost(record), guard), loop
            )
            fut.result(timeout=10)

        def key_lookup(provider: str, env_name: str | None) -> str | None:
            if self.secret_resolver is None or not env_name:
                return None
            try:
                secret = self.secret_resolver(env_name)
                if asyncio.iscoroutine(secret):
                    return asyncio.run_coroutine_threadsafe(secret, loop).result(timeout=5)
                return secret
            except Exception:
                return None  # not in the vault: fall back to the environment

        return AgentOSRouterLLM(
            preferred_model=node.config.get("model") or node.config.get("llm"),
            key_lookup=key_lookup,
            on_call=on_call,
            # THREAT_MODEL T-13: secret-labelled input may only reach local providers.
            local_only=inbound.confidentiality == Confidentiality.SECRET.value,
            node_id=node.id,
            guard=guard,
        )

    _STARTED = (
        NodeState.RUNNING,
        NodeState.SUCCEEDED,
        NodeState.FAILED,
        NodeState.WAITING,
        NodeState.CANCELLED,
        NodeState.SKIPPED,
    )

    def _get_ready_nodes(self, state: FlowRunState) -> list[str]:
        """Return IDs of un-started nodes whose inbound edges are resolved and active.

        Unbranched edges are active once their source SUCCEEDED (pre-2.3 behaviour); 2.3 adds
        condition branches, on_error edges and merge modes (see control_nodes.readiness).
        """
        return [
            node_id
            for node_id in self.flow.nodes
            if state.node_states.get(node_id) not in self._STARTED
            and cn.readiness(self.flow, state, node_id) == "ready"
        ]

    async def _skip_dead_branches(self, state: FlowRunState) -> None:
        changed = True
        while changed:
            changed = False
            for node_id in self.flow.nodes:
                if state.node_states.get(node_id) in self._STARTED:
                    continue
                if cn.readiness(self.flow, state, node_id) == "skip":
                    ev = await self._append_event(run_id=state.run_id, type="node_skipped", data={"node_id": node_id})
                    state.apply_event(ev)
                    changed = True

    def _has_error_handler(self, node_id: str) -> bool:
        return any(e.source == node_id and e.branch == "on_error" for e in self.flow.edges)

    @staticmethod
    def _is_handleable(err: Exception) -> bool:
        # Security blocks and lease loss always stop the run; they are never routed to a handler.
        return not isinstance(err, (SinkRuleViolationError, SSRFBlockedError, FencingTokenError))

    def _sink_call_preview(self, state: FlowRunState, approval_node: Any) -> dict[str, Any]:
        """Every argument of the sink an approval node approves, for the approval card (display only).

        - pinned args: value + the trusted label pinned values carry, marked ``pinned``;
        - args mapped from the approval node: ``via_approval`` (their exact values/labels are in ``arguments``);
        - args mapped from other nodes: current value + label, or ``pending`` if that node has not run.
        """
        approves = approval_node.config.get("approves", {}) or {}
        sink_id = approves.get("sink_node")
        sink = self.flow.nodes.get(sink_id) if sink_id else None
        if sink is None:
            return {}
        preview: dict[str, Any] = {}
        for name, value in (sink.pinned_args or {}).items():
            preview[name] = {"value": value, "pinned": True, "label": Label.trusted(sources={sink_id}).model_dump(mode="json")}
        for edge in self.flow.edges:
            if edge.target != sink_id:
                continue
            for arg, field in edge.arg_mapping.items():
                if arg in preview:
                    continue
                if edge.source == approval_node.id:
                    preview[arg] = {"via_approval": True}
                    continue
                outputs = state.node_outputs.get(edge.source)
                if outputs is None or field not in outputs:
                    preview[arg] = {"pending": True, "source": edge.source}
                    continue
                lbl = state.node_output_labels.get(edge.source, {}).get(field)
                preview[arg] = {"value": outputs[field], "source": edge.source,
                                "label": lbl.model_dump(mode="json") if lbl else None}
        return preview

    async def _execute_single_node(self, state: FlowRunState, node_id: str) -> None:
        """Execute a single node within its configured timeout and record events."""
        node = self.flow.nodes[node_id]
        spec = BUILTIN_NODE_SPECS.get(node.type) or NodeSpec(type=node.type)

        # Collect inbound arguments and labels from upstream outputs
        inbound_args: dict[str, Any] = {}
        inbound_labels: dict[str, Label] = {}

        inbound_edges = [e for e in self.flow.edges if e.target == node_id]
        for edge in inbound_edges:
            src_outputs = state.node_outputs.get(edge.source, {})
            src_labels = state.node_output_labels.get(edge.source, {})
            for target_arg, src_field in edge.arg_mapping.items():
                if src_field in src_outputs:
                    inbound_args[target_arg] = src_outputs[src_field]
                if src_field in src_labels:
                    inbound_labels[target_arg] = src_labels[src_field]

        # For entrypoint, use run inputs if not mapped
        if node_id == self.flow.entrypoint:
            run_init_event = next(
                (e for e in state.event_history if e.get("type") == "run_started"), None
            )
            trigger_type = (run_init_event or {}).get("data", {}).get("trigger")
            # Runtime: entry-node inputs are UNTRUSTED for every trigger by default.
            # Allowlist: only trigger == "cron" may be trusted (inputs come from stored schedule config).
            # Unknown or missing trigger -> untrusted. Pinned args stay trusted.
            if trigger_type == "cron":
                init_lbl = Label.trusted(sources={node_id})
            else:
                init_lbl = Label.untrusted(sources={node_id})

            sub_labels = (run_init_event or {}).get("data", {}).get("input_labels")
            if trigger_type == "subflow" and isinstance(sub_labels, dict) and not inbound_args:
                # 2.3: a subflow keeps the labels of the values its parent passed in.
                raw_inputs = (run_init_event or {}).get("data", {}).get("inputs", {}) or {}
                inbound_args = dict(raw_inputs)
                parent = {k: Label.model_validate(v) for k, v in sub_labels.items()}
                fallback = Label.join_all(list(parent.values()), default=init_lbl)
                inbound_labels = {k: parent.get(k, fallback) for k in inbound_args}
                inbound_labels["*"] = fallback
                inbound_labels["payload"] = fallback
            elif not inbound_args:
                raw_inputs = (run_init_event or {}).get("data", {}).get("inputs", {})
                inbound_args = dict(raw_inputs) if isinstance(raw_inputs, dict) else {"payload": raw_inputs}
                inbound_labels = {"*": init_lbl, "payload": init_lbl}
                for k in inbound_args.keys():
                    inbound_labels[k] = init_lbl
            else:
                inbound_labels.setdefault("*", init_lbl)
                inbound_labels.setdefault("payload", init_lbl)

        # Apply author pinned arguments
        for k, v in node.pinned_args.items():
            if not k.startswith(f"{node.type}."):
                inbound_args[k] = v
                inbound_labels[k] = Label.trusted(sources={node_id})

        # 2.3: control-dependency label (join of deciding predicates), recorded for provenance
        control_lbl = cn.runtime_control_label(self._scopes, state, node_id)
        start_data: dict[str, Any] = {
            "node_id": node_id,
            "inputs": inbound_args,
            "input_labels": {k: v.model_dump(mode="json") for k, v in inbound_labels.items()},
        }
        if control_lbl is not None:
            start_data["control_label"] = control_lbl.model_dump(mode="json")
        self._control_labels[node_id] = control_lbl  # read by _dispatch_node (signature kept stable)
        start_ev = await self._append_event(
            run_id=state.run_id,
            type="node_started",
            data=start_data,
        )
        state.apply_event(start_ev)

        # Timeout configuration
        timeout = node.config.get("timeout_seconds") or spec.timeout_seconds

        t_node_start = time.perf_counter()
        try:
            if timeout and timeout > 0:
                await asyncio.wait_for(
                    self._dispatch_node(state, node, spec, inbound_args, inbound_labels),
                    timeout=timeout,
                )
            else:
                await self._dispatch_node(state, node, spec, inbound_args, inbound_labels)
            state.node_durations_ms[node_id] = (time.perf_counter() - t_node_start) * 1000.0
        except asyncio.TimeoutError as err:
            state.node_durations_ms[node_id] = (time.perf_counter() - t_node_start) * 1000.0
            if self._has_error_handler(node_id):
                raise  # the execution loop records it as a handled failure
            fail_ev = await self._append_event(
                run_id=state.run_id,
                type="node_failed",
                data={
                    "node_id": node_id,
                    "error": f"Node {node_id!r} timed out after {timeout}s",
                },
            )
            state.apply_event(fail_ev)
            raise

    async def _dispatch_node(
        self,
        state: FlowRunState,
        node: NodeDefinition,
        spec: NodeSpec,
        inputs: dict[str, Any],
        input_labels: dict[str, Label],
    ) -> None:
        """Dispatch execution based on node type."""
        node_id = node.id
        control_label = self._control_labels.get(node_id)
        effective_inbound = Label.join_all(list(input_labels.values()), default=Label.trusted())

        # 2.3 node catalog (dispatched before the generic sink branch)
        if node.type in ("condition", "merge", "error_handler", "subflow", "http_request"):
            if node.type == "condition":
                outputs, labels = cn.run_condition(self.flow, state, node, effective_inbound)
            elif node.type == "merge":
                outputs, labels = cn.run_merge(self.flow, state, node)
            elif node.type == "error_handler":
                outputs, labels = cn.run_error_handler(self.flow, state, node)
            elif node.type == "subflow":
                outputs, labels = await cn.run_subflow(self, state, node, inputs, input_labels)
            else:
                outputs, labels = await cn.run_http_request(self, state, node, inputs, input_labels, control_label)
            ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": outputs,
                    "output_labels": {k: v.model_dump(mode="json") for k, v in labels.items()},
                },
            )
            state.apply_event(ev)
            return

        if node.type == "wait":
            delay = float(node.config.get("delay_seconds", 0))
            resume_at = self.clock() + delay
            wait_ev = await self._append_event(
                run_id=state.run_id,
                type="node_waiting",
                data={"node_id": node_id, "reason": "timer", "resume_at": resume_at, "delay_seconds": delay},
            )
            state.apply_event(wait_ev)
            run_wait_ev = await self._append_event(
                run_id=state.run_id, type="run_waiting", data={"node_id": node_id, "reason": "timer"}
            )
            state.apply_event(run_wait_ev)
            await self._update_run_status(state, RunStatus.WAITING, resume_at=resume_at)
            return

        # 2.3: destructive sinks require a trusted control dependency (shared rule code)
        cn.check_control(
            node_id, spec.side_effect, control_label,
            approval_gated=ex.is_approval_gated(self.flow, node_id), policy=self.policy,
        )

        # 1. Trigger nodes (webhook_trigger, manual_trigger)
        if node.type in ("webhook_trigger", "manual_trigger"):
            out_label = Label.untrusted(sources={node_id})
            outputs = {"payload": inputs, "headers": {}}
            labels = {"payload": out_label, "headers": out_label, "*": out_label}
            ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": outputs,
                    "output_labels": {k: v.model_dump(mode="json") for k, v in labels.items()},
                },
            )
            state.apply_event(ev)
            return

        # 2. Validator node (Requirement 3: outputs constrained value, never original text)
        if node.type == "validator":
            # 2.5b hardening: shared inbound + shared labels (identical to publish); fail closed with an event
            inbound = ex.shared_inbound(self.flow, node_id, state.node_output_labels, effective_inbound)
            try:
                outputs, _ = execute_validator_runtime(node, inputs, self.policy, inbound)
            except ex.ExtractionRejected as rej:
                await self._append_event(run_id=state.run_id, type="validator_rejected", data={
                    "node_id": node_id, "reason": rej.reason, "field": rej.field,
                    "field_type": node.config.get("field_type"), "declassified": False,
                })
                if rej.reason == "invalid_config":
                    raise ex.ExtractionRejected(rej.reason, rej.field, (
                        f"Validator {node_id!r} cannot declassify (fail closed, nothing declassified): {rej}"
                    )) from None
                raise ex.ExtractionRejected(rej.reason, rej.field, (
                    f"Validator {node_id!r} rejected its input ({rej.reason}"
                    f"{', field ' + rej.field if rej.field else ''})"
                )) from None
            labels = ex.validator_output_labels(node_id, node.config, inbound, self.policy.allowlists)
            await self._append_event(run_id=state.run_id, type="declassified", data={
                "node_id": node_id, "kind": "validator", "fields": [node.config.get("field", "data")],
                "field_type": ex.validator_type(node.config), "source_sources": sorted(inbound.sources),
            })
            ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": outputs,
                    "output_labels": {k: v.model_dump(mode="json") for k, v in labels.items()},
                },
            )
            state.apply_event(ev)
            return

        # 2a. 3.1 calculator: safe arithmetic; the result is untrusted (tool output) with the input's
        #     confidentiality (same label rule as the analyzer: calculator_output_labels)
        if node.type == "calculator":
            from agentos.flows.calculator import evaluate

            inbound = ex.shared_inbound(self.flow, node_id, state.node_output_labels, effective_inbound)
            outputs = {"result": evaluate(inputs.get("expression"))}
            labels = calculator_output_labels(node_id, inbound)
            ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": outputs,
                    "output_labels": {k: v.model_dump(mode="json") for k, v in labels.items()},
                },
            )
            state.apply_event(ev)
            return

        # 2b. 2.5b quarantined extraction: one direct model call, strict parse, validated values only
        if node.type == "quarantined_extraction":
            outputs, labels = await self._run_extraction(state, node, inputs, effective_inbound)
            ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": outputs,
                    "output_labels": {k: v.model_dump(mode="json") for k, v in labels.items()},
                },
            )
            state.apply_event(ev)
            return

        # 3. Approval node (Requirement 7: pauses run, persists state, frees task)
        if node.type == "approval":
            wait_ev = await self._append_event(
                run_id=state.run_id,
                type="node_waiting",
                data={
                    "node_id": node_id,
                    "prompt": node.config.get("prompt", "Approval required"),
                    "approves": node.config.get("approves", {}),
                    "arguments": inputs,
                    # 2.4d-fix: display only. The approved sink's full call (pinned args, args from
                    # other nodes) so the approver sees every argument. Labels and decisions unchanged.
                    "sink_args": self._sink_call_preview(state, node),
                },
            )
            state.apply_event(wait_ev)
            run_wait_ev = await self._append_event(
                run_id=state.run_id,
                type="run_waiting",
                data={"node_id": node_id},
            )
            state.apply_event(run_wait_ev)
            return

        # 4. Direct Sink Node (e.g. send_email)
        if spec.side_effect in (
            SideEffectClass.EXTERNAL_SEND,
            SideEffectClass.DESTRUCTIVE,
            SideEffectClass.WRITE,
        ):
            # Check IFC rules on inbound arguments
            for arg_name, rule in spec.sink_rules.items():
                is_pinned = arg_name in node.pinned_args
                arriving_lbl = (
                    Label.trusted(sources={node_id})
                    if is_pinned
                    else input_labels.get(arg_name, effective_inbound)
                )

                # Part 0.a: is_approved requires explicit edge mapping from approval node
                is_approved = False
                for edge in self.flow.edges:
                    if edge.target == node_id and arg_name in edge.arg_mapping:
                        src_node = self.flow.nodes.get(edge.source)
                        if src_node and src_node.type == "approval":
                            app_cfg = src_node.config.get("approves", {})
                            if (
                                app_cfg.get("sink_node") == node_id
                                and arg_name in app_cfg.get("args", [])
                            ):
                                is_approved = True
                                break

                to_val = inputs.get(spec.recipient_arg)
                violations = evaluate_sink_argument_rule(
                    node_id=node_id,
                    spec=spec,
                    arg_name=arg_name,
                    rule=rule,
                    arriving_label=arriving_lbl,
                    effective_inbound_label=effective_inbound,
                    is_pinned=is_pinned,
                    is_approved=is_approved,
                    pinned_to_val=to_val,
                    policy=self.policy,
                    path=[node_id],
                    approval_gated=ex.is_approval_gated(self.flow, node_id),
                )
                if violations:
                    raise SinkRuleViolationError(violations[0])

            # Requirement 6: sink_intent -> transport(idempotency_key) -> sink_committed
            # If a crash occurred after sink_intent was written, reuse the exact idempotency key
            if node_id in state.pending_sink_intents:
                idempotency_key = state.pending_sink_intents[node_id]
            else:
                idempotency_key = f"{state.run_id}:{node_id}:{state.last_seq + 1}"

            transport = self.transport_registry.get(node.type) or MockTransport()
            if idempotency_key in state.committed_sinks:
                # Deduplicate on replay
                transport_result = {"status": "deduplicated", "idempotency_key": idempotency_key}
            else:
                # 3.3: a real channel checks its arguments (header injection, sizes, From) BEFORE the intent
                if node_id not in state.pending_sink_intents and hasattr(transport, "avalidate"):
                    await transport.avalidate(inputs)
                if node_id not in state.pending_sink_intents:
                    intent_ev = await self._append_event(
                        run_id=state.run_id,
                        type="sink_intent",
                        data={
                            "sink_node": node_id,
                            "idempotency_key": idempotency_key,
                            "args": inputs,
                        },
                    )
                    state.apply_event(intent_ev)

                # Requirement 1: Fencing check before transport invocation
                self._check_fencing(state.run_id)
                transport_result = await transport_send(transport, idempotency_key, inputs)

                commit_ev = await self._append_event(
                    run_id=state.run_id,
                    type="sink_committed",
                    data={
                        "sink_node": node_id,
                        "idempotency_key": idempotency_key,
                        "result": transport_result,
                    },
                )
                state.apply_event(commit_ev)

            succ_ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": transport_result,
                    "output_labels": {"*": Label.trusted(sources={node_id}).model_dump(mode="json")},
                },
            )
            state.apply_event(succ_ev)
            return

        # 5. Agent Node (CrewAI execution mediated through Tool Proxy)
        if node.type == "agent":
            loop = asyncio.get_running_loop()
            catalog, entries = await self._agent_tool_catalog(state, node_id, node)
            proxy = AgentOSToolProxy(
                run_id=state.run_id,
                agent_node_id=node_id,
                storage=self.storage,
                policy=self.policy,
                pinned_args=node.pinned_args,
                # 2.5a: same rule as the static analyzer: an unreplaced MCP description makes the context
                # untrusted from the start (the model has read server-controlled text)
                agent_input_label=agent_initial_context(effective_inbound, entries),
                transport_registry=self.transport_registry,
                loop=loop,
                track_labels=self.track_labels,
                lease_id=self.lease_id,
                fencing_checker=self.fencing_checker,
                tool_catalog=catalog,
                mcp_manager=self.mcp_manager,
                sandbox=self.sandbox,
                usage_guard=await self._usage_guard(state),
            )

            # Wrap tools
            tools = node.config.get("tools", [])
            wrapped_tools = [proxy.create_wrapped_tool(t) for t in tools]

            # Execute CrewAI in asyncio.to_thread
            # Documented: Python OS threads cannot be interrupted upon cancellation.
            # Cancellation marks the node CANCELLED and halts subsequent scheduling.
            task_desc_val = inputs.get("task", inputs.get("context", "Execute assigned task"))
            if isinstance(task_desc_val, (dict, list)):
                task_desc = json.dumps(task_desc_val)
            else:
                task_desc = str(task_desc_val)
            # 2.3: per-node model choice (validated against enabled providers on save/publish)
            # 2.4c: real models through AgentOSRouterLLM (fallback chain, llm_call events, T-13).
            # 3.4 Part 0a: ALWAYS the router (never a raw model name handed to CrewAI, which would build its own
            # provider client). In MOCK mode the router answers with the offline scripted model. Only an injected
            # custom LLM (tests / use cases) replaces it.
            if self.custom_llm is not None:
                llm_to_use = self.custom_llm
            else:
                agent_guard = await self._usage_guard(state)
                llm_to_use = self._router_llm(state, node, effective_inbound, loop, guard=agent_guard)

            def _run_crewai() -> str:
                from crewai.agent.core import Agent
                from crewai.task import Task

                agent = Agent(
                    role=node.config.get("role", "Assistant"),
                    goal=node.config.get("goal", "Accomplish task"),
                    backstory=node.config.get("backstory", "AgentOS Worker"),
                    tools=wrapped_tools,
                    llm=llm_to_use,
                    verbose=node.config.get("verbose", False),
                    cache=False,  # Enforce cache disabled
                )
                task = Task(description=task_desc, expected_output="Result", agent=agent)
                return str(agent.execute_task(task))

            agent_result = await asyncio.to_thread(_run_crewai)
            guard_now = self._guards.get(state.run_id)
            if guard_now is not None and guard_now.tripped is not None:
                raise guard_now.tripped  # 3.2: even if the agent framework swallowed the refusal

            out_lbl = proxy.agent_context_label
            succ_ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": {"output": agent_result},
                    "output_labels": {
                        "output": out_lbl.model_dump(mode="json"),
                        "*": out_lbl.model_dump(mode="json"),
                    },
                },
            )
            state.apply_event(succ_ev)
            return

        # 6. LLM Node
        if node.type == "llm":
            prompt = inputs.get("prompt", "")
            if self.custom_llm and hasattr(self.custom_llm, "call"):
                completion = str(self.custom_llm.call([{"role": "user", "content": prompt}]))
            else:
                # 2.4c: call through the provider chain (runs in a thread; events via the loop).
                # 3.4 Part 0a: also in MOCK mode, where the router answers with the offline scripted model.
                router_llm = self._router_llm(state, node, effective_inbound, asyncio.get_running_loop(),
                                              guard=await self._usage_guard(state))
                messages = [{"role": "user", "content": prompt if isinstance(prompt, str) else json.dumps(prompt)}]
                if node.config.get("system_prompt"):
                    messages.insert(0, {"role": "system", "content": str(node.config["system_prompt"])})
                completion = await asyncio.to_thread(router_llm.call, messages)

            out_lbl = effective_inbound
            succ_ev = await self._append_event(
                run_id=state.run_id,
                type="node_succeeded",
                data={
                    "node_id": node_id,
                    "outputs": {"completion": completion},
                    "output_labels": {
                        "completion": out_lbl.model_dump(mode="json"),
                        "*": out_lbl.model_dump(mode="json"),
                    },
                },
            )
            state.apply_event(succ_ev)
            return

        # Default fallback
        succ_ev = await self._append_event(
            run_id=state.run_id,
            type="node_succeeded",
            data={
                "node_id": node_id,
                "outputs": inputs,
                "output_labels": {"*": effective_inbound.model_dump(mode="json")},
            },
        )
        state.apply_event(succ_ev)

    async def _update_run_status(
        self,
        state: FlowRunState,
        status: RunStatus,
        error: str | None = None,
        resume_at: Any = "unchanged",
    ) -> None:
        """Update run record in storage."""
        self._check_fencing(state.run_id)
        state.status = status
        record = await self.storage.runs.get(state.run_id)
        if record:
            record.status = status.value
            record.error = error
            if resume_at != "unchanged":
                record.resume_at = resume_at
            record.outputs = state.node_outputs
            record.current_lease_id = self.lease_id
            await self.storage.runs.put(record)
            record.outputs = state.node_outputs
            await self.storage.runs.put(record)
        # 3.5: the run's sandbox workspace is deleted when the run ends (a WAITING run keeps it)
        if self.sandbox is not None and status in (RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.CANCELLED):
            self.sandbox.cleanup_run(state.run_id)
        # 3.6a: evaluate review queue sampling when run completes
        if status in (RunStatus.SUCCEEDED, RunStatus.FAILED):
            try:
                await self._maybe_sample_for_review(state, status)
            except Exception:
                pass

    async def _maybe_sample_for_review(self, state: FlowRunState, status: RunStatus) -> None:
        if not getattr(self, "storage", None) or not getattr(self, "flow", None):
            return
        from agentos.review.models import ReviewItem
        from agentos.review.store import review_store_for

        review_store = review_store_for(self.storage)
        config = await review_store.get_sampling_config(self.flow.id)
        if config.mode == "off":
            return

        should_queue = False
        if config.mode == "all":
            if status == RunStatus.SUCCEEDED:
                should_queue = True
        elif config.mode == "percentage":
            import random
            should_queue = random.randint(1, 100) <= config.percentage
        elif config.mode == "rules":
            events = await self.storage.events.list(state.run_id, after_seq=0)
            event_types = {e.type for e in events}
            event_datas = [e.data or {} for e in events]

            for rule in config.rules:
                if rule == "failed" and status == RunStatus.FAILED:
                    should_queue = True
                    break
                elif rule == "fallback_used":
                    if bool(getattr(state, "handled_failures", None)):
                        should_queue = True
                        break
                    if any(len(d.get("attempts", [])) > 0 for d in event_datas if d.get("attempts")):
                        should_queue = True
                        break
                elif rule == "rejected_input":
                    if "extraction_rejected" in event_types or "validator_rejected" in event_types:
                        should_queue = True
                        break
                elif rule == "approval_rejected":
                    if "approval_rejected" in event_types or getattr(state, "error", None) == "rejected_by_operator":
                        should_queue = True
                        break
                elif rule == "sink_blocked":
                    if "tool_call_rejected" in event_types or "sink_rule_violated" in event_types:
                        should_queue = True
                        break
                    err_msg = str(getattr(state, "error", "") or "")
                    if "SinkRuleViolationError" in err_msg or ("sink" in err_msg.lower() and "violat" in err_msg.lower()):
                        should_queue = True
                        break

        if not should_queue:
            return

        target_nodes = []
        if config.nodes and config.nodes != ["*"] and config.nodes != ["__final__"]:
            target_nodes = [nid for nid in config.nodes if nid in self.flow.nodes]
        else:
            targets = [nid for nid in self.flow.nodes if not any(e.source == nid for e in self.flow.edges)]
            if targets:
                target_nodes = targets
            elif state.node_outputs:
                target_nodes = [list(state.node_outputs.keys())[-1]]

        if not target_nodes and self.flow.entrypoint:
            target_nodes = [self.flow.entrypoint]

        flow_ver = getattr(self.flow, "version", 1)
        for nid in target_nodes:
            lbl_dict = state.node_output_labels.get(nid, {})
            label_names = set()
            for k, lbl in lbl_dict.items():
                if getattr(lbl, "integrity", None) == "untrusted":
                    label_names.add("UNTRUSTED")
                if getattr(lbl, "confidentiality", None) == "secret":
                    label_names.add("SECRET")
                elif getattr(lbl, "confidentiality", None) == "confidential":
                    label_names.add("CONFIDENTIAL")

            in_lbls = {
                k: {
                    "confidentiality": getattr(lbl, "confidentiality", "public"),
                    "integrity": getattr(lbl, "integrity", "untrusted"),
                    "sources": getattr(lbl, "sources", []),
                }
                for k, lbl in state.node_input_labels.get(nid, {}).items()
            }
            out_lbls = {
                k: {
                    "confidentiality": getattr(lbl, "confidentiality", "public"),
                    "integrity": getattr(lbl, "integrity", "untrusted"),
                    "sources": getattr(lbl, "sources", []),
                }
                for k, lbl in state.node_output_labels.get(nid, {}).items()
            }

            item = ReviewItem(
                run_id=state.run_id,
                flow_id=self.flow.id,
                flow_version=flow_ver,
                node_id=nid,
                status="pending",
                inputs=state.node_inputs.get(nid) or {},
                input_labels=in_lbls,
                outputs=state.node_outputs.get(nid) or {},
                output_labels=out_lbls,
                input_data=state.node_inputs.get(nid),
                output_data=state.node_outputs.get(nid),
                labels=sorted(label_names),
            )
            await review_store.put_item(item)

    async def _save_checkpoint(self, state: FlowRunState) -> None:
        """Save optional snapshot checkpoint verified against current event seq."""
        await self.storage.checkpoints.save_checkpoint(
            mission_id=state.run_id,
            task_index=state.last_seq,
            state=state.to_snapshot_dict(),
        )
