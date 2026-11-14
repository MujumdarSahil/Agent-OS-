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
import json
import time
import uuid
from typing import Any

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.models import FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import AgentOSToolProxy, MockTransport
from agentos.flows.rules import (
    RuleViolation,
    SinkRuleViolationError,
    evaluate_sink_argument_rule,
    normalize_and_validate_recipients,
)
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass
from agentos.flows.state import FlowRunState, NodeState, RunStatus
from agentos.storage.models import EventRecord, RunRecord
from agentos.storage.ports import Storage


def execute_validator_runtime(
    node: NodeDefinition,
    raw_inputs: dict[str, Any],
    policy: SecurityPolicy,
) -> tuple[dict[str, Any], Label]:
    """Execute validator node at runtime.

    Requirement 3: Validators at runtime OUTPUT the constrained value itself
    (bool, enum member, number, or matched entry from admin allowlist),
    NEVER the original input string.
    """
    field = node.config.get("field", "data")
    field_type = node.config.get("field_type")
    raw_val = raw_inputs.get(field, raw_inputs.get("data", raw_inputs))

    if field_type == "bool":
        if isinstance(raw_val, bool):
            clean_val = raw_val
        elif isinstance(raw_val, str):
            clean = raw_val.strip().lower()
            if clean in ("true", "1", "yes", "t"):
                clean_val = True
            elif clean in ("false", "0", "no", "f"):
                clean_val = False
            else:
                raise ValueError(f"Cannot parse boolean from {raw_val!r}")
        elif isinstance(raw_val, (int, float)):
            clean_val = bool(raw_val)
        else:
            raise ValueError(f"Cannot parse boolean from {raw_val!r}")

        out_label = Label.trusted(sources={node.id})
        return {field: clean_val, "data": clean_val}, out_label

    elif field_type == "bounded_number":
        try:
            clean_val = float(raw_val) if "." in str(raw_val) else int(raw_val)
        except (ValueError, TypeError) as err:
            raise ValueError(f"Cannot parse number from {raw_val!r}") from err
        out_label = Label.trusted(sources={node.id})
        return {field: clean_val, "data": clean_val}, out_label

    elif field_type == "allowlist_match":
        allowlist_name = node.config.get("allowlist_name")
        allowed_entries = policy.allowlists.get(allowlist_name, [])
        target = str(raw_val).strip().lower()
        matched_entry = None
        for entry in allowed_entries:
            if entry.strip().lower() == target:
                matched_entry = entry
                break

        if matched_entry is None:
            raise ValueError(f"Value {raw_val!r} not found in admin allowlist {allowlist_name!r}")

        # Return the canonical matched entry from allowlist, never the user input string
        out_label = Label.trusted(sources={node.id})
        return {field: matched_entry, "data": matched_entry, "to": matched_entry}, out_label

    elif field_type == "enum":
        clean_val = str(raw_val).strip()
        out_label = Label.trusted(sources={node.id})
        return {field: clean_val, "data": clean_val}, out_label

    else:
        # Free text or unconstrained field type stays untrusted
        out_label = Label.untrusted(sources={node.id})
        return {field: raw_val, "data": raw_val}, out_label


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
    ) -> None:
        self.flow = flow
        self.storage = storage
        self.policy = policy or SecurityPolicy()
        self.transport_registry = transport_registry or {"send_email": MockTransport()}
        self.custom_llm = custom_llm
        self.track_labels = track_labels

    async def run(
        self,
        run_id: str | None = None,
        inputs: dict[str, Any] | None = None,
        raise_on_error: bool = False,
    ) -> FlowRunState:
        """Execute flow graph from entrypoint."""
        run_id = run_id or f"run_{uuid.uuid4().hex[:12]}"
        inputs = inputs or {}

        # 1. Initialize run record and append run_started event
        run_record = RunRecord(
            run_id=run_id,
            mission_name=self.flow.id,
            status=RunStatus.RUNNING.value,
        )
        await self.storage.runs.put(run_record)

        ev = await self.storage.events.append(
            run_id=run_id,
            type="run_started",
            data={
                "flow_id": self.flow.id,
                "entrypoint": self.flow.entrypoint,
                "inputs": inputs,
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

        # If waiting for approval, resume cannot continue without approval decision
        if state.status == RunStatus.WAITING:
            return state

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
            wait_ev = await self.storage.events.append(
                run_id=state.run_id,
                type="node_waiting",
                data=wait_data,
            )
            state.apply_event(wait_ev)
            run_wait_ev = await self.storage.events.append(
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

    async def approve(self, run_id: str, node_id: str, decision: bool) -> FlowRunState:
        """Deliver operator approval decision and resume flow execution."""
        events = await self.storage.events.list(run_id, after_seq=0)
        state = FlowRunState.rebuild_from_events(run_id, events)

        if state.status != RunStatus.WAITING or state.waiting_node != node_id:
            raise ValueError(
                f"Run {run_id!r} is not currently waiting for approval on node {node_id!r} "
                f"(status={state.status.value!r}, waiting_node={state.waiting_node!r})"
            )

        shown_args = (state.waiting_details or {}).get("arguments", {})

        # Append approval decision event with exact argument values shown to operator
        ev = await self.storage.events.append(
            run_id=run_id,
            type="approval_decision",
            data={
                "node_id": node_id,
                "decision": decision,
                "arguments": shown_args,
            },
        )
        state.apply_event(ev)

        if decision is True:
            # Approval declassifies approved arguments to trusted for downstream sink
            out_label = Label.trusted(sources={node_id})
            succ_ev = await self.storage.events.append(
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
            # Rejection stops the flow
            fail_ev = await self.storage.events.append(
                run_id=run_id,
                type="node_failed",
                data={
                    "node_id": node_id,
                    "error": f"Approval rejected by operator on node {node_id!r}",
                },
            )
            state.apply_event(fail_ev)
            await self._update_run_status(state, RunStatus.FAILED, error=state.error)
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
            # Identify ready nodes: un-started nodes whose upstream dependencies have succeeded
            ready_nodes = self._get_ready_nodes(state)

            if not ready_nodes:
                if state.status == RunStatus.WAITING:
                    # Flow is waiting for approval
                    await self._update_run_status(state, RunStatus.WAITING)
                    await self._save_checkpoint(state)
                    return state

                if all(
                    state.node_states.get(nid) == NodeState.SUCCEEDED
                    for nid in self.flow.nodes
                ):
                    # Flow finished successfully
                    ev = await self.storage.events.append(
                        run_id=state.run_id,
                        type="run_succeeded",
                        data={"outputs": state.node_outputs},
                    )
                    state.apply_event(ev)
                    await self._update_run_status(state, RunStatus.SUCCEEDED)
                    await self._save_checkpoint(state)
                    return state

                # If any node failed and no more nodes can proceed -> run failed
                if any(st == NodeState.FAILED for st in state.node_states.values()):
                    ev = await self.storage.events.append(
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
                q_ev = await self.storage.events.append(
                    run_id=state.run_id,
                    type="node_queued",
                    data={"node_id": nid},
                )
                state.apply_event(q_ev)

            # Ready nodes run concurrently via asyncio.gather (two-branch + join)
            tasks = [self._execute_single_node(state, nid) for nid in ready_nodes]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for nid, res in zip(ready_nodes, results):
                if isinstance(res, Exception):
                    if first_exception is None:
                        first_exception = res
                    state.error = str(res)
                    fail_ev = await self.storage.events.append(
                        run_id=state.run_id,
                        type="node_failed",
                        data={"node_id": nid, "error": str(res)},
                    )
                    state.apply_event(fail_ev)

            # Save progress snapshot
            await self._save_checkpoint(state)

            if state.status == RunStatus.WAITING:
                await self._update_run_status(state, RunStatus.WAITING)
                return state

            if state.error:
                ev = await self.storage.events.append(
                    run_id=state.run_id,
                    type="run_failed",
                    data={"error": state.error},
                )
                state.apply_event(ev)
                await self._update_run_status(state, RunStatus.FAILED, error=state.error)
                if raise_on_error and first_exception:
                    raise first_exception
                return state

    def _get_ready_nodes(self, state: FlowRunState) -> list[str]:
        """Return IDs of nodes whose incoming dependencies have all SUCCEEDED."""
        ready: list[str] = []
        for node_id, node in self.flow.nodes.items():
            curr_state = state.node_states.get(node_id)
            if curr_state in (
                NodeState.RUNNING,
                NodeState.SUCCEEDED,
                NodeState.FAILED,
                NodeState.WAITING,
                NodeState.CANCELLED,
            ):
                continue

            # Incoming dependencies check
            inbound_edges = [e for e in self.flow.edges if e.target == node_id]
            if not inbound_edges and node_id == self.flow.entrypoint:
                ready.append(node_id)
            elif inbound_edges and all(
                state.node_states.get(e.source) == NodeState.SUCCEEDED
                for e in inbound_edges
            ):
                ready.append(node_id)

        return ready

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
        if node_id == self.flow.entrypoint and not inbound_args:
            run_init_event = next(
                (e for e in state.event_history if e.get("type") == "run_started"), None
            )
            inbound_args = (run_init_event or {}).get("data", {}).get("inputs", {})
            init_lbl = (
                Label.untrusted(sources={node_id})
                if node.type == "webhook_trigger"
                else Label.trusted(sources={node_id})
            )
            inbound_labels = {"*": init_lbl, "payload": init_lbl}

        # Apply author pinned arguments
        for k, v in node.pinned_args.items():
            if not k.startswith(f"{node.type}."):
                inbound_args[k] = v
                inbound_labels[k] = Label.trusted(sources={node_id})

        start_ev = await self.storage.events.append(
            run_id=state.run_id,
            type="node_started",
            data={
                "node_id": node_id,
                "inputs": inbound_args,
                "input_labels": {k: v.model_dump(mode="json") for k, v in inbound_labels.items()},
            },
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
            fail_ev = await self.storage.events.append(
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
        effective_inbound = Label.join_all(list(input_labels.values()), default=Label.trusted())

        # 1. Webhook trigger
        if node.type == "webhook_trigger":
            out_label = Label.untrusted(sources={node_id})
            outputs = {"payload": inputs, "headers": {}}
            labels = {"payload": out_label, "headers": out_label, "*": out_label}
            ev = await self.storage.events.append(
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
            outputs, out_label = execute_validator_runtime(node, inputs, self.policy)
            labels = {"*": out_label, "data": out_label, **{k: out_label for k in outputs}}
            ev = await self.storage.events.append(
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
            wait_ev = await self.storage.events.append(
                run_id=state.run_id,
                type="node_waiting",
                data={
                    "node_id": node_id,
                    "prompt": node.config.get("prompt", "Approval required"),
                    "approves": node.config.get("approves", {}),
                    "arguments": inputs,
                },
            )
            state.apply_event(wait_ev)
            run_wait_ev = await self.storage.events.append(
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

                to_val = inputs.get("to")
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
                )
                if violations:
                    raise SinkRuleViolationError(violations[0])

            # Requirement 6: sink_intent -> transport(idempotency_key) -> sink_committed
            # If a crash occurred after sink_intent was written, reuse the exact idempotency key
            if node_id in state.pending_sink_intents:
                idempotency_key = state.pending_sink_intents[node_id]
            else:
                idempotency_key = f"{state.run_id}:{node_id}:{state.last_seq + 1}"

            if idempotency_key in state.committed_sinks:
                # Deduplicate on replay
                transport_result = {"status": "deduplicated", "idempotency_key": idempotency_key}
            else:
                if node_id not in state.pending_sink_intents:
                    intent_ev = await self.storage.events.append(
                        run_id=state.run_id,
                        type="sink_intent",
                        data={
                            "sink_node": node_id,
                            "idempotency_key": idempotency_key,
                            "args": inputs,
                        },
                    )
                    state.apply_event(intent_ev)

                transport = self.transport_registry.get(node.type) or MockTransport()
                transport_result = transport.send(idempotency_key=idempotency_key, **inputs)

                commit_ev = await self.storage.events.append(
                    run_id=state.run_id,
                    type="sink_committed",
                    data={
                        "sink_node": node_id,
                        "idempotency_key": idempotency_key,
                        "result": transport_result,
                    },
                )
                state.apply_event(commit_ev)

            succ_ev = await self.storage.events.append(
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
            proxy = AgentOSToolProxy(
                run_id=state.run_id,
                agent_node_id=node_id,
                storage=self.storage,
                policy=self.policy,
                pinned_args=node.pinned_args,
                agent_input_label=effective_inbound,
                transport_registry=self.transport_registry,
                loop=loop,
                track_labels=self.track_labels,
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
            llm_to_use = self.custom_llm or node.config.get("llm")

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

            out_lbl = proxy.agent_context_label
            succ_ev = await self.storage.events.append(
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
            completion = f"Completion for: {prompt}"
            if self.custom_llm and hasattr(self.custom_llm, "call"):
                completion = str(self.custom_llm.call([{"role": "user", "content": prompt}]))

            out_lbl = effective_inbound
            succ_ev = await self.storage.events.append(
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
        succ_ev = await self.storage.events.append(
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
    ) -> None:
        """Update run record in storage."""
        state.status = status
        record = await self.storage.runs.get(state.run_id)
        if record:
            record.status = status.value
            record.error = error
            record.outputs = state.node_outputs
            await self.storage.runs.put(record)

    async def _save_checkpoint(self, state: FlowRunState) -> None:
        """Save optional snapshot checkpoint verified against current event seq."""
        await self.storage.checkpoints.save_checkpoint(
            mission_id=state.run_id,
            task_index=state.last_seq,
            state=state.to_snapshot_dict(),
        )
