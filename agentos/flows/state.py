"""Event-sourced run state and node state models.

Rebuilds complete workflow execution state from append-only events.
Checkpoints serve strictly as optional snapshots verified against the event sequence.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from agentos.flows.labels import Label
from agentos.storage.models import EventRecord


class NodeState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING = "waiting"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FlowRunState(BaseModel):
    """Event-sourced runtime state for a workflow run."""

    run_id: str
    flow_id: str = ""
    status: RunStatus = RunStatus.PENDING
    last_seq: int = 0
    node_states: dict[str, NodeState] = Field(default_factory=dict)
    node_outputs: dict[str, dict[str, Any]] = Field(default_factory=dict)
    node_output_labels: dict[str, dict[str, Label]] = Field(default_factory=dict)
    node_inputs: dict[str, dict[str, Any]] = Field(default_factory=dict)
    node_input_labels: dict[str, dict[str, Label]] = Field(default_factory=dict)
    waiting_node: str | None = None
    waiting_details: dict[str, Any] | None = None
    error: str | None = None
    committed_sinks: set[str] = Field(default_factory=set)
    # Pending uncommitted sink intents for idempotency on resume
    pending_sink_intents: dict[str, str] = Field(default_factory=dict)
    # Stored events for replay and provenance tracing
    event_history: list[dict[str, Any]] = Field(default_factory=list)

    def apply_event(self, event: EventRecord) -> None:
        """Apply a single append-only event to advance state deterministically."""
        self.last_seq = event.seq
        ev_dict = event.model_dump(mode="json")
        self.event_history.append(ev_dict)

        t = event.type
        d = event.data or {}

        if t == "run_started":
            self.flow_id = d.get("flow_id", "")
            self.status = RunStatus.RUNNING

        elif t == "node_queued":
            nid = d.get("node_id")
            if nid:
                self.node_states[nid] = NodeState.QUEUED

        elif t == "node_started":
            nid = d.get("node_id")
            if nid:
                self.node_states[nid] = NodeState.RUNNING
                self.node_inputs[nid] = d.get("inputs", {})
                raw_labels = d.get("input_labels", {})
                self.node_input_labels[nid] = {
                    k: Label.model_validate(v) for k, v in raw_labels.items()
                }

        elif t == "node_succeeded":
            nid = d.get("node_id")
            if nid:
                self.node_states[nid] = NodeState.SUCCEEDED
                self.node_outputs[nid] = d.get("outputs", {})
                raw_labels = d.get("output_labels", {})
                self.node_output_labels[nid] = {
                    k: Label.model_validate(v) for k, v in raw_labels.items()
                }

        elif t == "node_failed":
            nid = d.get("node_id")
            if nid:
                self.node_states[nid] = NodeState.FAILED
            self.error = d.get("error")

        elif t == "node_waiting":
            nid = d.get("node_id")
            if nid:
                self.node_states[nid] = NodeState.WAITING
                self.waiting_node = nid
                self.waiting_details = d
            self.status = RunStatus.WAITING

        elif t == "node_cancelled":
            nid = d.get("node_id")
            if nid:
                self.node_states[nid] = NodeState.CANCELLED

        elif t == "sink_intent":
            sink_nid = d.get("sink_node")
            key = d.get("idempotency_key")
            if sink_nid and key:
                self.pending_sink_intents[sink_nid] = key

        elif t == "sink_committed":
            sink_nid = d.get("sink_node")
            key = d.get("idempotency_key")
            if key:
                self.committed_sinks.add(key)
            if sink_nid:
                self.pending_sink_intents.pop(sink_nid, None)

        elif t == "approval_decision":
            nid = d.get("node_id")
            decision = d.get("decision")
            if decision is True:
                self.waiting_node = None
                self.waiting_details = None
                self.status = RunStatus.RUNNING
            else:
                if nid:
                    self.node_states[nid] = NodeState.FAILED
                self.status = RunStatus.FAILED
                self.error = f"Approval rejected by operator for node {nid!r}"

        elif t == "run_waiting":
            self.status = RunStatus.WAITING

        elif t == "run_succeeded":
            self.status = RunStatus.SUCCEEDED

        elif t == "run_failed":
            self.status = RunStatus.FAILED
            self.error = d.get("error")

    @classmethod
    def rebuild_from_events(cls, run_id: str, events: list[EventRecord]) -> FlowRunState:
        """Rebuild entire flow execution state from an append-only event stream."""
        state = cls(run_id=run_id)
        # Ensure events are processed in strict sequence order
        sorted_events = sorted(events, key=lambda e: e.seq)
        for ev in sorted_events:
            state.apply_event(ev)
        return state

    def to_snapshot_dict(self) -> dict[str, Any]:
        """Convert state to a checkpoint snapshot dictionary."""
        return self.model_dump(mode="json")

    @classmethod
    def from_snapshot_and_events(
        cls,
        snapshot: dict[str, Any],
        subsequent_events: list[EventRecord],
    ) -> FlowRunState:
        """Restore state from an optional snapshot and verify/replay subsequent events."""
        state = cls.model_validate(snapshot)
        sorted_events = sorted(subsequent_events, key=lambda e: e.seq)
        for ev in sorted_events:
            if ev.seq > state.last_seq:
                state.apply_event(ev)
        return state
