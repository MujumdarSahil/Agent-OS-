"""Node specifications, sink argument rules, and built-in spike node specs.

NodeSpecs define the interface contract, schemas, side-effect classifications,
and per-argument sink policies.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class SideEffectClass(str, Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    EXTERNAL_SEND = "external_send"
    DESTRUCTIVE = "destructive"


class SinkArgumentRule(BaseModel):
    """Integrity and authorization rules for a specific sink argument."""

    required_integrity: str = "trusted"  # "trusted" | "untrusted"
    allowlist_name: str | None = None  # name of allowlist in SecurityPolicy
    condition: str | None = None  # e.g. "body_internal_recipients_only"


class NodeSpec(BaseModel):
    """Specification defining node schemas, side effects, and sink contracts."""

    type: str
    config_schema: dict[str, Any] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    side_effect: SideEffectClass = SideEffectClass.NONE
    idempotent: bool = False
    timeout_seconds: float | None = None
    sink_rules: dict[str, SinkArgumentRule] = Field(default_factory=dict)
    # Constrained output fields that a validator is soundly allowed to declassify
    constrained_fields: list[str] = Field(
        default_factory=lambda: ["enum", "bool", "bounded_number", "allowlist_match"]
    )


# ---------------------------------------------------------------------------
# Built-in Spike Node Specs
# ---------------------------------------------------------------------------

WEBHOOK_TRIGGER_SPEC = NodeSpec(
    type="webhook_trigger",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "path": {"type": "string"},
        },
    },
    input_schema={},
    output_schema={
        "type": "object",
        "properties": {
            "payload": {"type": "object"},
            "headers": {"type": "object"},
        },
    },
    side_effect=SideEffectClass.NONE,
)

LLM_NODE_SPEC = NodeSpec(
    type="llm",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "model": {"type": "string"},
            "system_prompt": {"type": "string"},
            "temperature": {"type": "number"},
        },
    },
    input_schema={
        "type": "object",
        "properties": {
            "prompt": {"type": "string"},
            "context": {"type": "string"},
        },
    },
    output_schema={
        "type": "object",
        "properties": {
            "completion": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.NONE,
)

AGENT_NODE_SPEC = NodeSpec(
    type="agent",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "role": {"type": "string"},
            "goal": {"type": "string"},
            "backstory": {"type": "string"},
            "tools": {"type": "array", "items": {"type": "string"}},
            "verbose": {"type": "boolean"},
            "llm": {"type": "string"},
            # Hardened constraints: MUST be boolean const False if passed
            "cache": {"type": "boolean", "const": False},
            "allow_delegation": {"type": "boolean", "const": False},
            "allow_code_execution": {"type": "boolean", "const": False},
        },
    },
    input_schema={
        "type": "object",
        "properties": {
            "task": {"type": "string"},
            "context": {"type": "string"},
        },
    },
    output_schema={
        "type": "object",
        "properties": {
            "output": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.NONE,
)

TOOL_NODE_SPEC = NodeSpec(
    type="tool",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "tool_name": {"type": "string"},
        },
    },
    input_schema={"type": "object"},
    # Tool outputs are untrusted sources explicitly
    output_schema={
        "type": "object",
        "properties": {
            "result": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.READ,
)

FETCH_URL_TOOL_SPEC = NodeSpec(
    type="fetch_url",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    },
    input_schema={
        "type": "object",
        "properties": {"url": {"type": "string"}},
    },
    # HTTP outputs are untrusted sources
    output_schema={
        "type": "object",
        "properties": {"content": {"type": "string"}},
    },
    side_effect=SideEffectClass.READ,
)

SEND_EMAIL_SINK_SPEC = NodeSpec(
    type="send_email",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    },
    input_schema={
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "body"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "idempotency_key": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.EXTERNAL_SEND,
    idempotent=True,
    sink_rules={
        "to": SinkArgumentRule(
            required_integrity="trusted",
            allowlist_name="email_recipients",
        ),
        "body": SinkArgumentRule(
            required_integrity="untrusted",
            condition="body_internal_recipients_only",
        ),
    },
)

APPROVAL_NODE_SPEC = NodeSpec(
    type="approval",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "prompt": {"type": "string"},
            "timeout_seconds": {"type": "number"},
            "approves": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "sink_node": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["sink_node", "args"],
            },
        },
        "required": ["approves"],
    },
    input_schema={"type": "object"},
    output_schema={
        "type": "object",
        "properties": {
            "approved": {"type": "boolean"},
            "data": {"type": "object"},
            "to": {"type": "string"},
            "body": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.NONE,
)

VALIDATOR_NODE_SPEC = NodeSpec(
    type="validator",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "field": {"type": "string"},
            "field_type": {"type": "string"},
            "allowlist": {"type": "array", "items": {"type": "string"}},
            "allowlist_name": {"type": "string"},
        },
        "required": ["field", "field_type"],
    },
    input_schema={"type": "object"},
    output_schema={
        "type": "object",
        "properties": {
            "data": {"type": "object"},
            "to": {"type": "string"},
            "result": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.NONE,
)

LOOP_NODE_SPEC = NodeSpec(
    type="loop",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "max_iterations": {"type": "integer", "minimum": 1, "maximum": 100},
            "condition": {"type": "string"},
        },
        "required": ["max_iterations"],
    },
    input_schema={"type": "object"},
    output_schema={"type": "object"},
    side_effect=SideEffectClass.NONE,
)

BUILTIN_NODE_SPECS: dict[str, NodeSpec] = {
    "webhook_trigger": WEBHOOK_TRIGGER_SPEC,
    "llm": LLM_NODE_SPEC,
    "agent": AGENT_NODE_SPEC,
    "tool": TOOL_NODE_SPEC,
    "fetch_url": FETCH_URL_TOOL_SPEC,
    "send_email": SEND_EMAIL_SINK_SPEC,
    "approval": APPROVAL_NODE_SPEC,
    "validator": VALIDATOR_NODE_SPEC,
    "loop": LOOP_NODE_SPEC,
}
