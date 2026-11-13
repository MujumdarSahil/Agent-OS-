"""Node specifications, sink argument rules, and built-in spike node specs.

NodeSpecs define the interface contract, side-effect classifications, and
per-argument sink policies enforced by the Static Analyzer and Runtime Tool Proxy.
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
    allowlist: list[str] = Field(default_factory=list)
    internal_domain_allowlist: list[str] = Field(default_factory=list)
    condition: str | None = None  # e.g. "body_internal_recipients_only"

    def is_recipient_internal(self, email: str) -> bool:
        """Check if an email address belongs to the internal domain allowlist."""
        if "@" not in email:
            return False
        domain = email.split("@", 1)[1].lower()
        allowed = {d.lower().lstrip("@") for d in self.internal_domain_allowlist}
        return domain in allowed


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
    constrained_fields: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in Spike Node Specs
# ---------------------------------------------------------------------------

WEBHOOK_TRIGGER_SPEC = NodeSpec(
    type="webhook_trigger",
    config_schema={
        "type": "object",
        "properties": {"path": {"type": "string"}},
    },
    input_schema={},
    output_schema={
        "type": "object",
        "properties": {"payload": {"type": "object"}, "headers": {"type": "object"}},
    },
    side_effect=SideEffectClass.NONE,
)

LLM_NODE_SPEC = NodeSpec(
    type="llm",
    config_schema={
        "type": "object",
        "properties": {
            "model": {"type": "string"},
            "system_prompt": {"type": "string"},
        },
    },
    input_schema={
        "type": "object",
        "properties": {"prompt": {"type": "string"}, "context": {"type": "string"}},
    },
    output_schema={
        "type": "object",
        "properties": {"completion": {"type": "string"}},
    },
    side_effect=SideEffectClass.NONE,
)

AGENT_NODE_SPEC = NodeSpec(
    type="agent",
    config_schema={
        "type": "object",
        "properties": {
            "role": {"type": "string"},
            "goal": {"type": "string"},
            "backstory": {"type": "string"},
            "tools": {"type": "array", "items": {"type": "string"}},
            "pinned_args": {"type": "object"},
            # Hardened constraints
            "cache": {"type": "boolean", "const": False},
            "allow_delegation": {"type": "boolean", "const": False},
            "allow_code_execution": {"type": "boolean", "const": False},
        },
    },
    input_schema={
        "type": "object",
        "properties": {"task": {"type": "string"}, "context": {"type": "string"}},
    },
    output_schema={
        "type": "object",
        "properties": {"output": {"type": "string"}},
    },
    side_effect=SideEffectClass.NONE,
)

TOOL_NODE_SPEC = NodeSpec(
    type="tool",
    config_schema={
        "type": "object",
        "properties": {"tool_name": {"type": "string"}},
    },
    input_schema={"type": "object"},
    output_schema={"type": "object"},
    side_effect=SideEffectClass.READ,
)

SEND_EMAIL_SINK_SPEC = NodeSpec(
    type="send_email",
    config_schema={
        "type": "object",
        "properties": {
            "pinned_to": {"type": "string"},
            "internal_domains": {"type": "array", "items": {"type": "string"}},
        },
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
        "properties": {"status": {"type": "string"}, "idempotency_key": {"type": "string"}},
    },
    side_effect=SideEffectClass.EXTERNAL_SEND,
    idempotent=True,
    sink_rules={
        "to": SinkArgumentRule(
            required_integrity="trusted",
            allowlist=["trusted-admin@corp.local", "alice@corp.local", "secops@corp.local"],
            internal_domain_allowlist=["corp.local", "company.internal"],
        ),
        "body": SinkArgumentRule(
            required_integrity="untrusted",
            condition="body_internal_recipients_only",
            internal_domain_allowlist=["corp.local", "company.internal"],
        ),
    },
)

APPROVAL_NODE_SPEC = NodeSpec(
    type="approval",
    config_schema={
        "type": "object",
        "properties": {
            "prompt": {"type": "string"},
            "timeout_seconds": {"type": "number"},
        },
    },
    input_schema={"type": "object"},
    output_schema={"type": "object"},
    side_effect=SideEffectClass.NONE,
)

VALIDATOR_NODE_SPEC = NodeSpec(
    type="validator",
    config_schema={
        "type": "object",
        "properties": {
            "field": {"type": "string"},
            "allowlist": {"type": "array", "items": {"type": "string"}},
            "field_type": {
                "type": "string",
                "enum": ["enum", "bool", "bounded_number", "allowlist_match"],
            },
        },
        "required": ["field"],
    },
    input_schema={"type": "object"},
    output_schema={"type": "object"},
    side_effect=SideEffectClass.NONE,
    constrained_fields=["enum", "bool", "bounded_number", "allowlist_match"],
)

LOOP_NODE_SPEC = NodeSpec(
    type="loop",
    config_schema={
        "type": "object",
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
    "send_email": SEND_EMAIL_SINK_SPEC,
    "approval": APPROVAL_NODE_SPEC,
    "validator": VALIDATOR_NODE_SPEC,
    "loop": LOOP_NODE_SPEC,
}
