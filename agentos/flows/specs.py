"""Node specifications, sink argument rules, and built-in spike node specs.

NodeSpecs define the interface contract, schemas, side-effect classifications,
and per-argument sink policies.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

from agentos.flows.extraction import CONFIG_SCHEMA as _EXTRACTION_CONFIG_SCHEMA
from agentos.flows.extraction import VALIDATOR_CONFIG_SCHEMA as _VALIDATOR_CONFIG_SCHEMA


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
    # 3.3: the argument that names where a send goes (email: "to"; Slack: "channel"); conditional rules read it
    recipient_arg: str = "to"
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
            # 2.4d: example input that pre-fills the Run dialog (UI only; never used at runtime)
            "sample_input": {"type": "object"},
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

MANUAL_TRIGGER_SPEC = NodeSpec(
    type="manual_trigger",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "description": {"type": "string"},
            # 2.4d: example input that pre-fills the Run dialog (UI only; never used at runtime)
            "sample_input": {"type": "object"},
        },
    },
    input_schema={},
    output_schema={
        "type": "object",
        "properties": {
            "payload": {"type": "object"},
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
            # Per-node model choice (2.3): must belong to an enabled provider (checked on save/publish).
            "model": {"type": "string"},
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

CALCULATOR_TOOL_SPEC = NodeSpec(
    # 3.1: safe arithmetic (agentos/flows/calculator.py). No side effect; the output is UNTRUSTED like every
    # tool output (the expression may come from untrusted text) and keeps the input's confidentiality.
    type="calculator",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={
        "type": "object",
        "properties": {"expression": {"type": "string", "maxLength": 2000}},
        "required": ["expression"],
    },
    output_schema={"type": "object", "properties": {"result": {"type": "number"}}},
    side_effect=SideEffectClass.NONE,
)

# Built-in tools an agent can be given (bare names). Other node types are flow steps, not agent tools.
AGENT_TOOL_TYPES = ("calculator", "fetch_url", "send_email", "send_slack")

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
    # 2.5b hardening: the same constrained types and limits as quarantined extraction (agentos/flows/extraction.py)
    config_schema=_VALIDATOR_CONFIG_SCHEMA,
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

QUARANTINED_EXTRACTION_SPEC = NodeSpec(
    # 2.5b: declassifies untrusted text into strictly constrained fields with one direct model call;
    # outputs only validated values, labelled trusted (agentos/flows/extraction.py).
    type="quarantined_extraction",
    config_schema=_EXTRACTION_CONFIG_SCHEMA,
    # the untrusted text arrives on ONE edge-mapped argument (default "text"; `config.input` renames it)
    input_schema={"type": "object", "properties": {"text": {"type": "string"}}},
    output_schema={"type": "object"},
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

# ---------------------------------------------------------------------------
# 2.3 node catalog
# ---------------------------------------------------------------------------

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]

HTTP_REQUEST_SPEC = NodeSpec(
    type="http_request",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "method": {"type": "string", "enum": HTTP_METHODS, "default": "GET"},
            # Templates may use {{ nodes.<id>.<field> }}; the label is the join of referenced values.
            "url": {"type": "string"},
            "query": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            # Header values are strings, or {"vault": "<secret name>"} credentials bound to a pinned URL.
            "headers": {
                "type": "object",
                "additionalProperties": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "object", "properties": {"vault": {"type": "string"}}, "required": ["vault"],
                         "additionalProperties": False},
                    ]
                },
            },
            "timeout_s": {"type": "number", "minimum": 0.1, "maximum": 30},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 5_000_000},
        },
    },
    input_schema={
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "query": {"type": "object"},
            "body": {},
            "headers": {"type": "object"},
        },
    },
    output_schema={
        "type": "object",
        "properties": {
            "status": {"type": "integer"},
            "headers": {"type": "object"},
            "body": {"type": "string"},
            "final_url": {"type": "string"},
            "truncated": {"type": "boolean"},
        },
    },
    # Effective side effect depends on the method (see effective_side_effect); the static value is the
    # strongest non-destructive one so the builder shows it as a sink.
    side_effect=SideEffectClass.EXTERNAL_SEND,
    idempotent=False,
    timeout_seconds=60,
    sink_rules={
        "url": SinkArgumentRule(required_integrity="trusted", allowlist_name="http_allowlist"),
        "body": SinkArgumentRule(required_integrity="untrusted", condition="untrusted_only_to_allowlisted_hosts"),
        "query": SinkArgumentRule(required_integrity="untrusted", condition="untrusted_only_to_allowlisted_hosts"),
        "headers": SinkArgumentRule(required_integrity="untrusted", condition="untrusted_only_to_allowlisted_hosts"),
    },
)

CONDITION_NODE_SPEC = NodeSpec(
    type="condition",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {"expression": {"type": "string", "minLength": 1}},
        "required": ["expression"],
    },
    input_schema={"type": "object", "properties": {}},
    output_schema={
        "type": "object",
        "properties": {"branch": {"type": "string", "enum": ["true", "false"]}, "result": {"type": "boolean"}},
    },
    side_effect=SideEffectClass.NONE,
)

MERGE_NODE_SPEC = NodeSpec(
    type="merge",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {"mode": {"type": "string", "enum": ["all", "first"], "default": "all"}},
    },
    input_schema={"type": "object", "properties": {}},
    output_schema={"type": "object", "properties": {"inputs": {"type": "object"}, "first": {"type": "string"}}},
    side_effect=SideEffectClass.NONE,
)

WAIT_NODE_SPEC = NodeSpec(
    type="wait",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {"delay_seconds": {"type": "number", "minimum": 0}},
        "required": ["delay_seconds"],
    },
    input_schema={"type": "object", "properties": {}},
    output_schema={"type": "object", "properties": {"resumed_at": {"type": "number"}}},
    side_effect=SideEffectClass.NONE,
)

ERROR_HANDLER_NODE_SPEC = NodeSpec(
    type="error_handler",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={"type": "object", "properties": {}},
    output_schema={
        "type": "object",
        "properties": {
            "failed_node": {"type": "string"},
            "error_type": {"type": "string"},
            "message": {"type": "string"},
        },
    },
    side_effect=SideEffectClass.NONE,
)

SUBFLOW_NODE_SPEC = NodeSpec(
    type="subflow",
    config_schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "flow_id": {"type": "string", "minLength": 1},
            "version": {"type": "integer", "minimum": 1},
        },
        "required": ["flow_id", "version"],
    },
    input_schema={"type": "object", "properties": {}},
    output_schema={"type": "object", "properties": {"outputs": {"type": "object"}}},
    side_effect=SideEffectClass.NONE,
)

_HTTP_SIDE_EFFECTS = {
    "GET": SideEffectClass.READ,
    "HEAD": SideEffectClass.READ,
    "POST": SideEffectClass.EXTERNAL_SEND,
    "PUT": SideEffectClass.EXTERNAL_SEND,
    "PATCH": SideEffectClass.EXTERNAL_SEND,
    "DELETE": SideEffectClass.DESTRUCTIVE,
}


def effective_side_effect(node_type: str, config: dict[str, Any] | None = None) -> SideEffectClass:
    """Side-effect class of a configured node (http_request depends on its method)."""
    spec = BUILTIN_NODE_SPECS.get(node_type)
    if node_type == "http_request":
        method = str((config or {}).get("method") or "GET").upper()
        return _HTTP_SIDE_EFFECTS.get(method, SideEffectClass.EXTERNAL_SEND)
    return spec.side_effect if spec else SideEffectClass.NONE


def is_checked_sink(node_type: str, config: dict[str, Any] | None = None) -> bool:
    """Whether sink rules must be evaluated for this node (http_request always, even for GET)."""
    if node_type == "http_request":
        return True
    return effective_side_effect(node_type, config) in (
        SideEffectClass.EXTERNAL_SEND, SideEffectClass.DESTRUCTIVE, SideEffectClass.WRITE,
    )


# 3.3: Slack message through an admin-configured incoming-webhook channel (text always escaped, unfurling off).
SEND_SLACK_SINK_SPEC = NodeSpec(
    type="send_slack",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "text": {"type": "string", "maxLength": 3000},
        },
        "required": ["channel", "text"],
    },
    output_schema={
        "type": "object",
        "properties": {"status": {"type": "string"}, "idempotency_key": {"type": "string"}},
    },
    side_effect=SideEffectClass.EXTERNAL_SEND,
    idempotent=True,
    recipient_arg="channel",
    sink_rules={
        "channel": SinkArgumentRule(required_integrity="trusted", condition="slack_channel_configured"),
        "text": SinkArgumentRule(required_integrity="untrusted", condition="text_internal_channel_only"),
    },
)

# 3.5: sandbox code tools (agentos/sandbox; design docs/evidence/3.5.md). Side effect NONE: they reach no network
# and no host file (only the run's sandbox workspace), so the code MAY be untrusted (LLM-written); every output is
# UNTRUSTED with the confidentiality of everything that went in. Fail closed when no sandbox backend is available.
_FILES_ARG = {"type": "object", "additionalProperties": {"type": "string"},
              "description": "optional {relative path: text} written into the run's sandbox workspace first"}
PYTHON_EXEC_TOOL_SPEC = NodeSpec(
    type="python_exec",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={"type": "object", "properties": {"code": {"type": "string", "maxLength": 200_000},
                                                   "files": _FILES_ARG}, "required": ["code"]},
    output_schema={"type": "object", "properties": {"exit_code": {"type": "integer"}, "stdout": {"type": "string"},
                                                    "stderr": {"type": "string"}, "files_out": {"type": "object"},
                                                    "limit_hit": {"type": "string"}}},
    side_effect=SideEffectClass.NONE,
)
SHELL_EXEC_TOOL_SPEC = NodeSpec(
    type="shell_exec",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={"type": "object", "properties": {"command": {"type": "string", "maxLength": 100_000},
                                                   "files": _FILES_ARG}, "required": ["command"]},
    output_schema=PYTHON_EXEC_TOOL_SPEC.output_schema,
    side_effect=SideEffectClass.NONE,
)
FILE_READ_TOOL_SPEC = NodeSpec(
    type="file_read",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={"type": "object", "properties": {"path": {"type": "string", "maxLength": 255}}, "required": ["path"]},
    output_schema={"type": "object", "properties": {"content": {"type": "string"}}},
    side_effect=SideEffectClass.NONE,
)
FILE_WRITE_TOOL_SPEC = NodeSpec(
    type="file_write",
    config_schema={"type": "object", "additionalProperties": False, "properties": {}},
    input_schema={"type": "object", "properties": {"path": {"type": "string", "maxLength": 255},
                                                   "content": {"type": "string"}}, "required": ["path", "content"]},
    output_schema={"type": "object", "properties": {"path": {"type": "string"}, "bytes": {"type": "integer"}}},
    side_effect=SideEffectClass.NONE,
)
SANDBOX_TOOL_TYPES = ("python_exec", "shell_exec", "file_read", "file_write")
AGENT_TOOL_TYPES = AGENT_TOOL_TYPES + SANDBOX_TOOL_TYPES

BUILTIN_NODE_SPECS: dict[str, NodeSpec] = {
    "python_exec": PYTHON_EXEC_TOOL_SPEC,
    "shell_exec": SHELL_EXEC_TOOL_SPEC,
    "file_read": FILE_READ_TOOL_SPEC,
    "file_write": FILE_WRITE_TOOL_SPEC,
    "webhook_trigger": WEBHOOK_TRIGGER_SPEC,
    "manual_trigger": MANUAL_TRIGGER_SPEC,
    "llm": LLM_NODE_SPEC,
    "agent": AGENT_NODE_SPEC,
    "tool": TOOL_NODE_SPEC,
    "fetch_url": FETCH_URL_TOOL_SPEC,
    "calculator": CALCULATOR_TOOL_SPEC,
    "send_email": SEND_EMAIL_SINK_SPEC,
    "send_slack": SEND_SLACK_SINK_SPEC,
    "approval": APPROVAL_NODE_SPEC,
    "validator": VALIDATOR_NODE_SPEC,
    "quarantined_extraction": QUARANTINED_EXTRACTION_SPEC,
    "loop": LOOP_NODE_SPEC,
    "http_request": HTTP_REQUEST_SPEC,
    "condition": CONDITION_NODE_SPEC,
    "merge": MERGE_NODE_SPEC,
    "wait": WAIT_NODE_SPEC,
    "error_handler": ERROR_HANDLER_NODE_SPEC,
    "subflow": SUBFLOW_NODE_SPEC,
}
