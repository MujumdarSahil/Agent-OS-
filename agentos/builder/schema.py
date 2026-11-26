"""Strict schema and parsing of the builder model's output (4.0 D5).

Every error message here is written by AgentOS. The model's own text is never echoed back to it (only identifiers
that match the node-id pattern are named), and the raw output is never stored or logged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import jsonschema

from agentos.flows.models import FlowDefinition
from agentos.flows.specs import BUILTIN_NODE_SPECS, SANDBOX_TOOL_TYPES

MAX_DESCRIPTION = 4000
MAX_ANSWERS = 3
MAX_ANSWER = 500
MAX_CHANGE_REQUEST = 1000
MAX_NODES = 30
MAX_EDGES = 120
MAX_QUESTIONS = 3
MAX_EXPLANATION = 2000

# Node types a flow may use as steps (sandbox code tools are agent tools only, 3.5).
STEP_TYPES = sorted(t for t in BUILTIN_NODE_SPECS if t not in SANDBOX_TOOL_TYPES)

_ID = r"^[A-Za-z0-9_-]{1,64}$"
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

NODE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["id", "type"],
    "properties": {
        "id": {"type": "string", "pattern": _ID},
        "type": {"type": "string", "enum": STEP_TYPES},
        "config": {"type": "object"},
        "pinned_args": {"type": "object"},
    },
}
EDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["source", "target"],
    "properties": {
        "source": {"type": "string", "pattern": _ID},
        "target": {"type": "string", "pattern": _ID},
        "arg_mapping": {"type": "object", "additionalProperties": {"type": "string", "maxLength": 64}},
        "branch": {"enum": ["true", "false", "on_error", None]},
    },
}
FLOW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["entrypoint", "nodes"],
    "properties": {
        "id": {"type": "string", "pattern": _ID},
        "name": {"type": "string", "maxLength": 120},
        "entrypoint": {"type": "string", "pattern": _ID},
        "nodes": {"type": "object", "minProperties": 1, "maxProperties": MAX_NODES,
                  "additionalProperties": NODE_SCHEMA},
        "edges": {"type": "array", "maxItems": MAX_EDGES, "items": EDGE_SCHEMA},
        # Generated flows have no loops (bounded loops are built by hand in the visual editor).
        "loops": {"type": "object", "maxProperties": 0},
    },
}
OUTPUT_SCHEMA: dict[str, Any] = {
    "oneOf": [
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["questions"],
            "properties": {"questions": {"type": "array", "minItems": 1, "maxItems": MAX_QUESTIONS,
                                         "items": {"type": "string", "minLength": 1, "maxLength": 300}}},
        },
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["flow"],
            "properties": {"flow": FLOW_SCHEMA,
                           "explanation": {"type": "string", "maxLength": MAX_EXPLANATION}},
        },
    ]
}

# The compact schema the model is shown (same rules, without the long node-type enum, which the catalog lists).
PROMPT_SCHEMA = {
    "flow": {
        "id": "short_snake_case_id",
        "name": "Readable name",
        "entrypoint": "<node id of the trigger>",
        "nodes": {"<node id>": {"id": "<same node id>", "type": "<node type from the catalog>",
                                "config": {"...": "only keys from that type's config schema"},
                                "pinned_args": {"<sink argument>": "<fixed value stated by the user>"}}},
        "edges": [{"source": "<node id>", "target": "<node id>",
                   "arg_mapping": {"<target input arg>": "<source output field>"},
                   "branch": "true | false | on_error (only from a condition / into an error_handler), else omit"}],
    },
    "explanation": "two or three sentences",
}


class BuilderOutputError(ValueError):
    """The model output is not a valid draft. The message is AgentOS-written (safe to send back to the model)."""


@dataclass
class ParsedOutput:
    questions: list[str] = field(default_factory=list)
    flow: dict[str, Any] | None = None
    explanation: str = ""


def _safe(token: Any) -> str:
    return str(token) if _SAFE_TOKEN.fullmatch(str(token)) else "…"


def _where(path: Any) -> str:
    parts = [_safe(p) for p in path]
    return "/".join(parts) if parts else "(top level)"


def _schema_message(err: jsonschema.ValidationError) -> str:
    """Describe a schema error without quoting model-written values."""
    best = jsonschema.exceptions.best_match([err]) or err
    errs = list(best.context or []) or [best]
    e = min(errs, key=lambda x: len(list(x.path)) * -1)  # deepest error of the best branch
    where = _where(e.absolute_path)
    kind = e.validator
    if kind == "enum" and list(e.absolute_path)[-1:] == ["type"]:
        return f"{where}: unknown node type. Use only node types from the catalog."
    if kind == "additionalProperties":
        return f"{where}: contains a field that is not allowed here (the schema does not allow extra fields)."
    if kind == "maxProperties" and "nodes" in [str(p) for p in e.absolute_path]:
        return f"the flow has more than {MAX_NODES} nodes; use at most {MAX_NODES}."
    if kind == "maxProperties" and "loops" in [str(p) for p in e.absolute_path]:
        return "generated flows may not declare loops; leave 'loops' out."
    if kind == "required":
        return f"{where}: a required field is missing."
    if kind == "oneOf":
        return ("the output must be exactly one JSON object: either {\"questions\": [...]} or "
                "{\"flow\": {...}, \"explanation\": \"...\"}, with no other keys.")
    return f"{where}: value does not match the schema ({kind})."


_QUOTED = re.compile(r"'([^']*)'")


def _redact_quotes(msg: str) -> str:
    """FlowDefinition messages quote values; keep only identifier-like quotes (node ids, field names)."""
    out = _QUOTED.sub(lambda m: f"'{m.group(1)}'" if _SAFE_TOKEN.fullmatch(m.group(1)) else "'…'", msg)
    return out[:300]


def strip_fences(raw: str) -> str:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[A-Za-z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_output(raw: Any, agent_tools: set[str]) -> ParsedOutput:
    """Parse and validate one model answer. Raises BuilderOutputError (AgentOS-written message)."""
    if not isinstance(raw, str):
        raise BuilderOutputError("the answer was empty; return one JSON object.")
    try:
        data = json.loads(strip_fences(raw))
    except ValueError:
        raise BuilderOutputError("the answer is not valid JSON; return one JSON object and nothing else.") from None
    if not isinstance(data, dict):
        raise BuilderOutputError("the answer must be a JSON object.")
    validator = jsonschema.Draft202012Validator(OUTPUT_SCHEMA)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    if errors:
        # Prefer the branch the model evidently chose, so the message is specific.
        branch = 1 if "flow" in data else 0 if "questions" in data else None
        if branch is not None:
            sub = jsonschema.Draft202012Validator(OUTPUT_SCHEMA["oneOf"][branch])
            sub_errors = sorted(sub.iter_errors(data), key=lambda e: -len(list(e.absolute_path)))
            if sub_errors:
                raise BuilderOutputError(_schema_message(sub_errors[0]))
        raise BuilderOutputError(_schema_message(errors[0]))
    if "questions" in data:
        return ParsedOutput(questions=[q.strip() for q in data["questions"] if q.strip()][:MAX_QUESTIONS])
    flow = normalize_flow(data["flow"])
    for nid, node in flow["nodes"].items():
        if node["type"] == "agent":
            for tool in (node.get("config") or {}).get("tools") or []:
                if tool not in agent_tools:
                    raise BuilderOutputError(
                        f"node '{_safe(nid)}': uses a tool that is not in the approved tool list. "
                        f"Approved tools: {', '.join(sorted(agent_tools))}.")
    validate_definition(flow)
    return ParsedOutput(flow=flow, explanation=str(data.get("explanation") or "")[:MAX_EXPLANATION])


def normalize_flow(flow: dict[str, Any], flow_id: str | None = None) -> dict[str, Any]:
    """Canonical dict form: node ids equal their keys, defaults filled, no loops."""
    nodes = {}
    for key, n in (flow.get("nodes") or {}).items():
        if n.get("id") != key:
            raise BuilderOutputError(f"node '{_safe(key)}': its 'id' must equal its key in 'nodes'.")
        nodes[key] = {"id": key, "type": n["type"], "config": dict(n.get("config") or {}),
                      "pinned_args": dict(n.get("pinned_args") or {})}
    edges = []
    for e in flow.get("edges") or []:
        edge = {"source": e["source"], "target": e["target"], "arg_mapping": dict(e.get("arg_mapping") or {})}
        if e.get("branch"):
            edge["branch"] = e["branch"]
        edges.append(edge)
    fid = flow_id or slug(flow.get("id") or flow.get("name") or "generated_flow")
    return {"id": fid, "name": str(flow.get("name") or fid)[:120], "entrypoint": flow["entrypoint"],
            "nodes": nodes, "edges": edges, "loops": {}}


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "_", str(text).lower()).strip("_-")[:48]
    return s or "generated_flow"


def to_definition(flow: dict[str, Any]) -> FlowDefinition:
    return FlowDefinition(id=flow["id"], name=flow.get("name", ""), entrypoint=flow["entrypoint"],
                          nodes=flow["nodes"], edges=flow.get("edges") or [], loops=flow.get("loops") or {})


def validate_definition(flow: dict[str, Any]) -> FlowDefinition:
    """FlowDefinition (node configs, edges, DAG, control flow), with a message safe to send back."""
    if len(flow.get("nodes") or {}) > MAX_NODES:
        raise BuilderOutputError(f"the flow has more than {MAX_NODES} nodes; use at most {MAX_NODES}.")
    try:
        return to_definition(flow)
    except Exception as err:  # pydantic wraps InvalidFlowConfigError / CyclicFlowError
        text = str(err)
        for marker in ("Value error, ", "Assertion failed, "):
            if marker in text:
                text = text.split(marker, 1)[1]
        text = text.split("[type=", 1)[0].strip()
        raise BuilderOutputError(f"the flow is not valid: {_redact_quotes(text)}") from None
