"""MCP tool naming, hashing and review status (2.5a). Pure functions, no I/O.

Names
- Canonical: ``mcp.<server>.<tool>``. A bare name never resolves to an MCP tool, so an MCP tool can
  never shadow a built-in such as send_email or http_request (T3).
- Wire (what the model sees): ``mcp__<server>__<tool>``. Function names in model APIs allow only
  ``[A-Za-z0-9_-]``, so dots cannot be used there.
- Server and tool names are normalised to ``[a-z0-9_]`` (case folded; ``-``, spaces and other characters
  become ``_``), so look-alikes such as ``Send-Email`` and ``send_email`` collide; colliding names are
  all rejected.

Review status of a discovered tool
- unreviewed: no approval yet.
- approved: approval exists, its pinned hash equals the latest snapshot hash, and the server launch
  target is unchanged.
- changed: approved, but the description/schema hash or the launch target changed since (T2).
- missing: the latest discovery did not return it.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

from agentos.storage.models import MCPServerRecord, MCPToolSnapshot, MCPToolState

PREFIX = "mcp."
WIRE_PREFIX = "mcp__"
_INVALID = re.compile(r"[^a-z0-9_]+")


class MCPNameError(ValueError):
    pass


def normalize_name(name: str) -> str:
    norm = _INVALID.sub("_", (name or "").strip().lower()).strip("_")
    if not norm or "__" in norm:
        # "__" is the wire separator; refuse it so wire names stay unambiguous
        raise MCPNameError(f"name {name!r} is empty or contains '__' after normalisation")
    return norm


def canonical_name(server: str, tool: str) -> str:
    return f"{PREFIX}{server}.{tool}"


def wire_name(server: str, tool: str) -> str:
    return f"{WIRE_PREFIX}{server}__{tool}"


def parse_name(name: str) -> tuple[str, str] | None:
    """(server, tool) for a canonical or wire MCP name; None for anything else (bare names)."""
    if name.startswith(PREFIX):
        rest = name[len(PREFIX):]
        server, sep, tool = rest.partition(".")
    elif name.startswith(WIRE_PREFIX):
        rest = name[len(WIRE_PREFIX):]
        server, sep, tool = rest.partition("__")
    else:
        return None
    if not sep or not server or not tool:
        return None
    return server, tool


def is_mcp_name(name: str) -> bool:
    return name.startswith(PREFIX) or name.startswith(WIRE_PREFIX)


def tool_hash(name: str, description: str, input_schema: dict[str, Any]) -> str:
    canonical = json.dumps([name, description or "", input_schema or {}], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def target_fingerprint(record: MCPServerRecord) -> str:
    """Fingerprint of what will be launched or connected to; approvals are pinned to it."""
    raw = json.dumps([record.transport, record.command or "", list(record.args), record.url or ""], separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def tool_status(record: MCPServerRecord, state: MCPToolState) -> str:
    if state.missing:
        return "missing"
    if state.approval is None:
        return "unreviewed"
    if state.approval.approved_sha256 != state.snapshot.sha256:
        return "changed"
    if state.approval.target_fingerprint != target_fingerprint(record):
        return "changed"
    return "approved"


def merge_discovery(
    record: MCPServerRecord,
    listed: Iterable[dict[str, Any]],
    builtin_names: Iterable[str] = (),
) -> tuple[dict[str, MCPToolState], list[dict[str, Any]]]:
    """New ``tools`` map for ``record`` from a tools/list result, plus the events it implies.

    ``listed`` items: {"name", "description", "input_schema"} exactly as the server sent them.
    Approvals are kept; a tool whose hash differs from its approval becomes "changed" (it is never
    re-approved automatically). Colliding names are rejected (none of them is kept).
    """
    builtins = set(builtin_names)
    events: list[dict[str, Any]] = []
    by_norm: dict[str, list[dict[str, Any]]] = {}
    for item in listed:
        raw = str(item.get("name") or "")
        try:
            norm = normalize_name(raw)
        except MCPNameError as e:
            events.append({"type": "mcp_tool_name_rejected", "tool": raw[:200], "reason": str(e)})
            continue
        by_norm.setdefault(norm, []).append(item)

    tools: dict[str, MCPToolState] = {}
    for norm, items in by_norm.items():
        if len(items) > 1:
            events.append({
                "type": "mcp_tool_name_rejected",
                "tool": norm,
                "reason": f"{len(items)} tools collide after normalisation: "
                          + ", ".join(repr(str(i.get('name'))[:100]) for i in items),
            })
            continue
        item = items[0]
        name, desc = str(item.get("name")), str(item.get("description") or "")
        schema = item.get("input_schema") or {}
        snap = MCPToolSnapshot(
            name=name, description=desc, input_schema=schema,
            sha256=tool_hash(name, desc, schema), source=f"mcp:{record.name}",
        )
        prev = record.tools.get(norm)
        warnings = []
        if norm in builtins or name in builtins:
            warnings.append(
                f"bare name {name!r} matches a built-in tool; it is only ever available as "
                f"{canonical_name(record.name, norm)!r} and never replaces the built-in"
            )
        state = MCPToolState(snapshot=snap, approval=prev.approval if prev else None, warnings=warnings)
        tools[norm] = state
        if prev and prev.approval and prev.approval.approved_sha256 != snap.sha256:
            events.append({
                "type": "mcp_tool_changed",
                "tool": norm,
                "approved_sha256": prev.approval.approved_sha256,
                "new_sha256": snap.sha256,
            })

    for norm, prev in record.tools.items():
        if norm not in tools and not any(e.get("tool") == norm for e in events):
            tools[norm] = prev.model_copy(update={"missing": True})
            if prev.approval:
                events.append({"type": "mcp_tool_changed", "tool": norm, "reason": "no longer offered by the server"})
    return tools, events
