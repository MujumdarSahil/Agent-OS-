"""One tool-spec lookup for the static analyzer AND the runtime proxy (2.5a).

Built-in tools resolve by their bare name (``send_email``). MCP tools resolve only by their namespaced
name (``mcp.<server>.<tool>``, or the wire form ``mcp__<server>__<tool>``) and only when the tool is
approved: enabled server, hash unchanged since approval, same launch target. Anything else raises
``ToolLookupError`` with the reason (unknown, unreviewed, changed, missing, disabled), so publish and
run time fail closed for the same reasons.

Labels (T1), shared so both sides agree:
- ``agent_initial_context``: an agent given an MCP tool whose description the admin did NOT replace has
  read server-controlled text, so its context starts UNTRUSTED. With an admin description, the server's
  description and schema text never reach the model and the rule does not apply.
- ``context_after_tool_output``: every tool output is UNTRUSTED; MCP outputs carry the confidentiality
  the admin configured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass, SinkArgumentRule
from agentos.mcp.catalog import canonical_name, is_mcp_name, parse_name, tool_status
from agentos.storage.models import MCPServerRecord


class ToolLookupError(LookupError):
    def __init__(self, name: str, reason: str, detail: str = "") -> None:
        self.name = name
        self.reason = reason
        super().__init__(detail or f"tool {name!r}: {reason}")


@dataclass(frozen=True)
class ToolEntry:
    name: str                        # canonical name
    spec: NodeSpec
    is_mcp: bool = False
    server: str | None = None
    tool: str | None = None          # normalized tool name
    server_tool_name: str | None = None  # name exactly as the server reported it (used for the call)
    sha256: str | None = None
    output_confidentiality: str = Confidentiality.INTERNAL.value
    admin_description: str | None = None
    server_description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    @property
    def model_description(self) -> str:
        """The description the model sees: the admin's when set, otherwise the server's (untrusted)."""
        if not self.is_mcp:
            return f"AgentOS mediated tool {self.name}"
        return self.admin_description if self.admin_description else self.server_description

    @property
    def model_schema(self) -> dict[str, Any]:
        """Schema the model sees. With an admin description, only property names and types are kept, so
        server-written property descriptions (another poisoning channel) never reach the model."""
        if not self.is_mcp or not self.admin_description:
            return self.input_schema
        props = (self.input_schema or {}).get("properties") or {}
        return {"type": "object", "properties": {k: {"type": (v or {}).get("type", "string")} for k, v in props.items()}}


def _mcp_spec(cname: str, side_effect: str, snapshot_schema: dict[str, Any],
              sink_rules: dict[str, dict[str, Any]], untrusted_ok: list[str]) -> NodeSpec:
    se = SideEffectClass(side_effect)
    rules: dict[str, SinkArgumentRule] = {}
    if sink_rules:
        rules = {arg: SinkArgumentRule(**r) for arg, r in sink_rules.items()}
    elif se != SideEffectClass.READ:
        # default above read: every argument requires trusted (pinned or allowlisted)
        for arg in ((snapshot_schema or {}).get("properties") or {}):
            if arg not in untrusted_ok:
                rules[arg] = SinkArgumentRule(required_integrity="trusted")
    return NodeSpec(type=cname, input_schema=snapshot_schema or {}, side_effect=se, sink_rules=rules)


class ToolCatalog:
    """Built-ins plus the MCP tools of the given server records."""

    def __init__(self, mcp_records: Iterable[MCPServerRecord] = ()) -> None:
        self._mcp: dict[str, ToolEntry | ToolLookupError] = {}
        self._servers: dict[str, MCPServerRecord] = {}
        for rec in mcp_records:
            self._servers[rec.name] = rec
            for norm, state in rec.tools.items():
                cname = canonical_name(rec.name, norm)
                status = tool_status(rec, state)
                if not rec.enabled:
                    self._mcp[cname] = ToolLookupError(cname, "disabled", f"MCP server {rec.name!r} is disabled")
                    continue
                if status != "approved":
                    detail = {
                        "unreviewed": f"MCP tool {cname!r} has not been reviewed by an admin",
                        "changed": f"MCP tool {cname!r} changed since it was approved (description, schema or server "
                                   f"target); it needs review again",
                        "missing": f"MCP tool {cname!r} is no longer offered by its server",
                    }[status]
                    self._mcp[cname] = ToolLookupError(cname, status, detail)
                    continue
                ap = state.approval
                assert ap is not None
                self._mcp[cname] = ToolEntry(
                    name=cname,
                    spec=_mcp_spec(cname, ap.side_effect, state.snapshot.input_schema, ap.sink_rules, ap.untrusted_ok_args),
                    is_mcp=True, server=rec.name, tool=norm, server_tool_name=state.snapshot.name,
                    sha256=state.snapshot.sha256, output_confidentiality=ap.output_confidentiality,
                    admin_description=ap.replacement_description, server_description=state.snapshot.description,
                    input_schema=state.snapshot.input_schema,
                )

    def server(self, name: str) -> MCPServerRecord | None:
        return self._servers.get(name)

    def resolve(self, name: str) -> ToolEntry:
        if is_mcp_name(name):
            parsed = parse_name(name)
            if parsed is None:
                raise ToolLookupError(name, "unknown", f"malformed MCP tool name {name!r}")
            cname = canonical_name(*parsed)
            found = self._mcp.get(cname)
            if found is None:
                raise ToolLookupError(cname, "unknown", f"MCP tool {cname!r} is not known (discover the server first)")
            if isinstance(found, ToolLookupError):
                raise found
            return found
        spec = BUILTIN_NODE_SPECS.get(name)
        if spec is None:
            raise ToolLookupError(name, "unknown", f"Tool {name!r} has no declared NodeSpec (fail closed)")
        return ToolEntry(name=name, spec=spec, input_schema=spec.input_schema or {})

    def try_resolve(self, name: str) -> ToolEntry | None:
        try:
            return self.resolve(name)
        except ToolLookupError:
            return None

    def mcp_hashes(self, names: Iterable[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for n in names:
            e = self.try_resolve(n)
            if e is not None and e.is_mcp and e.sha256:
                out[e.name] = e.sha256
        return out

    def approved_mcp(self) -> list[ToolEntry]:
        return [e for e in self._mcp.values() if isinstance(e, ToolEntry)]

    def agent_tool_options(self) -> list[ToolEntry]:
        """3.1: what the agent tool picker may offer: the built-in agent tools that resolve here plus the
        approved MCP tools of enabled servers. Every entry passes ``resolve`` (the check used on save)."""
        from agentos.flows.specs import AGENT_TOOL_TYPES

        builtins = [e for e in (self.try_resolve(n) for n in AGENT_TOOL_TYPES) if e is not None]
        return builtins + sorted(self.approved_mcp(), key=lambda e: e.name)


BUILTIN_CATALOG = ToolCatalog()


def description_label(entry: ToolEntry) -> Label | None:
    if entry.is_mcp and not entry.admin_description:
        return Label.untrusted(sources={f"mcp:{entry.server}/{entry.tool}#description"})
    return None


def agent_initial_context(input_label: Label, entries: Iterable[ToolEntry]) -> Label:
    label = input_label
    for e in entries:
        dl = description_label(e)
        if dl is not None:
            label = label.join(dl)
    return label


def tool_output_label(entry: ToolEntry) -> Label:
    if entry.is_mcp:
        return Label.untrusted(confidentiality=entry.output_confidentiality, sources={entry.name})
    return Label.untrusted(sources={entry.name})


def context_after_tool_output(label: Label, entry: ToolEntry) -> Label:
    return label.join(tool_output_label(entry))
