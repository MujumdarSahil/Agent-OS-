"""Static check of a draft and deterministic one-click fixes (4.0 D8).

The check is the Publish gate's: FlowDefinition + StaticFlowAnalyzer.verify() with the server's policy and tool
catalog. Each one-click fix is applied to a copy of the draft and checked again here, so the UI shows whether that
fix alone makes the draft pass (``passes``). Recipients (to, channel, url) are never fixed by an approval.
"""

from __future__ import annotations

import copy
from typing import Any

from agentos.builder.guards import emails_in, urls_in
from agentos.builder.schema import validate_definition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.flows.tool_catalog import ToolCatalog

RECIPIENT_ARGS = ("to", "channel", "url")
APPROVABLE_ARGS = {"send_email": ("body", "subject"), "send_slack": ("text",)}
REFUSAL = ("refused: a recipient taken from the incoming message is not allowed; name a fixed recipient in the "
           "description or ask an admin for an allowlist")


def violations_of(flow: dict[str, Any], policy: SecurityPolicy, catalog: ToolCatalog | None) -> list[dict[str, Any]]:
    """Static check violations as plain dicts (rule = node.argument, as the publish audit names them)."""
    fd = validate_definition(flow)
    res = StaticFlowAnalyzer(flow=fd, policy=policy, tool_catalog=catalog).verify()
    return [{"rule": f"{v.node_id}.{v.target_arg}", "node_id": v.node_id, "target_arg": v.target_arg,
             "path": list(v.path), "reason": v.reason} for v in res.violations]


def passes(flow: dict[str, Any], policy: SecurityPolicy, catalog: ToolCatalog | None) -> bool:
    try:
        return not violations_of(flow, policy, catalog)
    except ValueError:
        return False


def _unique_id(flow: dict[str, Any], base: str) -> str:
    nid, i = base[:60], 2
    while nid in flow["nodes"]:
        nid, i = f"{base[:57]}_{i}", i + 1
    return nid


def _split_arg(node: dict[str, Any], target_arg: str) -> tuple[str | None, str]:
    """(agent tool or None, argument) of a violation target ("send_email.to" on an agent node)."""
    if node["type"] == "agent" and "." in target_arg:
        tool, arg = target_arg.split(".", 1)
        return tool, arg
    return None, target_arg


def pin(flow: dict[str, Any], node_id: str, target_arg: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(flow)
    node = out["nodes"][node_id]
    tool, arg = _split_arg(node, target_arg)
    node["pinned_args"][f"{tool}.{arg}" if tool else arg] = value
    if not tool:
        for e in out["edges"]:
            if e["target"] == node_id:
                e["arg_mapping"].pop(arg, None)
    return out


def use_allowlist(flow: dict[str, Any], node_id: str, arg: str, allowlist: str) -> dict[str, Any] | None:
    """Insert a validator (allowlist match) between the data that chooses the recipient and the sink."""
    out = copy.deepcopy(flow)
    inbound = [e for e in out["edges"] if e["target"] == node_id and arg in e["arg_mapping"]]
    if not inbound:
        return None
    vid = _unique_id(out, f"check_{node_id}_{arg}")
    out["nodes"][vid] = {"id": vid, "type": "validator", "pinned_args": {},
                         "config": {"field": "value", "field_type": "allowlist", "allowlist_name": allowlist}}
    for e in inbound:
        field = e["arg_mapping"].pop(arg)
        out["edges"].append({"source": e["source"], "target": vid, "arg_mapping": {"value": field}})
    out["edges"].append({"source": vid, "target": node_id, "arg_mapping": {arg: "value"}})
    return out


def add_approval(flow: dict[str, Any], node_id: str, args: list[str]) -> dict[str, Any] | None:
    """Insert an approval that approves ``args`` of the sink; control (branch) edges move to the approval."""
    out = copy.deepcopy(flow)
    inbound = [e for e in out["edges"] if e["target"] == node_id]
    if not any(set(args) & set(e["arg_mapping"]) for e in inbound):
        return None
    aid = _unique_id(out, f"approve_{node_id}")
    out["nodes"][aid] = {"id": aid, "type": "approval", "pinned_args": {}, "config": {
        "prompt": f"Review {', '.join(args)} before step '{node_id}' sends it", "approves": {"sink_node": node_id,
                                                                                         "args": list(args)}}}
    keep = []
    for e in out["edges"]:
        if e["target"] != node_id:
            keep.append(e)
            continue
        moved = {a: f for a, f in e["arg_mapping"].items() if a in args}
        rest = {a: f for a, f in e["arg_mapping"].items() if a not in args}
        if e.get("branch"):  # the decision whether to send now decides whether to ask
            keep.append({**e, "target": aid, "arg_mapping": moved})
            if rest:
                keep.append({"source": e["source"], "target": node_id, "arg_mapping": rest})
            continue
        if moved:
            keep.append({"source": e["source"], "target": aid, "arg_mapping": moved})
        if rest or not moved:
            keep.append({**e, "arg_mapping": rest})
    keep.append({"source": aid, "target": node_id, "arg_mapping": {a: a for a in args}})
    out["edges"] = keep
    if out["entrypoint"] == node_id:
        return None
    return out


def _candidates(arg: str, node_type: str, stated: str, policy: SecurityPolicy) -> list[str]:
    if arg == "to":
        return emails_in(stated)
    if arg == "channel":
        low = stated.lower()
        return [c for c in sorted(policy.slack_channels) if c.lower() in low]
    if arg == "url" and node_type == "http_request":
        return urls_in(stated)
    return []


def one_click_fixes(flow: dict[str, Any], violations: list[dict[str, Any]], stated: str, policy: SecurityPolicy,
                    catalog: ToolCatalog | None) -> tuple[list[dict[str, Any]], list[str]]:
    """(fixes, refusals). ``stated``: only what the user wrote (description, answers, change request)."""
    fixes: list[dict[str, Any]] = []
    refusals: list[str] = []
    done: set[tuple[str, str]] = set()
    for v in violations:
        node = flow["nodes"].get(v["node_id"])
        if node is None:
            continue
        tool, arg = _split_arg(node, v["target_arg"])
        key = (v["node_id"], v["target_arg"])
        if key in done:
            continue
        done.add(key)
        sink_type = tool or node["type"]
        if arg in RECIPIENT_ARGS:
            options: list[dict[str, Any]] = []
            for value in _candidates(arg, sink_type, stated, policy):
                options.append({"kind": "pin", "label": f"Pin this recipient to {value}", "value": value,
                                "flow": pin(flow, v["node_id"], v["target_arg"], value)})
            if not tool and arg in ("to", "channel"):
                for name in sorted(policy.allowlists):
                    fixed = use_allowlist(flow, v["node_id"], arg, name)
                    if fixed is not None:
                        options.append({"kind": "allowlist", "label": f"Use allowlist {name}", "value": name,
                                        "flow": fixed})
            if not options:
                refusals.append(f"{v['node_id']}.{arg}: {REFUSAL}")
            for o in options:
                fixes.append({"id": f"{o['kind']}:{v['node_id']}:{v['target_arg']}:{o['value']}",
                              "node_id": v["node_id"], "target_arg": v["target_arg"], **o})
            continue
        if not tool and arg in APPROVABLE_ARGS.get(node["type"], ()):
            args = [a for a in APPROVABLE_ARGS[node["type"]]
                    if any(vv["node_id"] == v["node_id"] and vv["target_arg"] == a for vv in violations)]
            fixed = add_approval(flow, v["node_id"], args)
            if fixed is not None:
                fixes.append({"id": f"approval:{v['node_id']}", "node_id": v["node_id"], "target_arg": v["target_arg"],
                              "kind": "approval", "label": f"Add an approval before {v['node_id']}",
                              "value": ",".join(args), "flow": fixed})
                done.update((v["node_id"], a) for a in args)
    for f in fixes:
        f["passes"] = passes(f["flow"], policy, catalog)
    return fixes, refusals
