"""4.3 (D7): diff between two flow versions (or the draft and a version), security-relevant changes first.

The structural part is the 4.0 "Edit with AI" diff (agentos.builder.diff.flow_diff). On top of it:
- per changed node, the config / pinned_args keys that changed (old -> new, values shortened);
- ``security``: sink added / removed, pinned recipient or host changed, approval removed (or approving less),
  validator / extraction loosened, a new path from an untrusted source to a sink, and the static analysis result
  before vs after (both against the CURRENT policy).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agentos.builder.diff import flow_diff
from agentos.flows.specs import SideEffectClass, effective_side_effect

SEND_TOOLS = ("send_email", "send_slack")
RECIPIENT_KEYS = {"send_email": "to", "send_slack": "channel"}
SECURITY_KINDS = ("sink_added", "sink_removed", "recipient_changed", "approval_removed", "validator_loosened",
                  "extraction_loosened", "new_untrusted_path", "analysis_changed")


def _short(v: Any, n: int = 160) -> Any:
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    text = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    return text if len(text) <= n else text[: n - 1] + "…"


def _nodes(flow: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {k: (v if isinstance(v, dict) else dict(v)) for k, v in (flow.get("nodes") or {}).items()}


def _sinks(flow: Dict[str, Any]) -> Dict[str, str]:
    """{sink key: kind}. A sink node by id; an agent's send tool as "<node>.<tool>"."""
    out: Dict[str, str] = {}
    for nid, n in _nodes(flow).items():
        t = n.get("type", "")
        eff = effective_side_effect(t, n.get("config") or {})
        if eff in (SideEffectClass.EXTERNAL_SEND, SideEffectClass.WRITE, SideEffectClass.DESTRUCTIVE):
            out[nid] = t
        if t == "agent":
            for tool in (n.get("config") or {}).get("tools") or []:
                if tool in SEND_TOOLS or str(tool).startswith("mcp:"):
                    out[f"{nid}.{tool}"] = f"agent tool {tool}"
    return out


def _host(url: Any) -> Optional[str]:
    if not isinstance(url, str) or not url:
        return None
    from agentos.flows.net_guard import url_host

    try:
        return url_host(url)
    except Exception:
        return url


def _recipients(flow: Dict[str, Any]) -> Dict[str, Any]:
    """{"<node>.<arg>": value} of the pinned destinations: send_email to, send_slack channel, http_request host, and
    agent tool pins ("send_email.to")."""
    out: Dict[str, Any] = {}
    for nid, n in _nodes(flow).items():
        t = n.get("type")
        pinned = n.get("pinned_args") or {}
        cfg = n.get("config") or {}
        if t in RECIPIENT_KEYS:
            out[f"{nid}.{RECIPIENT_KEYS[t]}"] = pinned.get(RECIPIENT_KEYS[t])
        elif t == "http_request":
            out[f"{nid}.host"] = _host(pinned.get("url") or cfg.get("url"))
        elif t == "agent":
            for k, v in pinned.items():
                if k.endswith(".to") or k.endswith(".channel") or k.endswith(".url"):
                    out[f"{nid}.{k}"] = _host(v) if k.endswith(".url") else v
    return out


def _approvals(flow: Dict[str, Any]) -> Dict[str, set]:
    """{approval node: {(sink, arg)}} (an approval without explicit approves -> {("*", "*")})."""
    out: Dict[str, set] = {}
    for nid, n in _nodes(flow).items():
        if n.get("type") != "approval":
            continue
        ap = (n.get("config") or {}).get("approves") or {}
        args = ap.get("args") or []
        out[nid] = {(ap.get("sink_node") or "*", a) for a in args} or {("*", "*")}
    return out


def _constraint_loosened(old: Dict[str, Any], new: Dict[str, Any], type_key: str) -> List[str]:
    why: List[str] = []
    if old.get(type_key) != new.get(type_key):
        why.append(f"type {old.get(type_key)} -> {new.get(type_key)}")
        return why
    added = sorted(set(new.get("values") or []) - set(old.get("values") or []))
    if added:
        why.append(f"allowed values added: {', '.join(map(str, added))[:120]}")
    if isinstance(old.get("min"), (int, float)) and isinstance(new.get("min"), (int, float)) and new["min"] < old["min"]:
        why.append(f"min {old['min']} -> {new['min']}")
    if isinstance(old.get("max"), (int, float)) and isinstance(new.get("max"), (int, float)) and new["max"] > old["max"]:
        why.append(f"max {old['max']} -> {new['max']}")
    for k in ("pattern", "allowlist_name"):
        if old.get(k) != new.get(k):
            why.append(f"{k} {old.get(k)} -> {new.get(k)}")
    return why


def _loosened(old_flow: Dict[str, Any], new_flow: Dict[str, Any]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    on, nn = _nodes(old_flow), _nodes(new_flow)
    for nid, o in on.items():
        t = o.get("type")
        if t not in ("validator", "quarantined_extraction"):
            continue
        kind = "validator_loosened" if t == "validator" else "extraction_loosened"
        n = nn.get(nid)
        if n is None or n.get("type") != t:
            items.append({"kind": kind, "node": nid, "detail": f"{t} removed"})
            continue
        oc, nc = o.get("config") or {}, n.get("config") or {}
        if t == "validator":
            why = _constraint_loosened(oc, nc, "field_type")
        else:
            of = {f.get("name"): f for f in oc.get("fields") or [] if isinstance(f, dict)}
            nf = {f.get("name"): f for f in nc.get("fields") or [] if isinstance(f, dict)}
            why = [f"field {k} added" for k in sorted(set(nf) - set(of))]
            for k in sorted(set(of) & set(nf)):
                why += [f"field {k}: {w}" for w in _constraint_loosened(of[k], nf[k], "type")]
        if why:
            items.append({"kind": kind, "node": nid, "detail": "; ".join(why)})
    return items


def _node_changes(old_flow: Dict[str, Any], new_flow: Dict[str, Any], changed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    on, nn = _nodes(old_flow), _nodes(new_flow)
    out = []
    for c in changed:
        a, b = on[c["id"]], nn[c["id"]]
        row: Dict[str, Any] = {"id": c["id"], "fields": c["fields"]}
        if a.get("type") != b.get("type"):
            row["type"] = [a.get("type"), b.get("type")]
        for f in ("config", "pinned_args"):
            ao, bo = a.get(f) or {}, b.get(f) or {}
            keys = sorted(k for k in set(ao) | set(bo) if ao.get(k) != bo.get(k))
            if keys:
                row[f] = {k: [_short(ao.get(k)), _short(bo.get(k))] for k in keys}
        out.append(row)
    return out


def _analysis(flow: Dict[str, Any], policy: Any, catalog: Any, summaries: Optional[Dict[Any, Any]]) -> Dict[str, Any]:
    from agentos.flows.environments import flow_definition
    from agentos.flows.static_analyzer import StaticFlowAnalyzer

    try:
        an = StaticFlowAnalyzer(flow=flow_definition(flow), policy=policy, subflow_summaries=summaries or {},
                                tool_catalog=catalog)
        res = an.verify()
        return {"passed": res.is_valid, "violations": sorted({f"{v.node_id}.{v.target_arg}" for v in res.violations}),
                "untrusted_paths": an.untrusted_sink_paths()}
    except Exception as e:
        return {"passed": False, "violations": [f"(definition): {str(e)[:160]}"], "untrusted_paths": []}


def version_diff(old: Dict[str, Any], new: Dict[str, Any], policy: Any, catalog: Any = None,
                 old_summaries: Optional[Dict[Any, Any]] = None,
                 new_summaries: Optional[Dict[Any, Any]] = None) -> Dict[str, Any]:
    """Diff of ``old`` -> ``new`` (flow dicts). ``security`` lists every security-relevant change, first in the UI."""
    base = flow_diff(old, new)
    security: List[Dict[str, Any]] = []

    os_, ns = _sinks(old), _sinks(new)
    nr = _recipients(new)
    for k in sorted(set(ns) - set(os_)):
        dest = [f"{rk.split('.', 1)[1]}={v}" for rk, v in nr.items() if rk.split(".")[0] == k.split(".")[0] and v]
        security.append({"kind": "sink_added", "node": k, "detail": f"{ns[k]}" + (f" ({', '.join(dest)})" if dest else "")})
    for k in sorted(set(os_) - set(ns)):
        security.append({"kind": "sink_removed", "node": k, "detail": os_[k]})

    orr = _recipients(old)
    for k in sorted(set(orr) & set(nr)):
        if orr[k] != nr[k]:
            security.append({"kind": "recipient_changed", "node": k.split(".")[0],
                             "detail": f"{k.split('.', 1)[1]}: {orr[k]} -> {nr[k]}", "from": orr[k], "to": nr[k]})

    oa, na = _approvals(old), _approvals(new)
    for nid in sorted(oa):
        if nid not in na:
            security.append({"kind": "approval_removed", "node": nid, "detail": "approval node removed"})
        elif oa[nid] - na[nid]:
            lost = ", ".join(f"{s}.{a}" for s, a in sorted(oa[nid] - na[nid]))
            security.append({"kind": "approval_removed", "node": nid, "detail": f"no longer approves {lost}"})

    security += _loosened(old, new)

    before = _analysis(old, policy, catalog, old_summaries)
    after = _analysis(new, policy, catalog, new_summaries)
    for p in sorted(set(after["untrusted_paths"]) - set(before["untrusted_paths"])):
        security.append({"kind": "new_untrusted_path", "node": p.split("->")[-1], "detail": f"untrusted data: {p}"})
    if before["passed"] != after["passed"] or before["violations"] != after["violations"]:
        security.append({"kind": "analysis_changed", "node": "(flow)",
                         "detail": f"security check {'passed' if before['passed'] else 'failed'} -> "
                                   f"{'passed' if after['passed'] else 'failed'}"
                                   + (f"; new violations: {', '.join(sorted(set(after['violations']) - set(before['violations'])))}"
                                      if set(after["violations"]) - set(before["violations"]) else "")})

    order = {k: i for i, k in enumerate(SECURITY_KINDS)}
    security.sort(key=lambda x: (order.get(x["kind"], 99), x["node"]))
    out = {**base, "nodes_changed_detail": _node_changes(old, new, base["nodes_changed"]),
           "security": security, "analysis": {"before": before, "after": after}}
    out["empty"] = base["empty"] and not security
    return out
