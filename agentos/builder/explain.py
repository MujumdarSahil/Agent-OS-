"""Deterministic explanation of a draft (4.0 D9): step by step in plain English, and a security summary computed
from the static analyzer's labels (never from the model)."""

from __future__ import annotations

from typing import Any

from agentos.builder.schema import to_definition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.specs import SideEffectClass, effective_side_effect
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.flows.tool_catalog import ToolCatalog

UNTRUSTED_SOURCE_TYPES = {"webhook_trigger": "webhook payload", "manual_trigger": "run inputs",
                          "http_request": "HTTP response", "fetch_url": "fetched web page", "tool": "tool output",
                          "error_handler": "error details"}


def _short(text: Any, n: int = 80) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def order(flow: dict[str, Any]) -> list[str]:
    """Topological order starting at the entrypoint (stable: declaration order among ready nodes)."""
    nodes = list(flow["nodes"])
    indeg = {n: 0 for n in nodes}
    for e in flow.get("edges") or []:
        if e["target"] in indeg:
            indeg[e["target"]] += 1
    ready = [flow["entrypoint"]] + [n for n in nodes if indeg[n] == 0 and n != flow["entrypoint"]]
    out: list[str] = []
    while ready:
        cur = ready.pop(0)
        if cur in out:
            continue
        out.append(cur)
        for e in flow.get("edges") or []:
            if e["source"] == cur and e["target"] in indeg:
                indeg[e["target"]] -= 1
                if indeg[e["target"]] == 0:
                    ready.append(e["target"])
    return out + [n for n in nodes if n not in out]


def _from(flow: dict[str, Any], nid: str, arg: str) -> str | None:
    for e in flow.get("edges") or []:
        if e["target"] == nid and arg in (e.get("arg_mapping") or {}):
            return f"{e['source']}.{e['arg_mapping'][arg]}"
    return None


def describe_step(flow: dict[str, Any], nid: str) -> str:
    n = flow["nodes"][nid]
    t, cfg, pinned = n["type"], n.get("config") or {}, n.get("pinned_args") or {}

    def arg(a: str) -> str:
        if a in pinned:
            return f"{pinned[a]} (pinned)"
        src = _from(flow, nid, a)
        return f"the value of {src}" if src else "(not set)"

    if t == "webhook_trigger":
        return "Starts when its webhook receives a request; the payload is UNTRUSTED."
    if t == "manual_trigger":
        return "Starts when someone runs it; its inputs are treated as UNTRUSTED."
    if t == "llm":
        return f"Asks a model{': ' + _short(cfg.get('system_prompt')) if cfg.get('system_prompt') else ''}."
    if t == "agent":
        tools = ", ".join(cfg.get("tools") or []) or "no tools"
        return f"Agent '{_short(cfg.get('role') or nid, 40)}' works on: {_short(cfg.get('goal'))} ({tools})."
    if t == "send_email":
        return f"Sends an email to {arg('to')} with body from {arg('body')}."
    if t == "send_slack":
        return f"Posts to Slack channel {arg('channel')} the text from {arg('text')}."
    if t == "http_request":
        url = pinned.get("url") or cfg.get("url") or arg("url")
        return f"Makes an HTTP {str(cfg.get('method') or 'GET').upper()} request to {url}."
    if t == "condition":
        nxt = {b: [e["target"] for e in flow["edges"] if e["source"] == nid and e.get("branch") == b]
               for b in ("true", "false")}
        return (f"Checks {_short(cfg.get('expression'))}: if true -> {', '.join(nxt['true']) or 'nothing'}, "
                f"otherwise -> {', '.join(nxt['false']) or 'nothing'}.")
    if t == "approval":
        ap = cfg.get("approves") or {}
        return f"Waits for a person to approve {', '.join(ap.get('args') or [])} of step '{ap.get('sink_node')}'."
    if t == "validator":
        return f"Checks that the value is {cfg.get('field_type')}" + (
            f" in allowlist {cfg['allowlist_name']}." if cfg.get("allowlist_name") else ".")
    if t == "quarantined_extraction":
        names = ", ".join(f.get("name", "?") for f in cfg.get("fields") or [] if isinstance(f, dict))
        return f"Extracts only constrained fields ({names}) from the untrusted text, with no tools."
    if t == "wait":
        return f"Waits {cfg.get('delay_seconds')} seconds."
    if t == "merge":
        return "Joins the branches."
    if t == "error_handler":
        return "Handles a failure of the step before it."
    if t == "subflow":
        return f"Runs flow {cfg.get('flow_id')} v{cfg.get('version')}."
    return f"Runs a {t} step."


def steps(flow: dict[str, Any]) -> list[dict[str, str]]:
    return [{"node_id": nid, "type": flow["nodes"][nid]["type"], "text": describe_step(flow, nid)}
            for nid in order(flow)]


def security_summary(flow: dict[str, Any], policy: SecurityPolicy, catalog: ToolCatalog | None) -> dict[str, Any]:
    fd = to_definition(flow)
    an = StaticFlowAnalyzer(flow=fd, policy=policy, tool_catalog=catalog)
    labels, inbound, _ = an._propagate_labels_fixpoint()  # same propagation the publish check uses
    untrusted = []
    for nid, n in flow["nodes"].items():
        if n["type"] in UNTRUSTED_SOURCE_TYPES and (n["type"] != "manual_trigger" or nid == flow["entrypoint"]):
            untrusted.append({"node_id": nid, "what": UNTRUSTED_SOURCE_TYPES[n["type"]]})
        if n["type"] == "agent" and any(str(t).startswith("mcp") or t == "fetch_url"
                                        for t in (n.get("config") or {}).get("tools") or []):
            untrusted.append({"node_id": nid, "what": "agent tool outputs"})
    untrusted_ids = {u["node_id"] for u in untrusted}
    flows_to: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    pinned: list[dict[str, Any]] = []
    for nid, n in flow["nodes"].items():
        for a, v in (n.get("pinned_args") or {}).items():
            pinned.append({"node_id": nid, "arg": a, "value": v})
        eff = effective_side_effect(n["type"], n.get("config"))
        sends = eff in (SideEffectClass.EXTERNAL_SEND, SideEffectClass.DESTRUCTIVE)
        agent_sends = [t for t in (n.get("config") or {}).get("tools") or [] if t in ("send_email", "send_slack")]
        if not sends and not agent_sends:
            continue
        rec = (n.get("pinned_args") or {}).get("channel" if n["type"] == "send_slack" else "to") \
            or (n.get("pinned_args") or {}).get("url") or (n.get("config") or {}).get("url")
        sinks.append({"node_id": nid, "type": n["type"], "side_effect": eff.value if sends else "external_send",
                      "recipient": rec, "via_agent_tools": agent_sends})
        arg_labels = {}
        for e in flow.get("edges") or []:
            if e["target"] == nid:
                for ta, sf in (e.get("arg_mapping") or {}).items():
                    lbl = labels.get(e["source"], {}).get(sf) or labels.get(e["source"], {}).get("*")
                    if lbl is not None:
                        arg_labels[ta] = lbl
        if not arg_labels and nid in inbound:
            arg_labels["(context)"] = inbound[nid]
        for a, lbl in arg_labels.items():
            if a in (n.get("pinned_args") or {}) or lbl.integrity != "untrusted":
                continue
            srcs = sorted(s for s in lbl.sources if s in untrusted_ids) or sorted(
                s for s in lbl.sources if s in flow["nodes"])
            flows_to.append({"sink": nid, "arg": a, "from": srcs})
    approvals = [{"node_id": nid, "sink": (n["config"].get("approves") or {}).get("sink_node"),
                  "args": (n["config"].get("approves") or {}).get("args") or []}
                 for nid, n in flow["nodes"].items() if n["type"] == "approval"]
    # Per node: the integrity of what it outputs (any untrusted output field -> "untrusted"), for the preview colours
    node_trust = {nid: ("untrusted" if any(lbl.integrity == "untrusted" for lbl in labels.get(nid, {}).values())
                        else "trusted") for nid in flow["nodes"]}
    return {"untrusted_inputs": untrusted, "untrusted_flows": flows_to, "pinned": pinned,
            "approvals": approvals, "external_sinks": sinks, "node_trust": node_trust}
