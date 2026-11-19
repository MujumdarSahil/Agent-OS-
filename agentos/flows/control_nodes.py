"""
Runtime support for the 2.3 node catalog, used by FlowEngine.

- Branch-aware readiness: edges are active, dead (branch not taken / source skipped) or pending.
- Control-dependency labels: the join of every condition predicate (and on_error path) that
  decides whether a node runs; DESTRUCTIVE sinks require it to be trusted (shared rule code).
- Dispatch for condition, merge, error_handler, subflow and http_request (wait lives in the engine
  because it pauses the run).
"""

from __future__ import annotations

import asyncio
import inspect
from typing import TYPE_CHECKING, Any

from agentos.flows.expressions import evaluate, label_of, references, render
from agentos.flows.labels import Label
from agentos.flows.models import EdgeDefinition, FlowDefinition, NodeDefinition
from agentos.flows.net_guard import (
    DEFAULT_MAX_BYTES,
    DEFAULT_TIMEOUT_S,
    HttpRequestTransport,
    check_url,
)
from agentos.flows.rules import (
    SinkRuleViolationError,
    evaluate_control_dependency,
    evaluate_sink_argument_rule,
)
from agentos.flows.specs import BUILTIN_NODE_SPECS, SideEffectClass, effective_side_effect
from agentos.flows.state import FlowRunState, NodeState, RunStatus

if TYPE_CHECKING:  # pragma: no cover
    from agentos.flows.engine import FlowEngine

ACTIVE, DEAD, PENDING = "active", "dead", "pending"
MAX_SUBFLOW_DEPTH = 5


# ---------------------------------------------------------------------------- readiness


def edge_status(state: FlowRunState, edge: EdgeDefinition) -> str:
    src = state.node_states.get(edge.source)
    if edge.branch == "on_error":
        if src == NodeState.FAILED and edge.source in state.handled_failures:
            return ACTIVE
        if src in (NodeState.SUCCEEDED, NodeState.SKIPPED):
            return DEAD
        return PENDING
    if src == NodeState.SUCCEEDED:
        if edge.branch in ("true", "false"):
            chosen = str(state.node_outputs.get(edge.source, {}).get("branch"))
            return ACTIVE if chosen == edge.branch else DEAD
        return ACTIVE
    if src == NodeState.SKIPPED:
        return DEAD
    if src == NodeState.FAILED and edge.source in state.handled_failures:
        return DEAD  # normal successors of a handled failure do not run
    return PENDING


def readiness(flow: FlowDefinition, state: FlowRunState, node_id: str) -> str:
    """'ready', 'skip' or 'wait' for a node that has not started."""
    node = flow.nodes[node_id]
    inbound = [e for e in flow.edges if e.target == node_id]
    if not inbound:
        return "ready" if node_id == flow.entrypoint else "wait"
    statuses = [edge_status(state, e) for e in inbound]
    if node.type == "merge" and node.config.get("mode") == "first":
        if ACTIVE in statuses:
            return "ready"
        return "skip" if all(s == DEAD for s in statuses) else "wait"
    if PENDING in statuses:
        return "wait"
    if node.type == "merge":
        return "ready" if ACTIVE in statuses else "skip"
    return "ready" if all(s == ACTIVE for s in statuses) else "skip"


def node_done(state: FlowRunState, node_id: str) -> bool:
    st = state.node_states.get(node_id)
    return st in (NodeState.SUCCEEDED, NodeState.SKIPPED) or (
        st == NodeState.FAILED and node_id in state.handled_failures
    )


# ---------------------------------------------------------------------------- control labels


def _descendants(flow: FlowDefinition, start: str) -> set[str]:
    seen = {start}
    stack = [start]
    while stack:
        cur = stack.pop()
        for e in flow.edges:
            if e.source == cur and e.target not in seen:
                seen.add(e.target)
                stack.append(e.target)
    return seen


def branch_scopes(flow: FlowDefinition) -> list[tuple[EdgeDefinition, set[str]]]:
    return [(e, _descendants(flow, e.target)) for e in flow.edges if e.branch is not None]


def runtime_control_label(
    scopes: list[tuple[EdgeDefinition, set[str]]], state: FlowRunState, node_id: str
) -> Label | None:
    parts: list[Label] = []
    for edge, scope in scopes:
        if node_id not in scope:
            continue
        if edge.branch in ("true", "false"):
            parts.append(state.node_output_labels.get(edge.source, {}).get("branch") or Label.untrusted(sources={edge.source}))
        else:
            parts.append(Label.untrusted(sources={edge.source}))
    return Label.join_all(parts, default=Label.trusted()) if parts else None


def upstream_context(flow: FlowDefinition, state: FlowRunState, node_id: str) -> tuple[dict, dict]:
    outs: dict[str, dict[str, Any]] = {}
    lbls: dict[str, dict[str, Label]] = {}
    for anc in flow.ancestors(node_id):
        if state.node_states.get(anc) == NodeState.SUCCEEDED:
            outs[anc] = state.node_outputs.get(anc, {})
            lbls[anc] = state.node_output_labels.get(anc, {})
    return outs, lbls


def _gated(flow: Any, node_id: str) -> bool:
    from agentos.flows.extraction import is_approval_gated

    return is_approval_gated(flow, node_id)


def check_control(
    node_id: str, side_effect: SideEffectClass, control_label: Label | None, *,
    approval_gated: bool = False, policy: Any = None,
) -> None:
    violations = evaluate_control_dependency(
        node_id, side_effect, control_label, [node_id], approval_gated=approval_gated, policy=policy
    )
    if violations:
        raise SinkRuleViolationError(violations[0])


# ---------------------------------------------------------------------------- simple nodes


def run_condition(flow: FlowDefinition, state: FlowRunState, node: NodeDefinition, effective_inbound: Label):
    outs, lbls = upstream_context(flow, state, node.id)
    expr = node.config["expression"]
    result = bool(evaluate(expr, outs))
    pred = label_of(expr, lbls)
    pred = Label(integrity=pred.integrity, confidentiality=pred.confidentiality, sources=pred.sources | {node.id})
    outputs = {"branch": "true" if result else "false", "result": result}
    return outputs, {"branch": pred, "result": pred, "*": effective_inbound.join(pred)}


def run_merge(flow: FlowDefinition, state: FlowRunState, node: NodeDefinition):
    active = [e.source for e in flow.edges if e.target == node.id and edge_status(state, e) == ACTIVE]
    inputs = {src: state.node_outputs.get(src, {}) for src in active}
    lbl = Label.join_all(
        [v for src in active for v in state.node_output_labels.get(src, {}).values()], default=Label.trusted()
    )
    lbl = Label(integrity=lbl.integrity, confidentiality=lbl.confidentiality, sources=lbl.sources | {node.id})
    return {"inputs": inputs, "first": active[0] if active else None}, {"inputs": lbl, "first": lbl, "*": lbl}


def run_error_handler(flow: FlowDefinition, state: FlowRunState, node: NodeDefinition):
    src = next(e.source for e in flow.edges if e.target == node.id)
    info = dict(state.handled_failures.get(src) or {"failed_node": src, "error_type": "unknown", "message": ""})
    lbl = Label.untrusted(sources={src, node.id})  # error text can contain attacker-influenced data
    return info, {k: lbl for k in ("failed_node", "error_type", "message", "*")}


# ---------------------------------------------------------------------------- subflow


async def run_subflow(engine: FlowEngine, state: FlowRunState, node: NodeDefinition, inputs: dict, input_labels: dict):
    depth = engine.subflow_depth + 1
    if depth > engine.max_subflow_depth:
        raise ValueError(f"subflow nesting deeper than {engine.max_subflow_depth}")
    flow_id, version = node.config["flow_id"], int(node.config["version"])
    rec = await engine.storage.flows.get_version(flow_id, version)
    if rec is None:
        raise ValueError(f"subflow {flow_id!r} v{version} is not published")
    child_def = FlowDefinition(
        id=rec.id, name=rec.name, entrypoint=rec.entrypoint, nodes=rec.nodes, edges=rec.edges, loops=rec.loops
    )
    if any(n.type in ("approval", "wait") for n in child_def.nodes.values()):
        raise ValueError("subflows containing approval or wait nodes are not supported yet")
    child = type(engine)(
        flow=child_def, storage=engine.storage, policy=engine.policy, transport_registry=engine.transport_registry,
        custom_llm=engine.custom_llm, track_labels=engine.track_labels, subflow_depth=depth,
        max_subflow_depth=engine.max_subflow_depth, secret_resolver=engine.secret_resolver, clock=engine.clock,
    )
    child_run_id = f"{state.run_id}--{node.id}"
    cstate = await child.run(
        run_id=child_run_id, inputs=inputs, trigger="subflow",
        input_labels={k: v.model_dump(mode="json") for k, v in input_labels.items()},
    )
    if cstate.status != RunStatus.SUCCEEDED:
        raise RuntimeError(f"subflow {flow_id!r} v{version} {cstate.status.value}: {cstate.error}")
    terminals = [n for n in child_def.nodes if not any(e.source == n for e in child_def.edges)]
    out_lbl = Label.join_all(
        [v for t in terminals for v in cstate.node_output_labels.get(t, {}).values()], default=Label.trusted()
    )
    out_lbl = Label(integrity=out_lbl.integrity, confidentiality=out_lbl.confidentiality, sources=out_lbl.sources | {node.id})
    outputs = {"outputs": {t: cstate.node_outputs.get(t, {}) for t in terminals}, "child_run_id": child_run_id}
    return outputs, {"outputs": out_lbl, "child_run_id": Label.trusted(sources={node.id}), "*": out_lbl}


# ---------------------------------------------------------------------------- http_request


def _approved(flow: FlowDefinition, node_id: str, arg: str) -> bool:
    for e in flow.edges:
        if e.target == node_id and arg in e.arg_mapping:
            src = flow.nodes.get(e.source)
            if src and src.type == "approval":
                cfg = src.config.get("approves", {})
                if cfg.get("sink_node") == node_id and arg in cfg.get("args", []):
                    return True
    return False


async def run_http_request(
    engine: FlowEngine, state: FlowRunState, node: NodeDefinition, inputs: dict, input_labels: dict,
    control_label: Label | None,
):
    cfg = node.config
    nid = node.id
    outs, lbls = upstream_context(engine.flow, state, nid)
    trusted = Label.trusted(sources={nid})

    def value(key: str) -> tuple[Any, Label, bool]:
        """(value, label, author_fixed) with precedence pinned > config template > edge input."""
        if key in node.pinned_args:
            return node.pinned_args[key], trusted, True
        cfg_val = cfg.get(key)
        if key in ("url", "body") and isinstance(cfg_val, str):
            refs = references(cfg_val, template=True)
            return render(cfg_val, outs), (label_of(cfg_val, lbls, template=True) if refs else trusted), not refs
        if key in inputs:
            return inputs[key], input_labels.get(key, Label.untrusted(sources={nid})), False
        return None, trusted, False

    url, url_lbl, url_fixed = value("url")
    if not url or not isinstance(url, str):
        raise ValueError(f"http_request {nid!r} has no URL")
    body, body_lbl, body_fixed = value("body")

    query: dict[str, Any] = {}
    q_parts: list[Label] = []
    query_from_data = False
    for k, tpl in (cfg.get("query") or {}).items():
        query[k] = render(tpl, outs)
        if references(tpl, template=True):
            q_parts.append(label_of(tpl, lbls, template=True))
            query_from_data = True
    if isinstance(inputs.get("query"), dict):
        query.update(inputs["query"])
        q_parts.append(input_labels.get("query", Label.untrusted(sources={nid})))
        query_from_data = True
    query_lbl = Label.join_all(q_parts, default=trusted)

    headers: dict[str, str] = {}
    credentials: dict[str, str] = {}
    for k, v in (cfg.get("headers") or {}).items():
        if isinstance(v, dict) and "vault" in v:
            if not url_fixed:
                raise ValueError(f"http_request {nid!r}: vault credential headers require a pinned URL")
            if engine.secret_resolver is None:
                raise ValueError(f"http_request {nid!r}: no secret resolver configured for vault header {k!r}")
            secret = engine.secret_resolver(v["vault"])
            credentials[k] = await secret if inspect.isawaitable(secret) else secret
        else:
            headers[k] = str(v)
    headers_lbl = trusted
    if isinstance(inputs.get("headers"), dict):
        headers.update({k: str(v) for k, v in inputs["headers"].items()})
        headers_lbl = input_labels.get("headers", Label.untrusted(sources={nid}))

    method = str(cfg.get("method") or "GET").upper()
    transport = engine.transport_registry.get("http_request") or HttpRequestTransport(engine.policy.http_allowlist)
    target = check_url(url, engine.policy.http_allowlist, getattr(transport, "resolver", None))
    sink_ctx = {
        "method": method,
        "host": target.host,
        "host_allowlisted": target.allowlisted,
        "query_from_data": query_from_data,
    }
    eff = effective_side_effect("http_request", cfg)
    spec = BUILTIN_NODE_SPECS["http_request"].model_copy(update={"side_effect": eff})
    checks = [("url", url_lbl, url_fixed, url), ("body", body_lbl, body_fixed, body), ("query", query_lbl, False, query),
              ("headers", headers_lbl, False, headers)]
    for arg, lbl, fixed, val in checks:
        if val in (None, "", {}):
            continue
        violations = evaluate_sink_argument_rule(
            node_id=nid, spec=spec, arg_name=arg, rule=spec.sink_rules[arg], arriving_label=lbl,
            effective_inbound_label=lbl, is_pinned=fixed, is_approved=_approved(engine.flow, nid, arg),
            pinned_to_val=None, policy=engine.policy, path=[nid], sink_context=sink_ctx,
            approval_gated=_gated(engine.flow, nid),
        )
        if violations:
            raise SinkRuleViolationError(violations[0])
    from agentos.flows.extraction import is_approval_gated

    check_control(nid, eff, control_label, approval_gated=is_approval_gated(engine.flow, nid), policy=engine.policy)

    call = dict(method=method, url=url, headers=headers, query=query or None, body=body,
                timeout_s=cfg.get("timeout_s") or DEFAULT_TIMEOUT_S, max_bytes=cfg.get("max_bytes") or DEFAULT_MAX_BYTES,
                credential_headers=credentials)
    if eff == SideEffectClass.READ:
        result = await asyncio.to_thread(transport.request, **call)
    else:
        key = state.pending_sink_intents.get(nid) or f"{state.run_id}:{nid}:{state.last_seq + 1}"
        if key in state.committed_sinks:
            result = {"status": "deduplicated", "idempotency_key": key}
        else:
            if nid not in state.pending_sink_intents:
                ev = await engine._append_event(
                    run_id=state.run_id, type="sink_intent",
                    data={"sink_node": nid, "idempotency_key": key,
                          "args": {"method": method, "url": url, "query": query, "body": body, "headers": headers}},
                )
                state.apply_event(ev)
            engine._check_fencing(state.run_id)
            result = await asyncio.to_thread(transport.request, **call)
            ev = await engine._append_event(
                run_id=state.run_id, type="sink_committed",
                data={"sink_node": nid, "idempotency_key": key, "result": {"status": result.get("status")}},
            )
            state.apply_event(ev)
    out = Label.untrusted(sources={nid})  # responses are always untrusted
    return result, {k: out for k in ("status", "headers", "body", "final_url", "truncated", "redirects", "*")}
