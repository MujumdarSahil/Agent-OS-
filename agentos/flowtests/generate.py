"""4.2 D11: creating test cases from a run, from the 3.6a review export, and from the 4.1 attack families.

SECRET: a value whose run label is ``secret`` (or a review export's ``[SECRET redacted]``) is never stored as an
expected value, a fixture body or a scripted answer, unless an admin asks for ``include_secrets`` (audited by the
caller). The excluded items are listed in ``notes``.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Optional

from agentos.flows.state import FlowRunState
from agentos.flowtests.models import (
    ApprovalDecision,
    ApprovalExpectation,
    ExtractionExpectation,
    Fixture,
    OutputExpectation,
    SecurityExpectation,
    SinkExpectation,
    StatusExpectation,
    TestCase,
)

REDACTED = "[SECRET redacted]"
SEND_NODES = {"send_email": "to", "send_slack": "channel"}


def _conf(lbl: Any) -> Any:
    if isinstance(lbl, dict):
        return lbl.get("confidentiality")
    c = getattr(lbl, "confidentiality", None)
    return getattr(c, "value", c)


def _is_secret(labels: Optional[dict[str, Any]], key: Optional[str] = None) -> bool:
    return any(_conf(lbl) == "secret" for k, lbl in (labels or {}).items() if key is None or k in (key, "*"))


async def from_run(storage: Any, flow: dict[str, Any], run_id: str, *, include_secrets: bool = False) -> TestCase:
    run = await storage.runs.get(run_id)
    if run is None or (run.flow_id or run.mission_name) != flow["id"]:
        raise ValueError(f"Run {run_id!r} of flow {flow['id']!r} not found")
    events = await storage.events.list(run_id, after_seq=0)
    state = FlowRunState.rebuild_from_events(run_id, events)
    nodes = flow.get("nodes") or {}
    notes: list[str] = []
    started = next((e for e in events if e.type == "run_started"), None)
    payload = (started.data or {}).get("inputs", {}) if started else {}

    fixtures: list[Fixture] = []
    mock: dict[str, str] = {}
    exps: list[Any] = []
    status = state.status.value
    final = "waiting_for_approval" if status == "waiting" else status
    if final in ("succeeded", "waiting_for_approval", "failed"):
        exps.append(StatusExpectation(equals=final))

    for nid, out in (state.node_outputs or {}).items():
        node = nodes.get(nid) or {}
        ntype = node.get("type")
        secret = _is_secret(state.node_output_labels.get(nid))
        if secret and not include_secrets:
            if ntype in ("http_request", "agent", "llm", "quarantined_extraction", "validator"):
                notes.append(f"{nid}: output labelled SECRET, not stored (an admin can include secret values)")
            if ntype == "http_request":
                fixtures.append(Fixture(method=str((node.get("config") or {}).get("method") or "GET").upper(),
                                        url=_http_url(node, state, nid), body="", recorded=False))
            continue
        if ntype == "http_request" and isinstance(out, dict):
            url = _http_url(node, state, nid)
            if url:
                fixtures.append(Fixture(method=str((node.get("config") or {}).get("method") or "GET").upper(),
                                        url=url, status=int(out.get("status") or 200), body=out.get("body", ""),
                                        content_type=str((out.get("headers") or {}).get("content-type")
                                                         or "application/json")))
        elif ntype in ("agent", "llm") and isinstance(out, dict) and isinstance(out.get("output"), str):
            mock[nid] = out["output"]
            exps.append(OutputExpectation(node=nid, field="output", op="equals", value=out["output"]))
        elif ntype in ("quarantined_extraction", "validator") and isinstance(out, dict):
            for k, v in out.items():
                if isinstance(v, (str, bool, int)):
                    exps.append(ExtractionExpectation(node=nid, field=k, equals=v))

    # fetch_url / MCP events hold metadata only (3.3 / 2.5a): placeholder fixtures to fill in
    for e in events:
        d = e.data or {}
        if e.type == "fetch_url" and d.get("host"):
            url = f"https://{d['host']}/*"
            if not any(f.url == url for f in fixtures):
                fixtures.append(Fixture(method="GET", url=url, body="", recorded=False))
        elif e.type == "mcp_tool_call" and d.get("tool_name"):
            if not any(f.tool == d["tool_name"] for f in fixtures):
                fixtures.append(Fixture(kind="mcp", tool=d["tool_name"], body="", recorded=False))
    if any(not f.recorded for f in fixtures):
        notes.append("some fixtures could not be recorded from the run (metadata only): fill in their responses")

    # approvals the operator decided, so the replay continues the same way
    approvals = [ApprovalDecision(node=(e.data or {}).get("node_id"),
                                  approve=(e.data or {}).get("decision") is True
                                  or str((e.data or {}).get("decision")).lower() in ("true", "approve", "approved"))
                 for e in events if e.type == "approval_decision"]
    for e in events:
        nid = (e.data or {}).get("node_id")
        if e.type == "node_waiting" and (nodes.get(nid) or {}).get("type") == "approval":
            exps.append(ApprovalExpectation(node=nid))

    # sinks: each send node called (with its recipients) or not called
    intents = {(e.data or {}).get("idempotency_key"): e.data or {} for e in events if e.type == "sink_intent"}
    committed = [intents.get((e.data or {}).get("idempotency_key")) or {} for e in events if e.type == "sink_committed"]
    for nid, node in nodes.items():
        arg = SEND_NODES.get(node.get("type"))
        if not arg:
            continue
        sent = [c for c in committed if c.get("sink_node") == nid]
        if not sent:
            exps.append(SinkExpectation(target=node["type"], node=nid, op="not_called"))
            continue
        for c in sent:
            dest = (c.get("args") or {}).get(arg) or (node.get("pinned_args") or {}).get(arg)
            if isinstance(dest, str) and dest:
                exps.append(SinkExpectation(target=node["type"], node=nid, op="called_with", arg=arg, value=dest))
            else:
                exps.append(SinkExpectation(target=node["type"], node=nid, op="called"))
    for c in committed:  # agent tool sends (sink_intent with tool_name)
        tool = c.get("tool_name")
        if tool in SEND_NODES:
            dest = (c.get("args") or {}).get(SEND_NODES[tool])
            if isinstance(dest, str):
                exps.append(SinkExpectation(target=tool, node=c.get("sink_node"), op="called_with",
                                            arg=SEND_NODES[tool], value=dest))
    exps.append(SecurityExpectation(op="no_external_send"))

    if _is_secret(state.node_output_labels.get(flow.get("entrypoint"))) and not include_secrets:
        notes.append("the trigger input is labelled SECRET: not stored")
        payload = {}
    return TestCase(flow_id=flow["id"], name=f"From run {run_id}", tags=["from-run"], input=payload,
                    fixtures=fixtures, mock_responses=mock, approvals=approvals, expectations=exps, source="run",
                    secret_values_included=include_secrets, notes=notes)


def _http_url(node: dict[str, Any], state: FlowRunState, nid: str) -> Optional[str]:
    url = (node.get("pinned_args") or {}).get("url") or ((state.node_inputs or {}).get(nid) or {}).get("url")
    out = (state.node_outputs or {}).get(nid) or {}
    return url if isinstance(url, str) and url else (out.get("final_url") if isinstance(out, dict) else None)


async def from_review(review_store: Any, storage: Any, flow: dict[str, Any], *,
                      include_secrets: bool = False) -> list[TestCase]:
    """Each reviewed item of this flow with a corrected output (or a "good" verdict) becomes a case whose expected
    value is that output. The input is the run's trigger payload when the run still exists."""
    from agentos.review.models import ReviewItem
    from agentos.review.store import _redact_value

    cases: list[TestCase] = []
    for d in await review_store.items.list():
        if d.get("status") != "reviewed" or d.get("flow_id") != flow["id"]:
            continue
        it = ReviewItem.model_validate(d)
        expected: Any = it.corrected_output if it.corrected_output not in (None, "") else (
            (it.outputs or {}).get("output", it.output_data) if it.verdict == "good" else None)
        if expected is None:
            continue
        notes: list[str] = []
        exp_value = _redact_value(expected, it.labels, labels_dict=it.output_labels, include_secrets=include_secrets)
        if exp_value == REDACTED or (isinstance(exp_value, str) and REDACTED in exp_value):
            notes.append(f"review item {it.id}: expected value labelled SECRET, not stored")
            continue
        payload: Any = None
        run = await storage.runs.get(it.run_id) if it.run_id else None
        if run is not None:
            started = next((e for e in await storage.events.list(it.run_id, after_seq=0) if e.type == "run_started"),
                           None)
            payload = (started.data or {}).get("inputs") if started else None
        if payload is None:
            payload = _redact_value(it.inputs or it.input_data or {}, it.labels, labels_dict=it.input_labels,
                                    include_secrets=include_secrets)
            notes.append("the original run is gone: the input is the reviewed node's input")
        cases.append(TestCase(flow_id=flow["id"], name=f"Review {it.id} ({it.node_id})", tags=["review"],
                              input=payload, source="review", secret_values_included=include_secrets, notes=notes,
                              expectations=[OutputExpectation(node=it.node_id, field="output", op="equals",
                                                              value=exp_value)]))
    return cases


def security_cases(flow: dict[str, Any]) -> list[TestCase]:
    """One case per 4.1 attack family/variant that fits this flow (MCP families skipped, as in Attack my flow).
    Adversarial MOCK model (it always obeys the injection), every approval approved (worst case), expectation:
    nothing reaches an address outside the internal domains."""
    from agentos.redteam.attacks import generate
    from agentos.redteam.myflow import _benign_input
    from agentos.redteam.runner import inject

    benign = _benign_input(flow)
    fixtures = [Fixture(method=str((n.get("config") or {}).get("method") or "GET").upper(),
                        url=(n.get("pinned_args") or {}).get("url"), body={}, recorded=False)
                for n in (flow.get("nodes") or {}).values()
                if n.get("type") == "http_request" and isinstance((n.get("pinned_args") or {}).get("url"), str)]
    out: list[TestCase] = []
    for a in generate(flow):
        if a.family.startswith("mcp_"):
            continue
        out.append(TestCase(
            flow_id=flow["id"], name=f"Security: {a.id}", tags=["security", a.family], input=inject(flow, benign, a),
            fixtures=fixtures, source="security", attack=dataclasses.asdict(a),
            approvals=[ApprovalDecision(approve=True) for _ in range(5)],
            expectations=[SecurityExpectation(op="no_external_send",
                                              note="the attack does not reach the attacker's destination")]))
    return out
