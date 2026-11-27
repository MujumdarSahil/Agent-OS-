"""4.2 D4/D5/D9: run one test case against a flow version with fake transports only.

The real FlowEngine runs the case (labels, sink rules, the tool proxy, the network guard and run limits all apply)
with trigger "test" in the real storage, so the run opens in the run panel. Only the transports differ: fake
recorders for email/Slack, fixtures for HTTP/fetch_url/MCP (fixtures.py). Test runs never enter the review queue.
"""

from __future__ import annotations

import json
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.state import RunStatus
from agentos.flowtests.expectations import Observation, SinkCall, evaluate, get_path, short, sink_calls_from, _MISSING
from agentos.flowtests.fixtures import TestSinks
from agentos.flowtests.models import CaseResult, Failure, JudgeExpectation, TestCase
from agentos.flowtests.models_choice import CURRENT_NODE, JUDGE_NODE, scripted_model, with_model
from agentos.redteam.runner import SECURITY_ERRORS, norm_dest

MAX_APPROVAL_STEPS = 10
FLOW_KEYS = ("id", "name", "entrypoint", "nodes", "edges", "loops")


class TestFlowEngine(FlowEngine):
    """FlowEngine for test runs: tells the scripted model which node is running; never samples for review."""
    __test__ = False

    async def _execute_single_node(self, state: Any, node_id: str) -> Any:
        token = CURRENT_NODE.set(node_id)
        try:
            return await super()._execute_single_node(state, node_id)
        finally:
            CURRENT_NODE.reset(token)

    async def _maybe_sample_for_review(self, state: Any, status: Any) -> None:
        return None  # test traffic is not production traffic


@dataclass
class TestEnv:
    """What a test run may use. Never the app's transport registry or MCP manager."""
    __test__ = False
    storage: Any
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    catalog: Any = None
    usage: Any = None
    sandbox: Any = None
    secret_resolver: Any = None
    live_tools: bool = False


def flow_dict(rec: Any) -> dict[str, Any]:
    data = rec if isinstance(rec, dict) else rec.model_dump(mode="json")
    out = {k: data.get(k) for k in FLOW_KEYS}
    out["edges"] = out["edges"] or []
    out["loops"] = out["loops"] or {}
    return json.loads(json.dumps(out, default=str))


def _status(state_status: Any) -> str:
    v = getattr(state_status, "value", state_status)
    return "waiting_for_approval" if v == "waiting" else str(v)


async def _approve_steps(engine: FlowEngine, storage: Any, run_id: str, state: Any, case: TestCase) -> Any:
    decisions = list(case.approvals)
    for _ in range(MAX_APPROVAL_STEPS):
        if state.status != RunStatus.WAITING or not decisions:
            break
        waits = [e for e in await storage.events.list(run_id) if e.type == "node_waiting"]
        if not waits:
            break
        node_id = (waits[-1].data or {}).get("node_id")
        idx = next((i for i, d in enumerate(decisions) if d.node in (None, node_id)), None)
        if idx is None:
            break
        d = decisions.pop(idx)
        state = await engine.approve(run_id=run_id, node_id=node_id, decision=True if d.approve else "reject",
                                     actor={"username": "flow-test", "via": "test"})
    return state


def pinned_hosts(fd: FlowDefinition) -> list[str]:
    """Hosts of http_request URLs pinned by the flow author (trusted config, not attacker-chosen)."""
    from agentos.flows.net_guard import url_host

    out = []
    for n in fd.nodes.values():
        url = (n.pinned_args or {}).get("url") if n.type == "http_request" else None
        if isinstance(url, str) and "{" not in url:
            out.append(norm_dest(url_host(url)))
    return out


def observe(events: list[Any], state: Any, sinks: TestSinks, fd: FlowDefinition, duration_ms: float,
            violations: list[dict[str, Any]], mock_calls: int = 0) -> tuple[Observation, list[float], list[str]]:
    node_types = {nid: n.type for nid, n in fd.nodes.items()}
    key_to_node: dict[str, str] = {}
    blocked: list[str] = []
    approvals: list[str] = []
    cost, calls, latencies, models = 0.0, 0, [], []
    from agentos.usage.ledger import calls_in

    for e in events:
        d = e.data or {}
        if e.type == "sink_intent" and d.get("idempotency_key"):
            key_to_node[str(d["idempotency_key"])] = d.get("sink_node")
        nid = d.get("node_id") or d.get("agent_node")
        if e.type in ("tool_call_rejected", "tool_call_blocked") or (
                e.type == "node_failed" and d.get("error_type") in SECURITY_ERRORS):
            blocked.append(nid or "?")
        if e.type == "node_waiting" and node_types.get(nid) == "approval" and nid not in approvals:
            approvals.append(nid)
        if e.type == "llm_call":
            cost += float(d.get("cost_usd") or 0)
            calls += calls_in(d)
            if d.get("latency_ms") is not None:
                latencies.append(float(d["latency_ms"]))
            if d.get("status") == "ok" and d.get("model"):
                models.append(f"{d.get('provider')}/{d.get('model')}")
    sink_rows = sink_calls_from([("send_email", c) for c in sinks.email.sent_calls]
                                + [("send_slack", c) for c in sinks.slack.sent_calls], key_to_node)
    for target, net in (("http_request", sinks.net), ("fetch_url", sinks.fetch)):
        sink_rows += [SinkCall(target, c.get("node"), [norm_dest(c["host"])], "host") for c in net.calls]
    sink_rows += [SinkCall(f"mcp:{c['tool']}", c.get("node"), [c["tool"]], "tool") for c in sinks.mcp.calls]
    obs = Observation(status=_status(state.status), error=state.error, outputs=dict(state.node_outputs),
                      node_types=node_types, sinks=sink_rows, blocked=blocked, approvals=approvals,
                      violations=violations, cost_usd=round(cost, 8), duration_ms=duration_ms,
                      model_calls=calls + mock_calls, known_hosts=pinned_hosts(fd))
    return obs, latencies, sorted(set(models))


async def run_case(case: TestCase, flow: dict[str, Any], env: TestEnv, model: str = "mock", *,
                   violations: Optional[list[dict[str, Any]]] = None) -> CaseResult:
    started = time.perf_counter()
    base = {"case_id": case.id, "name": case.name, "tags": list(case.tags)}
    run_id = f"test_{uuid.uuid4().hex[:12]}"
    try:
        flow_m = with_model(flow, model)
        fd = FlowDefinition(**flow_m)
        policy = env.policy
        llm: Any = None
        if model == "mock":
            if case.attack:
                from agentos.redteam.adversary import adversary
                from agentos.redteam.attacks import Attack

                llm = adversary(flow_m, Attack(**case.attack), policy.allowlists)
            else:
                llm = scripted_model(flow_m, case.mock_responses, policy.allowlists)
        sinks = TestSinks(case.fixtures, list(policy.http_allowlist), live_tools=env.live_tools)
        engine = TestFlowEngine(fd, env.storage, policy=policy, transport_registry=sinks.registry(), custom_llm=llm,
                                mcp_manager=sinks.mcp, usage=env.usage, sandbox=env.sandbox,
                                secret_resolver=env.secret_resolver, usage_source="test")
        state = await engine.run(run_id, inputs=case.input, raise_on_error=False, trigger="test")
        state = await _approve_steps(engine, env.storage, run_id, state, case)
        duration = round((time.perf_counter() - started) * 1000, 2)
        events = await env.storage.events.list(run_id)
        obs, latencies, models = observe(events, state, sinks, fd, duration, violations or [],
                                         mock_calls=int(getattr(llm, "_calls", 0) or 0))
        if llm is not None:
            models = [str(getattr(llm, "model", "mock"))]
    except Exception as err:  # the case could not run at all
        return CaseResult(**base, status="error", run_id=run_id, error=f"{type(err).__name__}: {short(str(err), 400)}",
                          duration_ms=round((time.perf_counter() - started) * 1000, 2))

    failures: list[Failure] = [Failure(expectation={"kind": "fixture"}, expected="a fixture", actual="none",
                                       message=m) for m in sinks.misses]
    nondet = False
    for exp in case.expectations:
        if isinstance(exp, JudgeExpectation):
            nondet = True
            f, jcost, jcalls = await judge(exp, obs, env, model, flow_m, case)
            obs.cost_usd = round(obs.cost_usd + jcost, 8)
            obs.model_calls += jcalls
            if f is not None:
                failures.append(f)
            continue
        f = evaluate(exp, obs, env.policy)
        if f is not None:
            failures.append(f)
    return CaseResult(**base, status="fail" if failures else "pass", failures=failures, run_id=run_id,
                      run_status=obs.status, cost_usd=obs.cost_usd, duration_ms=obs.duration_ms,
                      model_calls=obs.model_calls, latencies_ms=latencies, models_used=models, nondeterministic=nondet)


async def judge(exp: JudgeExpectation, obs: Observation, env: TestEnv, model: str, flow: dict[str, Any],
                case: TestCase) -> tuple[Optional[Failure], float, int]:
    """D9: grade one node output with a quarantined extraction (verdict pass/fail + one reason from a fixed list).
    Runs in a temporary storage (no extra run in the run list); real model calls still go through the router,
    budgets and the usage ledger (tagged test, on this flow)."""
    from agentos.storage import open_storage
    from agentos.usage.ledger import calls_in

    def fail(actual: Any, message: str) -> Failure:
        return Failure(expectation=exp.model_dump(mode="json"), expected="pass", actual=actual,
                       message=f"judge (non-deterministic): {message}")

    out = obs.outputs.get(exp.node)
    value = get_path(out, exp.field) if out is not None else _MISSING
    if value is _MISSING:
        return fail(None, f"{exp.node}.{exp.field} has no output to grade"), 0.0, 0
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    cfg: dict[str, Any] = {"input": "text", "rubric": exp.rubric,
                           "fields": [{"name": "verdict", "type": "enum", "values": ["pass", "fail"]},
                                      {"name": "reason", "type": "enum", "values": list(exp.reasons)}]}
    if model not in ("mock", "router"):
        cfg["model"] = model
    jflow = {"id": flow["id"], "name": "judge", "entrypoint": "judge", "edges": [], "loops": {},
             "nodes": {"judge": {"id": "judge", "type": "quarantined_extraction", "config": cfg, "pinned_args": {}}}}
    llm: Any = None
    if model == "mock":
        scripted = case.mock_responses.get(JUDGE_NODE)
        verdict = json.loads(scripted) if scripted else {"verdict": "pass", "reason": exp.reasons[0]}
        llm = scripted_model(jflow, {}, env.policy.allowlists, judge=verdict)
    with tempfile.TemporaryDirectory(prefix="agentos-judge-", ignore_cleanup_errors=True) as td:
        proj = Path(td) / "p"
        proj.mkdir()
        (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
        storage = await open_storage(str(proj), backend="file", vault_path=str(Path(td) / "vault.json"))
        try:
            engine = TestFlowEngine(FlowDefinition(**jflow), storage, policy=env.policy, custom_llm=llm,
                                    usage=env.usage, usage_source="test", transport_registry={})
            rid = f"judge_{uuid.uuid4().hex[:10]}"
            state = await engine.run(rid, inputs={"text": text}, raise_on_error=False, trigger="test")
            events = await storage.events.list(rid)
        finally:
            await storage.close()
    cost = sum(float((e.data or {}).get("cost_usd") or 0) for e in events if e.type == "llm_call")
    calls = sum(calls_in(e.data or {}) for e in events if e.type == "llm_call") + (1 if llm is not None else 0)
    res = (state.node_outputs or {}).get("judge") or {}
    if state.status != RunStatus.SUCCEEDED or "verdict" not in res:
        return fail("no grade", f"the judge model gave no valid grade ({short(state.error, 160)})"), cost, calls
    if res["verdict"] != "pass":
        return fail(f"fail ({res.get('reason')})", f"graded fail, reason: {res.get('reason')}"), cost, calls
    return None, cost, calls
