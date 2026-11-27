"""4.2: one place that runs a suite (API, CLI and the publish gate all use it).

resolve target -> static check once -> run the cases one by one -> regression against the previous run of the same
flow and model -> store with history.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional

from agentos.flows.models import FlowDefinition
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.flowtests.compare import comparison_row, regression
from agentos.flowtests.models import GateSettings, SuiteRun, counts_of
from agentos.flowtests.models_choice import check_model_enabled, normalize_model
from agentos.flowtests.runner import TestEnv, flow_dict, run_case
from agentos.flowtests.store import FlowTestStore


class FlowTestError(ValueError):
    """A setup problem (flow or version not found, bad model, no cases): HTTP 400/404, CLI exit code 2."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


async def resolve_flow(storage: Any, flow_id: str, target: str = "draft",
                       version: Optional[int] = None) -> tuple[dict[str, Any], str, Optional[int]]:
    if target == "version" or (version is not None and target != "draft"):
        if version is None:
            raise FlowTestError("target 'version' needs a version number")
        rec = await storage.flows.get_version(flow_id, int(version))
        if rec is None:
            raise FlowTestError(f"Flow {flow_id!r} version {version} not found", 404)
        return flow_dict(rec), "version", int(version)
    if target == "published":
        versions = await storage.flows.list_versions(flow_id)
        if not versions:
            raise FlowTestError(f"Flow {flow_id!r} has no published version", 404)
        return flow_dict(versions[-1]), "published", versions[-1].version
    if target != "draft":
        raise FlowTestError(f"unknown target {target!r} (draft, published or version)")
    rec = await storage.flows.get_draft(flow_id)
    if rec is None:
        raise FlowTestError(f"Flow {flow_id!r} draft not found", 404)
    return flow_dict(rec), "draft", None


def static_violations(flow: dict[str, Any], env: TestEnv) -> list[dict[str, Any]]:
    try:
        res = StaticFlowAnalyzer(FlowDefinition(**flow), policy=env.policy, tool_catalog=env.catalog).verify()
    except Exception:
        return []
    return [{"node_id": v.node_id, "target_arg": v.target_arg, "path": list(v.path), "reason": v.reason}
            for v in res.violations]


async def execute_suite(store: FlowTestStore, env: TestEnv, flow_id: str, *, target: str = "draft",
                        version: Optional[int] = None, model: str = "mock", tags: Optional[list[str]] = None,
                        purpose: str = "manual", started_by: Optional[str] = None,
                        comparison_id: Optional[str] = None, flow: Optional[dict[str, Any]] = None,
                        save: bool = True) -> SuiteRun:
    model = normalize_model(model)
    check_model_enabled(model)
    if flow is None:
        flow, target, version = await resolve_flow(env.storage, flow_id, target, version)
    cases = await store.list_cases(flow_id, tags)
    suite = SuiteRun(flow_id=flow_id, target=target, version=version, model=model, tags=list(tags or []),
                     live_tools=env.live_tools, purpose=purpose, started_by=started_by, comparison_id=comparison_id)
    started = time.perf_counter()
    violations = static_violations(flow, env)
    for case in cases:  # one at a time (budgets and run limits apply per run)
        suite.results.append(await run_case(case, flow, env, model, violations=violations, target=target,
                                            version=version))
    suite.duration_ms = round((time.perf_counter() - started) * 1000, 1)
    suite.counts = counts_of(suite.results)
    suite.regression = regression(await store.previous_run(flow_id, model), suite)
    if save:
        await store.save_run(suite)
    return suite


async def compare_models(store: FlowTestStore, env: TestEnv, flow_id: str, models: list[str], *,
                         target: str = "draft", version: Optional[int] = None, tags: Optional[list[str]] = None,
                         started_by: Optional[str] = None) -> dict[str, Any]:
    specs = [normalize_model(m) for m in models]
    if not 2 <= len(specs) <= 4 or len(set(specs)) != len(specs):
        raise FlowTestError("compare needs 2 to 4 different models")
    for m in specs:
        check_model_enabled(m)
    flow, target, version = await resolve_flow(env.storage, flow_id, target, version)
    cid = f"cmp_{uuid.uuid4().hex[:10]}"
    runs = [await execute_suite(store, env, flow_id, target=target, version=version, model=m, tags=tags,
                                purpose="compare", started_by=started_by, comparison_id=cid, flow=flow)
            for m in specs]
    return {"comparison_id": cid, "flow_id": flow_id, "target": target, "version": version,
            "rows": [comparison_row(r) for r in runs], "suite_run_ids": [r.id for r in runs]}


async def gate_check(store: FlowTestStore, env: TestEnv, flow_id: str, flow: dict[str, Any],
                     started_by: Optional[str] = None) -> Optional[dict[str, Any]]:
    """D10: None when the gate is off; else the gate result (``passed`` False refuses publish in block mode)."""
    gate: GateSettings = await store.get_gate(flow_id)
    if gate.mode == "off":
        return None
    cases = await store.list_cases(flow_id)
    if not cases:
        return {"mode": gate.mode, "model": gate.model, "passed": False, "suite_run_id": None,
                "counts": {"total": 0, "pass": 0, "fail": 0, "error": 0}, "failed": [],
                "message": "the publish gate is on but this flow has no test cases"}
    suite = await execute_suite(store, env, flow_id, target="draft", model=gate.model, purpose="gate",
                                started_by=started_by, flow=flow)
    failed = [r.name for r in suite.results if r.status != "pass"]
    return {"mode": gate.mode, "model": gate.model, "passed": not failed, "suite_run_id": suite.id,
            "counts": suite.counts, "failed": failed[:50],
            "message": "all test cases passed" if not failed else f"{len(failed)} of {len(cases)} test cases failed"}


async def version_gate(store: FlowTestStore, env: TestEnv, flow_id: str, version: int,
                       started_by: Optional[str] = None) -> dict[str, Any]:
    """4.3: the promote test gate. Runs the flow's cases against that EXACT published version with the gate model
    (default MOCK, fake transports only). No cases -> not passed."""
    gate: GateSettings = await store.get_gate(flow_id)
    cases = await store.list_cases(flow_id)
    if not cases:
        return {"passed": False, "suite_run_id": None, "counts": {"total": 0, "pass": 0, "fail": 0, "error": 0},
                "model": gate.model, "message": "this flow has no test cases"}
    suite = await execute_suite(store, env, flow_id, target="version", version=version, model=gate.model,
                                purpose="promote", started_by=started_by)
    failed = [r.name for r in suite.results if r.status != "pass"]
    return {"passed": not failed, "suite_run_id": suite.id, "counts": suite.counts, "model": gate.model,
            "failed": failed[:50],
            "message": "all test cases passed" if not failed else f"{len(failed)} of {len(cases)} test cases failed"}
