"""4.2 flow test cases API (design: docs/evidence/4.2.md D10-D12).

Every route is in agentos_server/permissions_table.py: viewers read cases and results; builders/admins create, edit,
run, compare and set the gate; the admin-only options (live tools, include secret values) are checked here and
audited. Test runs never cause real side effects (fake recording sinks, fixture HTTP/MCP; agentos/flowtests).
Audit details are ids and counts only, never inputs, expected values or fixtures.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentos.access.permissions import allows
from agentos.flows.policy import SecurityPolicy
from agentos.flowtests import (
    FlowTestError,
    GateSettings,
    TestCase,
    TestEnv,
    compare_models,
    execute_suite,
    flowtests_store_for,
    resolve_flow,
)
from agentos.flowtests.models_choice import InvalidModelChoice
from agentos_server.audit_support import audit

router = APIRouter(prefix="/flows", tags=["v2-flow-tests"])
summary_router = APIRouter(prefix="/flow-tests", tags=["v2-flow-tests"])


class RunSuiteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = "draft"
    version: Optional[int] = None
    model: str = "mock"
    tags: List[str] = Field(default_factory=list)
    live_tools: bool = False


class CompareBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    models: List[str]
    target: str = "draft"
    version: Optional[int] = None
    tags: List[str] = Field(default_factory=list)


class FromRunBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    include_secret_values: bool = False


class FromReviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    include_secret_values: bool = False


class GateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str = "off"
    model: str = "mock"


# ---------------------------------------------------------------------------- helpers

def _store(request: Request) -> Any:
    return flowtests_store_for(request.app.state.storage)


def _principal(request: Request) -> Any:
    return getattr(request.state, "principal", None)


def _who(request: Request) -> Optional[str]:
    p = _principal(request)
    return (p.username or p.actor) if p is not None else None


async def _require_admin(request: Request, option: str, flow_id: str) -> None:
    p = _principal(request)
    if p is None or not allows(p.role, "admin"):
        await audit(request, f"flow_tests.{option}", "flow", flow_id, outcome="refused",
                    details={"reason": "admin_only"})
        raise HTTPException(status_code=403, detail=f"Only an admin can use the {option.replace('_', ' ')} option")


async def test_env(request: Request, live_tools: bool = False) -> TestEnv:
    from agentos.flows.tool_catalog import ToolCatalog

    state = request.app.state
    storage = state.storage
    repo = getattr(storage, "mcp_servers", None)
    vault = getattr(state, "vault", None)
    return TestEnv(storage=storage, policy=getattr(state, "security_policy", None) or SecurityPolicy(),
                   catalog=ToolCatalog(await repo.list() if repo is not None else []),
                   usage=getattr(state, "usage", None), sandbox=getattr(state, "sandbox", None),
                   secret_resolver=vault.reveal if vault is not None else None, live_tools=live_tools)


test_env.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


async def _flow(request: Request, flow_id: str) -> Dict[str, Any]:
    storage = request.app.state.storage
    for target in ("draft", "published"):
        try:
            flow, _, _ = await resolve_flow(storage, flow_id, target)
            return flow
        except FlowTestError:
            continue
    raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")


def _http(err: Exception) -> HTTPException:
    if isinstance(err, FlowTestError):
        return HTTPException(status_code=err.status, detail=str(err))
    return HTTPException(status_code=400, detail=str(err))


def check_case(case: TestCase, flow: Dict[str, Any], policy: SecurityPolicy) -> None:
    """Expectations must point at nodes of the flow; extraction/validator values must be allowed values (D3)."""
    from agentos.flows import extraction as ex

    nodes = flow.get("nodes") or {}
    for e in case.expectations:
        node_id = getattr(e, "node", None)
        if node_id and node_id not in nodes:
            raise HTTPException(status_code=400, detail=f"expectation {e.kind}: node {node_id!r} is not in the flow")
        if e.kind != "extraction":
            continue
        node = nodes[e.node]
        cfg = node.get("config") or {}
        if node.get("type") == "quarantined_extraction":
            field = next((f for f in cfg.get("fields") or [] if f.get("name") == e.field), None)
        elif node.get("type") == "validator":
            field = ex.validator_field(cfg) if e.field in ex.validator_output_keys(cfg) else None
        else:
            raise HTTPException(status_code=400, detail=f"{e.node!r} is not an extraction or validator node")
        if field is None:
            raise HTTPException(status_code=400, detail=f"{e.node!r} has no field {e.field!r}")
        try:
            ex.validate_value(field, e.equals, policy.allowlists, bool_strings=True)
        except ex.ExtractionRejected:
            raise HTTPException(status_code=400,
                                detail=f"{e.node}.{e.field}: {e.equals!r} is not one of the field's allowed values")


async def _save_case(request: Request, flow_id: str, body: Dict[str, Any], case_id: Optional[str] = None) -> TestCase:
    store = _store(request)
    existing = await store.get_case(case_id) if case_id else None
    if case_id and (existing is None or existing.flow_id != flow_id):
        raise HTTPException(status_code=404, detail=f"Test case {case_id!r} not found")
    data = {k: v for k, v in body.items() if k not in ("created_at", "updated_at", "last_result")}
    data["flow_id"] = flow_id
    if existing is not None:
        data["id"] = existing.id
        data["created_at"] = existing.created_at
        data["created_by"] = existing.created_by
    else:
        data.setdefault("created_by", _who(request))
    try:
        case = TestCase.model_validate(data)
    except ValidationError as err:
        raise HTTPException(status_code=422, detail=err.errors(include_url=False, include_context=False))
    flow = await _flow(request, flow_id)
    check_case(case, flow, getattr(request.app.state, "security_policy", None) or SecurityPolicy())
    if case.secret_values_included and not (existing is not None and existing.secret_values_included):
        await _require_admin(request, "secret_values", flow_id)
        await audit(request, "flow_tests.secret_values", "flow", flow_id, details={"case_id": case.id})
    await audit(request, "flow_tests.case", "flow", flow_id, details={
        "case_id": case.id, "action": "update" if existing else "create", "expectations": len(case.expectations),
        "fixtures": len(case.fixtures), "source": case.source})
    return await store.put_case(case)


def _last_results(runs: List[Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for run in runs:  # newest first
        for r in run.results:
            out.setdefault(r.case_id, {"status": r.status, "suite_run_id": run.id, "at": run.started_at,
                                       "model": run.model})
    return out


# ---------------------------------------------------------------------------- summary (flow cards)

@summary_router.get("/summary")
async def flow_tests_summary(request: Request) -> Dict[str, Any]:
    return await _store(request).summary()


# ---------------------------------------------------------------------------- cases

@router.get("/{flow_id}/tests")
async def list_cases(flow_id: str, request: Request) -> Dict[str, Any]:
    store = _store(request)
    cases = await store.list_cases(flow_id)
    last = _last_results(await store.list_runs(flow_id))
    gate = await store.get_gate(flow_id)
    return {"cases": [{**c.model_dump(mode="json"), "last_result": last.get(c.id)} for c in cases],
            "gate": gate.model_dump(mode="json")}


@router.post("/{flow_id}/tests", status_code=201)
async def create_case(flow_id: str, body: Dict[str, Any], request: Request) -> Dict[str, Any]:
    body = {k: v for k, v in body.items() if k != "id"}
    return (await _save_case(request, flow_id, body)).model_dump(mode="json")


@router.post("/{flow_id}/tests/from-run")
async def case_from_run(flow_id: str, body: FromRunBody, request: Request) -> Dict[str, Any]:
    """A suggested case (not saved): the user edits it before saving."""
    from agentos.flowtests.generate import from_run

    if body.include_secret_values:
        await _require_admin(request, "secret_values", flow_id)
        await audit(request, "flow_tests.secret_values", "flow", flow_id, details={"from": "run"})
    flow = await _flow(request, flow_id)
    try:
        case = await from_run(request.app.state.storage, flow, body.run_id, include_secrets=body.include_secret_values)
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))
    case.created_by = _who(request)
    return case.model_dump(mode="json")


@router.post("/{flow_id}/tests/from-review")
async def cases_from_review(flow_id: str, body: FromReviewBody, request: Request) -> Dict[str, Any]:
    """Import every reviewed item of this flow (3.6a) with a corrected output: saved, tagged "review"."""
    from agentos.flowtests.generate import from_review
    from agentos.review.store import review_store_for

    if body.include_secret_values:
        await _require_admin(request, "secret_values", flow_id)
        await audit(request, "flow_tests.secret_values", "flow", flow_id, details={"from": "review"})
    storage = request.app.state.storage
    review = getattr(request.app.state, "review", None) or review_store_for(storage)
    flow = await _flow(request, flow_id)
    cases = await from_review(review, storage, flow, include_secrets=body.include_secret_values)
    store = _store(request)
    await audit(request, "flow_tests.case", "flow", flow_id, details={"action": "import_review", "count": len(cases)})
    saved = [await store.put_case(c.model_copy(update={"created_by": _who(request)})) for c in cases]
    return {"imported": len(saved), "cases": [c.model_dump(mode="json") for c in saved]}


@router.post("/{flow_id}/tests/security")
async def generate_security_cases(flow_id: str, request: Request) -> Dict[str, Any]:
    """Cases from the 4.1 attack families that fit this flow (expect: the attack does not succeed). Saved; an
    earlier generated case with the same attack is replaced."""
    from agentos.flowtests.generate import security_cases

    flow = await _flow(request, flow_id)
    store = _store(request)
    existing = {c.name: c for c in await store.list_cases(flow_id) if c.source == "security"}
    cases = security_cases(flow)
    await audit(request, "flow_tests.case", "flow", flow_id, details={"action": "generate_security", "count": len(cases)})
    saved = []
    for c in cases:
        old = existing.get(c.name)
        if old is not None:
            c = c.model_copy(update={"id": old.id, "created_at": old.created_at})
        saved.append(await store.put_case(c.model_copy(update={"created_by": _who(request)})))
    return {"generated": len(saved), "families": sorted({c.attack["family"] for c in saved if c.attack}),
            "cases": [c.model_dump(mode="json") for c in saved]}


# ---------------------------------------------------------------------------- running, history, comparison

@router.post("/{flow_id}/tests/run")
async def run_suite(flow_id: str, body: RunSuiteBody, request: Request) -> Dict[str, Any]:
    if body.live_tools:
        await _require_admin(request, "live_tools", flow_id)
        await audit(request, "flow_tests.live_tools", "flow", flow_id, details={"enabled": True})
    store = _store(request)
    try:
        suite = await execute_suite(store, await test_env(request, live_tools=body.live_tools), flow_id,
                                    target=body.target, version=body.version, model=body.model, tags=body.tags,
                                    started_by=_who(request))
    except (FlowTestError, InvalidModelChoice) as err:
        raise _http(err)
    await audit(request, "flow_tests.run", "flow", flow_id, details={
        "suite_run_id": suite.id, "target": suite.target, "version": suite.version, "model": suite.model,
        **suite.counts, "live_tools": suite.live_tools})
    return suite.model_dump(mode="json")


@router.post("/{flow_id}/tests/compare")
async def compare(flow_id: str, body: CompareBody, request: Request) -> Dict[str, Any]:
    try:
        res = await compare_models(_store(request), await test_env(request), flow_id, body.models,
                                   target=body.target, version=body.version, tags=body.tags,
                                   started_by=_who(request))
    except (FlowTestError, InvalidModelChoice) as err:
        raise _http(err)
    await audit(request, "flow_tests.run", "flow", flow_id, details={
        "comparison_id": res["comparison_id"], "models": len(res["rows"]),
        "total": sum(r["counts"].get("total", 0) for r in res["rows"]),
        "pass": sum(r["counts"].get("pass", 0) for r in res["rows"])})
    return res


@router.get("/{flow_id}/tests/runs")
async def list_suite_runs(flow_id: str, request: Request) -> List[Dict[str, Any]]:
    return [r.model_dump(mode="json") for r in await _store(request).list_runs(flow_id)]


@router.get("/{flow_id}/tests/runs/{suite_run_id}")
async def get_suite_run(flow_id: str, suite_run_id: str, request: Request) -> Dict[str, Any]:
    run = await _store(request).get_run(suite_run_id)
    if run is None or run.flow_id != flow_id:
        raise HTTPException(status_code=404, detail=f"Suite run {suite_run_id!r} not found")
    return run.model_dump(mode="json")


# ---------------------------------------------------------------------------- publish gate

@router.get("/{flow_id}/tests/settings")
async def get_gate(flow_id: str, request: Request) -> Dict[str, Any]:
    return (await _store(request).get_gate(flow_id)).model_dump(mode="json")


@router.put("/{flow_id}/tests/settings")
async def put_gate(flow_id: str, body: GateBody, request: Request) -> Dict[str, Any]:
    from agentos.flowtests.models_choice import check_model_enabled, normalize_model

    store = _store(request)
    before = await store.get_gate(flow_id)
    try:
        model = normalize_model(body.model)
        check_model_enabled(model)
        gate = GateSettings(flow_id=flow_id, mode=body.mode, model=model, updated_by=_who(request))
    except (InvalidModelChoice, ValidationError) as err:
        raise HTTPException(status_code=400, detail=str(err))
    await audit(request, "flow_tests.gate", "flow", flow_id, details={
        "mode": gate.mode, "model": gate.model, "previous_mode": before.mode})
    return (await store.put_gate(gate)).model_dump(mode="json")


# ---------------------------------------------------------------------------- one case (after the fixed paths)

@router.get("/{flow_id}/tests/{case_id}")
async def get_case(flow_id: str, case_id: str, request: Request) -> Dict[str, Any]:
    case = await _store(request).get_case(case_id)
    if case is None or case.flow_id != flow_id:
        raise HTTPException(status_code=404, detail=f"Test case {case_id!r} not found")
    return case.model_dump(mode="json")


@router.put("/{flow_id}/tests/{case_id}")
async def update_case(flow_id: str, case_id: str, body: Dict[str, Any], request: Request) -> Dict[str, Any]:
    return (await _save_case(request, flow_id, body, case_id)).model_dump(mode="json")


@router.delete("/{flow_id}/tests/{case_id}")
async def delete_case(flow_id: str, case_id: str, request: Request) -> Dict[str, bool]:
    store = _store(request)
    case = await store.get_case(case_id)
    if case is None or case.flow_id != flow_id:
        raise HTTPException(status_code=404, detail=f"Test case {case_id!r} not found")
    await audit(request, "flow_tests.case", "flow", flow_id, details={"case_id": case_id, "action": "delete"})
    return {"deleted": await store.delete_case(case_id)}
