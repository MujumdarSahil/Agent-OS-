"""
Flow management and run endpoints (/api/v2/flows).
CRUD, publish gate, version history, execution enqueue, events stream/poll, and approval.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition, InvalidFlowConfigError
from agentos.flows.policy import SecurityPolicy
from agentos.flows.state import RunStatus
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.storage.models import EventRecord, FlowRecord, RunRecord
from agentos.storage.ports import FencingTokenError
from agentos_server.audit_support import actor_of, audit, audit_best_effort, source_of

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/flows", tags=["v2-flows"])


class RunFlowRequest(BaseModel):
    inputs: Dict[str, Any] = Field(default_factory=dict)
    version: Optional[int] = None


class ApprovalRequestBody(BaseModel):
    node_id: str
    decision: Any = True  # bool or "reject"/"approve"
    # 4.1b: the second, explicit click for a card with look-alike / non-ASCII destinations
    confirm_lookalike: bool = False


# ---------------------------------------------------------------------------
# Flow CRUD & Publish & Versions
# ---------------------------------------------------------------------------

def _who(request: Request) -> Optional[Dict[str, Any]]:
    """3.4: the caller as recorded in run events and on published versions ({user_id, username})."""
    p = getattr(request.state, "principal", None)
    if p is None:
        return None
    return {"user_id": p.actor_id, "username": p.username or p.actor, "via": p.kind}


def _publish_digest(flow: FlowRecord) -> Optional[str]:
    """The content_sha256 that publishing this record would store (same computation as publish_flow)."""
    try:
        fd = FlowDefinition(id=flow.id, name=flow.name, entrypoint=flow.entrypoint, nodes=flow.nodes,
                            edges=flow.edges, loops=flow.loops)
    except Exception:
        return None
    return hashlib.sha256(json.dumps(fd.model_dump(mode="json"), sort_keys=True).encode("utf-8")).hexdigest()


async def _with_publish_view(storage: Any, flow: FlowRecord) -> FlowRecord:
    """3.4 Part 0c: add published_version / unpublished_changes so the UI shows "published vN" or "draft"."""
    versions = await storage.flows.list_versions(flow.id)
    latest = versions[-1] if versions else None
    if latest is None:
        return flow.model_copy(update={"published_version": None, "unpublished_changes": True})
    if flow.status == "published" and flow.version == latest.version:
        changed = False
    else:
        changed = _publish_digest(flow) != latest.content_sha256
    return flow.model_copy(update={"published_version": latest.version, "unpublished_changes": changed})


@router.get("", response_model=List[FlowRecord])
async def list_flows(request: Request) -> List[FlowRecord]:
    storage = request.app.state.storage
    return [await _with_publish_view(storage, f) for f in await storage.flows.list_flows()]


@router.post("", response_model=FlowRecord, status_code=201)
async def create_flow(flow: FlowRecord, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    existing = await storage.flows.get_draft(flow.id)
    if existing is not None:
        raise HTTPException(status_code=400, detail=f"Flow {flow.id!r} draft already exists; use PUT to update")
    await _save_draft_audited(request, flow, created=True)
    return (await storage.flows.get_draft(flow.id)) or flow


def _flow_digest(flow: FlowRecord) -> str:
    body = {"entrypoint": flow.entrypoint, "nodes": flow.nodes, "edges": flow.edges, "loops": flow.loops}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()


async def _save_draft_audited(request: Request, flow: FlowRecord, created: bool) -> None:
    """3.1: validate (no side effect) -> audit flow.save (refused or ok; 503 if the entry cannot be written)
    -> apply. Details: counts and the content sha256 only (never node configs or prompts)."""
    storage = request.app.state.storage
    # response-only / server-set fields are never taken from the client
    flow = flow.model_copy(update={"published_version": None, "unpublished_changes": None, "published_by": None,
                                   "test_gate": None})
    details = {"created": created, "nodes": len(flow.nodes or {}), "edges": len(flow.edges or []),
               "content_sha256": _flow_digest(flow)}
    try:
        _check_node_models(flow.nodes)
        FlowDefinition(id=flow.id, name=flow.name, entrypoint=flow.entrypoint, nodes=flow.nodes, edges=flow.edges,
                       loops=flow.loops)
    except HTTPException as err:
        await audit(request, "flow.save", "flow", flow.id, outcome="refused", details={**details, "reason": "model"})
        raise err
    except (InvalidFlowConfigError, ValueError) as err:
        await audit(request, "flow.save", "flow", flow.id, outcome="refused",
                    details={**details, "reason": "invalid_definition"})
        raise HTTPException(status_code=400, detail=str(err))
    await audit(request, "flow.save", "flow", flow.id, details=details)
    try:
        await storage.flows.put_draft(flow)
    except (InvalidFlowConfigError, ValueError) as err:
        await audit_best_effort(request.app, "flow.save", "flow", flow.id, outcome="failed", details=details,
                                actor=actor_of(request), source=source_of(request))
        raise HTTPException(status_code=400, detail=str(err))


@router.get("/{flow_id}", response_model=FlowRecord)
async def get_flow(flow_id: str, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    draft = await storage.flows.get_draft(flow_id)
    if draft is not None:
        return await _with_publish_view(storage, draft)
    versions = await storage.flows.list_versions(flow_id)
    if versions:
        return await _with_publish_view(storage, versions[-1])
    raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")


@router.put("/{flow_id}", response_model=FlowRecord)
async def put_flow(flow_id: str, flow: FlowRecord, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    if flow.id != flow_id:
        raise HTTPException(status_code=400, detail=f"Path flow_id {flow_id!r} does not match body id {flow.id!r}")
    await _save_draft_audited(request, flow, created=False)
    saved = await storage.flows.get_draft(flow_id)
    if saved is None:
        raise HTTPException(status_code=500, detail="Failed to save flow draft")
    return await _with_publish_view(storage, saved)


@router.delete("/{flow_id}")
async def delete_flow(flow_id: str, request: Request) -> Dict[str, bool]:
    """Requirement 7: Deletion guard — published versions cannot be deleted (returns 409)."""
    storage = request.app.state.storage
    versions = await storage.flows.list_versions(flow_id)
    if versions:
        await audit(request, "flow.delete", "flow", flow_id, outcome="refused",
                    details={"reason": "published_versions_exist", "versions": len(versions)})
        raise HTTPException(
            status_code=409,
            detail="Cannot delete flow with published versions; use archive instead",
        )
    if await storage.flows.get_draft(flow_id) is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")
    await audit(request, "flow.delete", "flow", flow_id)
    try:
        deleted = await storage.flows.delete_flow(flow_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")
        return {"deleted": True}
    except ValueError as err:
        raise HTTPException(status_code=409, detail=str(err))


@router.post("/{flow_id}/archive", response_model=FlowRecord)
async def archive_flow(flow_id: str, request: Request) -> FlowRecord:
    """Explicit archive endpoint."""
    storage = request.app.state.storage
    if not await storage.flows.list_versions(flow_id) and await storage.flows.get_draft(flow_id) is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")
    await audit(request, "flow.archive", "flow", flow_id)
    try:
        return await storage.flows.archive_flow(flow_id)
    except ValueError as err:
        await audit_best_effort(request.app, "flow.archive", "flow", flow_id, outcome="failed",
                                actor=actor_of(request), source=source_of(request))
        raise HTTPException(status_code=404, detail=str(err))


@router.post("/{flow_id}/publish", response_model=FlowRecord, status_code=200)
async def publish_flow(flow_id: str, request: Request) -> FlowRecord:
    """
    Requirement 2 & 4: Publish gate with StaticFlowAnalyzer + atomic version allocation.
    Stores content_sha256 and policy_hash with the immutable published version.
    """
    storage = request.app.state.storage
    draft = await storage.flows.get_draft(flow_id)
    if draft is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} draft not found")

    try:
        flow_def = FlowDefinition(
            id=draft.id,
            name=draft.name,
            entrypoint=draft.entrypoint,
            nodes=draft.nodes,
            edges=draft.edges,
            loops=draft.loops,
        )
    except Exception as err:
        from agentos.telemetry import record_refused_publish
        record_refused_publish()
        await audit(request, "flow.publish", "flow", flow_id, outcome="refused",
                    details={"reason": "structural_validation_failed"})
        raise HTTPException(status_code=400, detail=f"Flow structural validation failed: {err}")

    # 2.3: per-node model choice limited to enabled providers
    try:
        _check_node_models(draft.nodes)
    except HTTPException:
        from agentos.telemetry import record_refused_publish
        record_refused_publish()
        await audit(request, "flow.publish", "flow", flow_id, outcome="refused", details={"reason": "model"})
        raise

    # 2.3: resolve subflow summaries (exact published versions), with cycle and depth checks
    summaries = await _resolve_subflow_summaries(storage, flow_def)

    # Run publish gate verification
    policy = getattr(request.app.state, "security_policy", None) or SecurityPolicy()
    # 2.5a: same tool lookup as the runtime proxy (built-ins + approved MCP tools); unreviewed or changed
    # MCP tools refuse publish, and the summary records the hashes of the MCP tools this version uses.
    from agentos.flows.tool_catalog import ToolCatalog

    mcp_repo = getattr(storage, "mcp_servers", None)
    catalog = ToolCatalog(await mcp_repo.list() if mcp_repo is not None else [])
    analyzer = StaticFlowAnalyzer(flow=flow_def, policy=policy, subflow_summaries=summaries, tool_catalog=catalog)
    res = analyzer.verify()
    if not res.is_valid:
        from agentos.telemetry import record_refused_publish
        record_refused_publish()
        # 3.1: the refusal is audited with the violated rule names (node.argument), not the payload
        rules = sorted({f"{v.node_id}.{v.target_arg}" for v in res.violations})
        await audit(request, "flow.publish", "flow", flow_id, outcome="refused",
                    details={"violated_rules": rules[:50], "violations": len(res.violations)})
        notify = getattr(request.app.state, "notify", None)  # 3.3: "attack blocked" alert (metadata only)
        if notify is not None:
            await notify.on_publish_refused(flow_id, len(res.violations))
        violations_payload = [
            {
                "node_id": v.node_id,
                "target_arg": v.target_arg,
                "path": v.path,
                "reason": v.reason,
            }
            for v in res.violations
        ]
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Publish refused: security violations found",
                "violations": violations_payload,
            },
        )

    # 4.2: "require tests to pass" (per flow, default off). Runs after the static check, against the draft, with the
    # flow's gate model (default MOCK) and fake transports only. block: any failing case (or no case) refuses.
    gate = await _test_gate(request, flow_id, draft)
    if gate is not None and not gate["passed"] and gate["mode"] == "block":
        from agentos.telemetry import record_refused_publish
        record_refused_publish()
        await audit(request, "flow.publish", "flow", flow_id, outcome="refused", details={
            "reason": "tests_failed", "suite_run_id": gate["suite_run_id"], **gate["counts"]})
        raise HTTPException(status_code=400, detail={"error": "Publish refused: tests failed", "test_gate": gate})

    # Compute content_sha256 and policy_hash
    content_bytes = json.dumps(flow_def.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    policy_bytes = json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()

    # 3.1: audit before applying (fail closed: 503 and no new version if the entry cannot be written)
    await audit(request, "flow.publish", "flow", flow_id, details={
        "content_sha256": content_sha256, "policy_hash": policy_hash,
        "expected_version": len(await storage.flows.list_versions(flow_id)) + 1,
    })
    # Atomically assign version and persist published flow
    published = await storage.flows.publish(
        flow_id=flow_id,
        content_sha256=content_sha256,
        policy_hash=policy_hash,
        analysis=analyzer.summary(),
        published_by=(_who(request) or {}).get("user_id"),
    )
    view = await _with_publish_view(storage, published)
    return view.model_copy(update={"test_gate": gate}) if gate is not None else view


async def _test_gate(request: Request, flow_id: str, draft: FlowRecord) -> Optional[Dict[str, Any]]:
    from agentos.flowtests import flowtests_store_for, gate_check
    from agentos.flowtests.runner import flow_dict
    from agentos_server.routes_v2.flow_tests import test_env

    store = flowtests_store_for(request.app.state.storage)
    p = getattr(request.state, "principal", None)
    return await gate_check(store, await test_env(request), flow_id, flow_dict(draft),
                            started_by=(p.username or p.actor) if p is not None else None)


MAX_SUBFLOW_DEPTH = 5


def _check_node_models(nodes: Dict[str, Any]) -> None:
    """Reject a per-node `model` (llm/agent) that is not served by an enabled provider."""
    from agentos.llm.provider_registry import enabled_model_ids
    from agentos.llm.router_factory import get_fallback_policy_cache

    allowed: Optional[set] = None
    for nid, node in (nodes or {}).items():
        node_dict = node if isinstance(node, dict) else node.model_dump()
        model = (node_dict.get("config") or {}).get("model")
        if node_dict.get("type") not in ("llm", "agent") or not model:
            continue
        if allowed is None:
            allowed = enabled_model_ids(get_fallback_policy_cache())
        if model not in allowed:
            raise HTTPException(
                status_code=400,
                detail=f"Node {nid!r}: model {model!r} is not provided by an enabled provider",
            )


async def _resolve_subflow_summaries(storage: Any, flow_def: FlowDefinition) -> Dict[Any, Any]:
    """Load published analysis summaries of referenced subflows; detect cycles and deep nesting."""
    summaries: Dict[Any, Any] = {}

    async def visit(refs: List[tuple], stack: List[tuple], depth: int) -> None:
        for key in refs:
            if key in stack or key[0] == flow_def.id:
                chain = " -> ".join(f"{k[0]}@v{k[1]}" for k in stack + [key])
                raise HTTPException(status_code=400, detail=f"Subflow cycle detected: {flow_def.id} -> {chain}")
            if depth > MAX_SUBFLOW_DEPTH:
                raise HTTPException(status_code=400, detail=f"Subflow nesting deeper than {MAX_SUBFLOW_DEPTH}")
            rec = await storage.flows.get_version(key[0], key[1])
            if rec is None:
                raise HTTPException(status_code=400, detail=f"Subflow {key[0]!r} v{key[1]} is not published")
            summaries[key] = rec.analysis  # None for versions published before 2.3 -> treated as unknown
            child_refs = [
                (n["config"]["flow_id"], int(n["config"]["version"]))
                for n in (rec.nodes or {}).values()
                if isinstance(n, dict) and n.get("type") == "subflow"
            ]
            await visit(child_refs, stack + [key], depth + 1)

    top = [
        (n.config["flow_id"], int(n.config["version"])) for n in flow_def.nodes.values() if n.type == "subflow"
    ]
    await visit(top, [], 1)
    return summaries


@router.get("/{flow_id}/versions", response_model=List[FlowRecord])
async def list_flow_versions(flow_id: str, request: Request) -> List[FlowRecord]:
    storage = request.app.state.storage
    return await storage.flows.list_versions(flow_id)


@router.get("/{flow_id}/versions/{version}", response_model=FlowRecord)
async def get_flow_version(flow_id: str, version: int, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    rec = await storage.flows.get_version(flow_id, version)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} version {version} not found")
    return rec


# ---------------------------------------------------------------------------
# Flow Runs, Events Stream/Poll & Approval
# ---------------------------------------------------------------------------

@router.post("/{flow_id}/runs", status_code=201)
async def enqueue_run(flow_id: str, body: RunFlowRequest, request: Request) -> Dict[str, Any]:
    """
    Requirement 5: Manual trigger inputs are labeled untrusted by default.
    Enqueues run to the QueueBackend.
    """
    storage = request.app.state.storage
    queue = request.app.state.queue

    # Determine version: exact or latest published
    target_version = body.version
    if target_version is None:
        versions = await storage.flows.list_versions(flow_id)
        if not versions:
            raise HTTPException(status_code=400, detail=f"Cannot run flow {flow_id!r}: no published versions exist")
        target_version = versions[-1].version
    else:
        ver_record = await storage.flows.get_version(flow_id, target_version)
        if ver_record is None:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} version {target_version} not found")

    run_id = f"run_{uuid.uuid4().hex[:12]}"
    # 3.1: inputs are run data (untrusted payload): never audited, only ids and the version
    await audit(request, "run.start", "run", run_id,
                details={"flow_id": flow_id, "version": target_version, "trigger": "manual"})
    run_record = RunRecord(
        run_id=run_id,
        mission_name=flow_id,
        flow_id=flow_id,
        flow_version=target_version,
        status="queued",
        trigger="manual",
        started_by=_who(request),
    )
    await storage.runs.put(run_record)
    await queue.enqueue(
        run_id=run_id,
        flow_id=flow_id,
        version=target_version,
        inputs=body.inputs,
    )
    return {
        "run_id": run_id,
        "flow_id": flow_id,
        "version": target_version,
        "status": "queued",
    }


@router.get("/{flow_id}/runs", response_model=List[RunRecord])
async def list_flow_runs(flow_id: str, request: Request) -> List[RunRecord]:
    storage = request.app.state.storage
    all_runs = await storage.runs.list(limit=500)
    return [r for r in all_runs if r.flow_id == flow_id or r.mission_name == flow_id]


@router.get("/{flow_id}/runs/{run_id}", response_model=RunRecord)
async def get_flow_run(flow_id: str, run_id: str, request: Request) -> RunRecord:
    storage = request.app.state.storage
    rec = await storage.runs.get(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    return rec


@router.get("/{flow_id}/runs/{run_id}/events", response_model=List[EventRecord])
async def poll_flow_run_events(
    flow_id: str,
    run_id: str,
    request: Request,
    after_seq: int = Query(0, ge=0),
) -> List[EventRecord]:
    """Poll run events with seq > after_seq."""
    storage = request.app.state.storage
    rec = await storage.runs.get(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    return await storage.events.list(run_id, after_seq=after_seq)


@router.websocket("/{flow_id}/runs/{run_id}/events")
async def stream_flow_run_events(
    websocket: WebSocket,
    flow_id: str,
    run_id: str,
    after_seq: int = Query(0, ge=0),
) -> None:
    """
    WebSocket endpoint streaming events as they appear.
    Requires WebSocket subprotocol 'agentos.token.<token>' (validated by ASGI middleware).
    ``after_seq`` (default 0) replays only events with seq > after_seq, so a reconnecting
    client resumes without gaps or duplicates.
    """
    app = websocket.app
    storage = app.state.storage
    rec = await storage.runs.get(run_id)
    if rec is None:
        await websocket.close(code=4004, reason=f"Run {run_id} not found")
        return

    await websocket.accept(subprotocol="agentos.v1")
    logger.info("WebSocket connected for flow run %s", run_id)

    last_seq = after_seq
    try:
        while True:
            events = await storage.events.list(run_id, after_seq=last_seq)
            for ev in events:
                await websocket.send_text(ev.model_dump_json())
                last_seq = ev.seq

            # Check run status
            run_rec = await storage.runs.get(run_id)
            if run_rec and run_rec.status in ("completed", "succeeded", "failed", "cancelled"):
                # Drain events appended between the read above and the status check, so the
                # client never misses the final events before run_finished.
                for ev in await storage.events.list(run_id, after_seq=last_seq):
                    await websocket.send_text(ev.model_dump_json())
                    last_seq = ev.seq
                await websocket.send_text(json.dumps({
                    "event": "run_finished",
                    "status": run_rec.status,
                    "error": run_rec.error,
                    "outputs": run_rec.outputs,
                }))
                break

            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for run %s", run_id)
    except Exception as e:
        logger.error("Error streaming run %s: %s", run_id, e)


PARK_WAIT_S = 3.0
PARK_POLL_S = 0.05


async def _wait_until_parked(queue: Any, run_id: str) -> bool:
    """True once the run's queue job no longer holds a worker lease (or there is no job). A bounded wait
    inside the request (at most PARK_WAIT_S), not a background watcher."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + PARK_WAIT_S
    while True:
        job = await queue.get_job_by_run_id(run_id) if queue is not None else None
        if job is None or job.status != "leased":
            return True
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(PARK_POLL_S)


@router.post("/{flow_id}/runs/{run_id}/approve")
async def approve_flow_run(
    flow_id: str,
    run_id: str,
    body: ApprovalRequestBody,
    request: Request,
) -> Dict[str, Any]:
    """
    Requirement 6: Deliver operator approval decision.
    - Only for runs in waiting at the named approval node.
    - Idempotent (second call is a no-op returning same result).
    - Decision can be 'reject' or False (fails run cleanly without executing sink).
    """
    storage = request.app.state.storage
    run_rec = await storage.runs.get(run_id)
    if run_rec is None:
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found")
    from agentos.flowtests.guard import TEST_RUN_MESSAGE, is_test_run

    if is_test_run(run_rec):  # 4.2: never resumed with the app transports (real channels)
        await audit(request, "approval.decide", "run", run_id, outcome="refused",
                    details={"flow_id": flow_id, "node_id": body.node_id, "reason": "test_run"})
        raise HTTPException(status_code=409, detail=TEST_RUN_MESSAGE)

    version = run_rec.flow_version
    if version is None:
        versions = await storage.flows.list_versions(flow_id)
        if not versions:
            raise HTTPException(status_code=400, detail="Run has no associated flow version")
        version = versions[-1].version

    flow_rec = await storage.flows.get_version(flow_id, version)
    if flow_rec is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} v{version} not found")

    flow_def = FlowDefinition(
        id=flow_rec.id,
        name=flow_rec.name,
        entrypoint=flow_rec.entrypoint,
        nodes=flow_rec.nodes,
        edges=flow_rec.edges,
        loops=flow_rec.loops,
    )

    policy = getattr(request.app.state, "security_policy", None) or SecurityPolicy()
    engine = FlowEngine(
        flow=flow_def,
        storage=storage,
        policy=policy,
        transport_registry=getattr(request.app.state, "transport_registry", None),
        usage=getattr(request.app.state, "usage", None),  # 3.2: the run continues in this request
        sandbox=getattr(request.app.state, "sandbox", None),  # 3.5: code tools after an approval
    )

    queue = request.app.state.queue
    # 3.1 (approval race): the worker makes the run visible as waiting while it still holds the lease and
    # releases it right after. A decision in that window must not be lost: wait briefly for the release,
    # else 409 "retry". One decision per run is applied at a time (exactly once with the idempotency check
    # in engine.approve). See docs/evidence/3.1.md.
    locks: Optional[Dict[str, asyncio.Lock]] = getattr(request.app.state, "approval_locks", None)
    if locks is None:
        locks = {}
        request.app.state.approval_locks = locks
    lock = locks.setdefault(run_id, asyncio.Lock())
    async with lock:
        if not await _wait_until_parked(queue, run_id):
            raise HTTPException(status_code=409, detail={
                "detail": f"Run {run_id} is still being parked by the worker; retry the decision in a moment",
                "retry": True,
            })
        approve = body.decision is True or str(body.decision).lower() in ("true", "approve", "approved")
        prior = [e for e in await storage.events.list(run_id, after_seq=0)
                 if e.type == "approval_decision" and (e.data or {}).get("node_id") == body.node_id]
        # 3.4 separation of duties (admin config, default off): who published this version may not decide its runs
        if getattr(request.app.state, "separation_of_duties", False) and not prior:
            who = _who(request)
            if who and flow_rec.published_by and flow_rec.published_by == who["user_id"]:
                await audit(request, "approval.decide", "run", run_id, outcome="refused", details={
                    "flow_id": flow_id, "node_id": body.node_id, "reason": "separation_of_duties"})
                raise HTTPException(status_code=403, detail="Separation of duties: you published this flow "
                                                            "version, so someone else must decide its approvals")
        # 3.1: audited before it is applied (503 and no decision if the entry cannot be written)
        await audit(request, "approval.decide", "run", run_id, details={
            "flow_id": flow_id, "node_id": body.node_id, "decision": "approve" if approve else "reject",
            "already_decided": bool(prior), "confirm_lookalike": body.confirm_lookalike,
        })
        try:
            state = await engine.approve(run_id=run_id, node_id=body.node_id, decision=body.decision,
                                         actor=_who(request), confirm_lookalike=body.confirm_lookalike)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))
        except FencingTokenError:
            raise HTTPException(status_code=409, detail={
                "detail": f"Run {run_id} is still being parked by the worker; retry the decision in a moment",
                "retry": True,
            })

    job = await queue.get_job_by_run_id(run_id)
    if job and hasattr(queue, "_lock") and hasattr(queue, "_jobs"):
        async with queue._lock:
            qjob = queue._jobs.get(job.job_id)
            if qjob:
                if state.status == RunStatus.SUCCEEDED:
                    qjob.status = "completed"
                    qjob.lease_id = None
                    qjob.leased_until = None
                elif state.status in (RunStatus.FAILED, RunStatus.CANCELLED):
                    qjob.status = "failed"
                    qjob.last_error = state.error or "rejected_by_operator"
                    qjob.lease_id = None
                    qjob.leased_until = None

    return {
        "run_id": run_id,
        "status": state.status.value,
        "error": state.error,
    }
