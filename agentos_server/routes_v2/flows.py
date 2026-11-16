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

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/flows", tags=["v2-flows"])


class RunFlowRequest(BaseModel):
    inputs: Dict[str, Any] = Field(default_factory=dict)
    version: Optional[int] = None


class ApprovalRequestBody(BaseModel):
    node_id: str
    decision: Any = True  # bool or "reject"/"approve"


# ---------------------------------------------------------------------------
# Flow CRUD & Publish & Versions
# ---------------------------------------------------------------------------

@router.get("", response_model=List[FlowRecord])
async def list_flows(request: Request) -> List[FlowRecord]:
    storage = request.app.state.storage
    return await storage.flows.list_flows()


@router.post("", response_model=FlowRecord, status_code=201)
async def create_flow(flow: FlowRecord, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    existing = await storage.flows.get_draft(flow.id)
    if existing is not None:
        raise HTTPException(status_code=400, detail=f"Flow {flow.id!r} draft already exists; use PUT to update")
    try:
        await storage.flows.put_draft(flow)
    except (InvalidFlowConfigError, ValueError) as err:
        raise HTTPException(status_code=400, detail=str(err))
    return (await storage.flows.get_draft(flow.id)) or flow


@router.get("/{flow_id}", response_model=FlowRecord)
async def get_flow(flow_id: str, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    draft = await storage.flows.get_draft(flow_id)
    if draft is not None:
        return draft
    versions = await storage.flows.list_versions(flow_id)
    if versions:
        return versions[-1]
    raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found")


@router.put("/{flow_id}", response_model=FlowRecord)
async def put_flow(flow_id: str, flow: FlowRecord, request: Request) -> FlowRecord:
    storage = request.app.state.storage
    if flow.id != flow_id:
        raise HTTPException(status_code=400, detail=f"Path flow_id {flow_id!r} does not match body id {flow.id!r}")
    try:
        await storage.flows.put_draft(flow)
    except (InvalidFlowConfigError, ValueError) as err:
        raise HTTPException(status_code=400, detail=str(err))
    saved = await storage.flows.get_draft(flow_id)
    if saved is None:
        raise HTTPException(status_code=500, detail="Failed to save flow draft")
    return saved


@router.delete("/{flow_id}")
async def delete_flow(flow_id: str, request: Request) -> Dict[str, bool]:
    """Requirement 7: Deletion guard — published versions cannot be deleted (returns 409)."""
    storage = request.app.state.storage
    versions = await storage.flows.list_versions(flow_id)
    if versions:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete flow with published versions; use archive instead",
        )
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
    try:
        return await storage.flows.archive_flow(flow_id)
    except ValueError as err:
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
        raise HTTPException(status_code=400, detail=f"Flow structural validation failed: {err}")

    # Run publish gate verification
    policy = getattr(request.app.state, "security_policy", None) or SecurityPolicy()
    analyzer = StaticFlowAnalyzer(flow=flow_def, policy=policy)
    res = analyzer.verify()
    if not res.is_valid:
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

    # Compute content_sha256 and policy_hash
    content_bytes = json.dumps(flow_def.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    policy_bytes = json.dumps(policy.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()

    # Atomically assign version and persist published flow
    published = await storage.flows.publish(
        flow_id=flow_id,
        content_sha256=content_sha256,
        policy_hash=policy_hash,
    )
    return published


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
    run_record = RunRecord(
        run_id=run_id,
        mission_name=flow_id,
        flow_id=flow_id,
        flow_version=target_version,
        status="queued",
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
    )

    try:
        state = await engine.approve(run_id=run_id, node_id=body.node_id, decision=body.decision)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    queue = request.app.state.queue
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
