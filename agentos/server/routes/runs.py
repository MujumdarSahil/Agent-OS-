"""
Runs routes — polling status and WebSocket streaming.

Polling (GET /api/runs/{run_id}/status) is the primary mechanism.
WebSocket (WS /api/runs/{run_id}/stream) is secondary — see PHASE3_LIMITATIONS.md.
"""
import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect

from agentos.server.models import RunStatusResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["runs"])


@router.get("/runs/{run_id}/status", response_model=RunStatusResponse)
async def get_run_status(run_id: str, request: Request):
    """Poll the current status of a run."""
    run_manager = request.app.state.run_manager
    state = run_manager.get(run_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
    return RunStatusResponse(
        run_id=state.run_id,
        mission_name=state.mission_name,
        status=state.status,
        task_index=state.task_index,
        outputs=state.outputs,
        error=state.error,
        provider=state.provider,
    )


@router.websocket("/runs/{run_id}/stream")
async def stream_run(websocket: WebSocket, run_id: str):
    """
    WebSocket endpoint that pushes task events as they occur.
    Falls back gracefully — if the client disconnects, we stop streaming
    but the background task continues and remains poll-able.
    """
    # Import here to avoid circular at module level
    from agentos.server.app import create_app  # noqa – used only for type hint
    app = websocket.app
    run_manager = app.state.run_manager
    state = run_manager.get(run_id)

    if state is None:
        await websocket.close(code=4004, reason=f"Run {run_id} not found")
        return

    await websocket.accept()
    logger.info(f"WebSocket client connected for run {run_id}")

    try:
        # Drain any already-queued events, then wait for new ones
        while True:
            try:
                event = state.event_queue.get_nowait()
            except asyncio.QueueEmpty:
                if state.status in ("completed", "failed"):
                    # Send final status and close
                    await websocket.send_text(json.dumps({
                        "event": "run_finished",
                        "status": state.status,
                        "error": state.error,
                        "outputs": state.outputs,
                    }))
                    break
                # Wait for next event (with a short timeout to recheck status)
                try:
                    event = await asyncio.wait_for(state.event_queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    # Send a heartbeat ping so the client knows we're alive
                    await websocket.send_text(json.dumps({"event": "ping"}))
                    continue

            await websocket.send_text(json.dumps(event))

            if event.get("event") in ("run_completed", "run_failed"):
                break

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected for run {run_id}")
    except Exception as e:
        logger.exception(f"WebSocket error for run {run_id}: {e}")
    finally:
        await websocket.close()
