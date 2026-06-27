"""Checkpoints route — read run history from SQLite."""
import logging
import os
from typing import List

from fastapi import APIRouter, HTTPException, Request

from agentos.core.checkpoint import SQLiteCheckpointStore
from agentos.server.models import CheckpointRecord

logger = logging.getLogger(__name__)
router = APIRouter(tags=["checkpoints"])


def _store(request: Request) -> SQLiteCheckpointStore:
    p = request.app.state.project_path
    db_path = os.path.join(p, "checkpoints", "run_history.db")
    return SQLiteCheckpointStore(db_path=db_path)


@router.get("/checkpoints/{mission_name}", response_model=List[CheckpointRecord])
async def get_checkpoints(mission_name: str, request: Request):
    try:
        store = _store(request)
        rows = store.list_runs(mission_id=mission_name)
        return [CheckpointRecord(**r) for r in rows]
    except Exception as e:
        logger.exception(f"get_checkpoints {mission_name} failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/checkpoints", response_model=List[CheckpointRecord])
async def get_all_checkpoints(request: Request):
    """Return all checkpoint records across all missions (for dashboard)."""
    try:
        store = _store(request)
        rows = store.list_runs()
        return [CheckpointRecord(**r) for r in rows]
    except Exception as e:
        logger.exception("get_all_checkpoints failed")
        raise HTTPException(status_code=500, detail=str(e))
