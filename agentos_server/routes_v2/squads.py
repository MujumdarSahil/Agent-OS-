"""
Squad CRUD endpoints (/api/v2/squads).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request

from agentos.storage.models import SquadRecord

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/squads", tags=["v2-squads"])


@router.get("", response_model=List[SquadRecord])
async def list_squads(request: Request) -> List[SquadRecord]:
    storage = request.app.state.storage
    return await storage.squads.list()


@router.get("/{name}", response_model=SquadRecord)
async def get_squad(name: str, request: Request) -> SquadRecord:
    storage = request.app.state.storage
    squad = await storage.squads.get(name)
    if squad is None:
        raise HTTPException(status_code=404, detail=f"Squad '{name}' not found")
    return squad


@router.post("", response_model=SquadRecord)
async def put_squad(payload: Dict[str, Any], request: Request) -> SquadRecord:
    storage = request.app.state.storage
    try:
        squad_record = SquadRecord(**payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    await storage.squads.put(squad_record)
    return squad_record


@router.delete("/{name}")
async def delete_squad(name: str, request: Request) -> Dict[str, bool]:
    storage = request.app.state.storage
    deleted = await storage.squads.delete(name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Squad '{name}' not found")
    return {"deleted": True}
