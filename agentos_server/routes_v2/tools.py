"""
Tool CRUD endpoints (/api/v2/tools).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request

from agentos.storage.models import ToolRecord

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/tools", tags=["v2-tools"])


@router.get("", response_model=List[ToolRecord])
async def list_tools(request: Request) -> List[ToolRecord]:
    storage = request.app.state.storage
    return await storage.tools.list()


@router.get("/{name}", response_model=ToolRecord)
async def get_tool(name: str, request: Request) -> ToolRecord:
    storage = request.app.state.storage
    tool = await storage.tools.get(name)
    if tool is None:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")
    return tool


@router.post("", response_model=ToolRecord)
async def put_tool(payload: Dict[str, Any], request: Request) -> ToolRecord:
    storage = request.app.state.storage
    try:
        tool_record = ToolRecord(**payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Existing project tools cannot be modified
    existing = await storage.tools.get(tool_record.name)
    if existing and existing.origin == "project":
        raise HTTPException(status_code=400, detail="Project tools are read-only")

    # Stored tool code is saved as text and never executed outside sandbox
    await storage.tools.put(tool_record)
    return tool_record


@router.delete("/{name}")
async def delete_tool(name: str, request: Request) -> Dict[str, bool]:
    storage = request.app.state.storage
    existing = await storage.tools.get(name)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")
    if existing.origin == "project":
        raise HTTPException(status_code=400, detail="Project tools are read-only")

    deleted = await storage.tools.delete(name)
    return {"deleted": deleted}
