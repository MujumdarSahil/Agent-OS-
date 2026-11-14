"""
MCP Server CRUD endpoints (/api/v2/mcp-servers).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request

from agentos.storage.models import MCPServerRecord

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mcp-servers", tags=["v2-mcp-servers"])


@router.get("", response_model=List[MCPServerRecord])
async def list_mcp_servers(request: Request) -> List[MCPServerRecord]:
    storage = request.app.state.storage
    return await storage.mcp_servers.list()


@router.get("/{name}", response_model=MCPServerRecord)
async def get_mcp_server(name: str, request: Request) -> MCPServerRecord:
    storage = request.app.state.storage
    server = await storage.mcp_servers.get(name)
    if server is None:
        raise HTTPException(status_code=404, detail=f"MCP Server '{name}' not found")
    return server


@router.post("", response_model=MCPServerRecord)
async def put_mcp_server(payload: Dict[str, Any], request: Request) -> MCPServerRecord:
    storage = request.app.state.storage
    try:
        server_record = MCPServerRecord(**payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Saved but NEVER launched or connected in 1.4
    await storage.mcp_servers.put(server_record)
    return server_record


@router.delete("/{name}")
async def delete_mcp_server(name: str, request: Request) -> Dict[str, bool]:
    storage = request.app.state.storage
    deleted = await storage.mcp_servers.delete(name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"MCP Server '{name}' not found")
    return {"deleted": True}
