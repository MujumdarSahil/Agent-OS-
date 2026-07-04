"""Tools routes."""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Request

from agentos.server.models import ToolScaffoldRequest, ToolInfo
from agentos.core.project_ops import list_tools, scaffold_tool, is_valid_project

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tools"])


def _project(request: Request) -> str:
    p = request.app.state.project_path
    if not is_valid_project(p):
        raise HTTPException(status_code=404, detail="No active AgentOS project found.")
    return p


@router.get("/tools", response_model=List[ToolInfo])
async def get_tools(request: Request):
    return [ToolInfo(**t) for t in list_tools(_project(request))]


@router.post("/tools", response_model=ToolInfo, status_code=201)
async def create_tool(body: ToolScaffoldRequest, request: Request):
    try:
        path = scaffold_tool(_project(request), body.name)
        return ToolInfo(name=body.name, file=path)
    except Exception as e:
        logger.exception("create_tool failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tool-types", response_model=list)
async def get_tool_types():
    """Return all tool class and instance names currently registered in ToolRegistry."""
    from agentos.core.base import ToolRegistry
    registry = ToolRegistry()
    classes = sorted(registry._registry.keys())
    instances = sorted(registry._instances.keys())
    return classes + instances
