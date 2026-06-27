"""MCP plugin routes."""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Request

from agentos.core.project_ops import list_mcp_plugins, scaffold_mcp_plugin
from agentos.server.models import MCPPluginInfo, MCPPluginScaffoldRequest

logger = logging.getLogger(__name__)
router = APIRouter(tags=["mcp-plugins"])


def _project(request: Request) -> str:
    return request.app.state.project_path


@router.get("/mcp-plugins", response_model=List[MCPPluginInfo])
async def get_plugins(request: Request):
    return [MCPPluginInfo(**p) for p in list_mcp_plugins(_project(request))]


@router.post("/mcp-plugins", response_model=MCPPluginInfo, status_code=201)
async def create_plugin(body: MCPPluginScaffoldRequest, request: Request):
    try:
        scaffold_mcp_plugin(_project(request), body.name)
        return MCPPluginInfo(
            name=body.name, version="1.0.0", author="Developer",
            permissions=[], entrypoint="plugin.MyMCPPlugin", mcp_server_url=None,
        )
    except FileExistsError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("create_plugin failed")
        raise HTTPException(status_code=500, detail=str(e))
