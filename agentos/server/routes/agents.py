"""Agent CRUD routes."""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Request

from agentos.core.config_models import AgentYAMLConfig
from agentos.core.project_ops import (
    list_agents, read_agent, write_agent, delete_agent,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["agents"])


def _project(request: Request) -> str:
    return request.app.state.project_path


@router.get("/agents", response_model=List[AgentYAMLConfig])
async def get_agents(request: Request):
    return list_agents(_project(request))


@router.post("/agents", response_model=AgentYAMLConfig, status_code=201)
async def create_agent(body: AgentYAMLConfig, request: Request):
    try:
        path = write_agent(_project(request), body)
        logger.info(f"Created agent: {body.name} at {path}")
        return body
    except Exception as e:
        logger.exception("create_agent failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{name}", response_model=AgentYAMLConfig)
async def get_agent(name: str, request: Request):
    try:
        return read_agent(_project(request), name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")
    except Exception as e:
        logger.exception(f"get_agent {name} failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/agents/{name}", response_model=AgentYAMLConfig)
async def update_agent(name: str, body: AgentYAMLConfig, request: Request):
    p = _project(request)
    try:
        read_agent(p, name)  # ensure exists
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")
    try:
        write_agent(p, body)
        return body
    except Exception as e:
        logger.exception(f"update_agent {name} failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/agents/{name}", status_code=204)
async def remove_agent(name: str, request: Request):
    deleted = delete_agent(_project(request), name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")


@router.get("/agent-types", response_model=list)
async def get_agent_types():
    """Return all agent class names currently registered in AgentRegistry."""
    from agentos.core.base import AgentRegistry
    registry = AgentRegistry()
    return sorted(registry._registry.keys())
