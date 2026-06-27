"""Crews routes."""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Request

from agentos.core.config_models import CrewYAMLConfig
from agentos.core.project_ops import list_crews, write_crew, read_crew

logger = logging.getLogger(__name__)
router = APIRouter(tags=["crews"])


def _project(request: Request) -> str:
    return request.app.state.project_path


@router.get("/crews", response_model=List[CrewYAMLConfig])
async def get_crews(request: Request):
    return list_crews(_project(request))


@router.post("/crews", response_model=CrewYAMLConfig, status_code=201)
async def create_crew(body: CrewYAMLConfig, request: Request):
    try:
        write_crew(_project(request), body)
        return body
    except Exception as e:
        logger.exception("create_crew failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/crews/{name}", response_model=CrewYAMLConfig)
async def get_crew(name: str, request: Request):
    try:
        return read_crew(_project(request), name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Crew '{name}' not found")
