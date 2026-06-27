"""Missions routes — list, create, and async run trigger."""
import logging
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request

from agentos.core.config_models import MissionYAMLConfig
from agentos.core.project_ops import list_missions, write_mission, read_mission
from agentos.server.models import RunStartResponse, RunRequest

logger = logging.getLogger(__name__)
router = APIRouter(tags=["missions"])


def _project(request: Request) -> str:
    return request.app.state.project_path


@router.get("/missions", response_model=List[MissionYAMLConfig])
async def get_missions(request: Request):
    return list_missions(_project(request))


@router.post("/missions", response_model=MissionYAMLConfig, status_code=201)
async def create_mission(body: MissionYAMLConfig, request: Request):
    try:
        write_mission(_project(request), body)
        return body
    except Exception as e:
        logger.exception("create_mission failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/missions/{name}", response_model=MissionYAMLConfig)
async def get_mission(name: str, request: Request):
    try:
        return read_mission(_project(request), name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Mission '{name}' not found")


@router.post("/missions/{name}/run", response_model=RunStartResponse)
async def run_mission(
    name: str,
    request: Request,
    background_tasks: BackgroundTasks,
    resume: bool = Query(False),
    body: Optional[RunRequest] = None,
):
    """
    Trigger a mission run asynchronously.
    Returns run_id immediately; poll GET /api/runs/{run_id}/status for progress.
    Does NOT block while the mission runs — missions can take minutes.
    """
    p = _project(request)

    # Validate mission exists before launching
    try:
        read_mission(p, name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Mission '{name}' not found")

    run_manager = request.app.state.run_manager
    effective_resume = resume or (body.resume if body else False)
    license_key = body.license_key if body else None

    run_id = run_manager.create_run(mission_name=name)

    background_tasks.add_task(
        run_manager.execute,
        run_id=run_id,
        project_path=p,
        mission_name=name,
        resume=effective_resume,
        license_key=license_key,
    )

    logger.info(f"Queued mission '{name}' as run {run_id} (resume={effective_resume})")
    return RunStartResponse(run_id=run_id, mission_name=name)
