"""
federation.py — Phase 4 API routes for Multi-Squad Federation.

Sequential federation only. See PHASE4_FEDERATION.md for full scope and limitations.
"""
import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/federation", tags=["federation"])


class FederatedMissionStage(BaseModel):
    squad_crew: str    # crew name for this stage
    mission: str       # mission name for this stage


class CreateFederatedMissionRequest(BaseModel):
    name: str
    stages: List[FederatedMissionStage]


class FederatedMissionInfo(BaseModel):
    name: str
    stages: List[FederatedMissionStage]


class FederatedRunStatus(BaseModel):
    run_id: str
    federation_name: str
    status: str
    stages_completed: int
    total_stages: int
    error: Optional[str] = None
    final_output: Optional[str] = None


# In-memory store for federation run state (same pattern as run_manager)
_federation_runs: Dict[str, Dict[str, Any]] = {}
_federation_configs: Dict[str, Dict[str, Any]] = {}


def _project(request: Request) -> str:
    return request.app.state.project_path


@router.post("/missions", status_code=201)
async def create_federated_mission(body: CreateFederatedMissionRequest, request: Request):
    """
    Create/register a federated mission configuration.
    Saves the stage list to project's federated_missions/<name>.yaml.
    """
    import yaml
    import os
    project_path = _project(request)
    fed_dir = os.path.join(project_path, "federated_missions")
    os.makedirs(fed_dir, exist_ok=True)
    
    config = {
        "name": body.name,
        "stages": [{"squad_crew": s.squad_crew, "mission": s.mission} for s in body.stages],
    }
    config_path = os.path.join(fed_dir, f"{body.name}.yaml")
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f)
    
    _federation_configs[body.name] = config
    return {"name": body.name, "stages_count": len(body.stages), "config_path": config_path}


@router.get("/missions")
async def list_federated_missions(request: Request):
    """List all federated mission configurations in the project."""
    import yaml
    import os
    import glob
    
    project_path = _project(request)
    fed_dir = os.path.join(project_path, "federated_missions")
    results = []
    if os.path.exists(fed_dir):
        for fpath in glob.glob(os.path.join(fed_dir, "*.yaml")):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                results.append(data)
            except Exception as e:
                logger.warning(f"Skipping invalid federated mission {fpath}: {e}")
    return results


@router.post("/missions/{name}/run")
async def run_federated_mission(
    name: str,
    request: Request,
    background_tasks: BackgroundTasks,
    resume: bool = False,
):
    """
    Run a federated mission asynchronously. Returns a run_id to poll for status.
    """
    import yaml
    import os
    
    project_path = _project(request)
    
    # Load the federation config
    config_path = os.path.join(project_path, "federated_missions", f"{name}.yaml")
    if not os.path.exists(config_path):
        raise HTTPException(status_code=404, detail=f"Federated mission '{name}' not found")
    
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    run_id = str(uuid.uuid4())
    _federation_runs[run_id] = {
        "run_id": run_id,
        "federation_name": name,
        "status": "queued",
        "stages_completed": 0,
        "total_stages": len(config.get("stages", [])),
        "error": None,
        "final_output": None,
    }
    
    background_tasks.add_task(
        _execute_federation, run_id, name, config, project_path, resume
    )
    
    return {"run_id": run_id, "federation_name": name, "status": "queued"}


@router.get("/runs/{run_id}/status", response_model=FederatedRunStatus)
async def get_federated_run_status(run_id: str):
    """Get the status of a federated mission run."""
    if run_id not in _federation_runs:
        raise HTTPException(status_code=404, detail=f"Federation run '{run_id}' not found")
    return FederatedRunStatus(**_federation_runs[run_id])


async def _execute_federation(
    run_id: str,
    federation_name: str,
    config: Dict,
    project_path: str,
    resume: bool,
):
    """Background task: build squads from project files and run the federation."""
    from agentos.core.federation import FederatedMission, FederationStage
    from agentos.core.project_ops import build_squad_from_project
    from agentos.core.checkpoint import SQLiteCheckpointStore
    
    _federation_runs[run_id]["status"] = "running"
    
    try:
        checkpoint_db = os.path.join(project_path, "checkpoints", "run_history.db")
        checkpoint_store = SQLiteCheckpointStore(db_path=checkpoint_db)
        
        stages = []
        for idx, stage_cfg in enumerate(config.get("stages", [])):
            mission_name = stage_cfg["mission"]
            squad, mission = build_squad_from_project(project_path, mission_name)
            stages.append(FederationStage(
                squad=squad,
                mission=mission,
                stage_index=idx,
                name=f"{stage_cfg['squad_crew']}/{mission_name}",
            ))
        
        fed = FederatedMission(
            federation_id=federation_name,
            stages=stages,
            checkpoint_store=checkpoint_store,
        )
        
        result = await fed.run()
        
        _federation_runs[run_id].update({
            "status": "completed",
            "stages_completed": result["stages_completed"],
            "total_stages": result["total_stages"],
            "final_output": result.get("final_output", ""),
        })
        
    except Exception as e:
        logger.exception(f"Federation run {run_id} failed")
        _federation_runs[run_id].update({
            "status": "failed",
            "error": str(e),
        })
