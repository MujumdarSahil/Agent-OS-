"""
Builder routes — natural-language agent/tool/crew generation.

Preview/confirm split enforces the "never auto-write" rule from Phase 2:
  POST /api/builder/{type}           -> preview (no disk write)
  POST /api/builder/{type}/confirm   -> write to disk (human confirmation step)
"""
import hashlib
import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from agentos.builder.agent_builder import AgentBuilder
from agentos.builder.tool_builder import ToolBuilder
from agentos.builder.crew_builder import CrewBuilder
from agentos.core.project_ops import load_project_config
from agentos.llm import LLMClient
from agentos.server.models import (
    BuilderDescriptionRequest,
    BuilderPreviewResponse,
    BuilderConfirmRequest,
    BuilderConfirmResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/builder", tags=["builder"])


def _llm(project_path: str) -> LLMClient:
    cfg = load_project_config(project_path)
    return LLMClient(preferred_tags=cfg.preferred_tags or ["fast"])


def _preview_token(config: dict) -> str:
    """Stable hash of the config dict used as a preview token."""
    raw = json.dumps(config, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Agent builder
# ---------------------------------------------------------------------------

@router.post("/agent", response_model=BuilderPreviewResponse)
async def preview_agent(body: BuilderDescriptionRequest, request: Request):
    p = request.app.state.project_path
    try:
        builder = AgentBuilder(llm_client=_llm(p))
        config = builder.create_from_description(body.description)
        return BuilderPreviewResponse(config=config, preview_token=_preview_token(config))
    except Exception as e:
        logger.exception("preview_agent failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agent/confirm", response_model=BuilderConfirmResponse)
async def confirm_agent(body: BuilderConfirmRequest, request: Request):
    p = request.app.state.project_path
    import yaml
    from agentos.core.config_models import AgentYAMLConfig
    from agentos.core.project_ops import write_agent
    try:
        cfg = AgentYAMLConfig(**body.config)
        path = write_agent(p, cfg)
        return BuilderConfirmResponse(file_path=path, config=body.config)
    except Exception as e:
        logger.exception("confirm_agent failed")
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Tool builder
# ---------------------------------------------------------------------------

@router.post("/tool", response_model=BuilderPreviewResponse)
async def preview_tool(body: BuilderDescriptionRequest, request: Request):
    p = request.app.state.project_path
    try:
        builder = ToolBuilder(llm_client=_llm(p))
        config, py_code = builder.create_from_description(body.description)
        combined = {"config": config, "py_code": py_code}
        return BuilderPreviewResponse(config=combined, preview_token=_preview_token(combined))
    except Exception as e:
        logger.exception("preview_tool failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tool/confirm", response_model=BuilderConfirmResponse)
async def confirm_tool(body: BuilderConfirmRequest, request: Request):
    p = request.app.state.project_path
    try:
        config = body.config.get("config", {})
        py_code = body.config.get("py_code", "")
        name = config.get("name", "unknown_tool")
        tools_dir = os.path.join(p, "tools")
        os.makedirs(tools_dir, exist_ok=True)
        dest = os.path.join(tools_dir, f"{name}.py")
        with open(dest, "w", encoding="utf-8") as f:
            f.write(py_code)
        return BuilderConfirmResponse(file_path=dest, config=body.config)
    except Exception as e:
        logger.exception("confirm_tool failed")
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Crew builder
# ---------------------------------------------------------------------------

@router.post("/crew", response_model=BuilderPreviewResponse)
async def preview_crew(body: BuilderDescriptionRequest, request: Request):
    p = request.app.state.project_path
    try:
        builder = CrewBuilder(llm_client=_llm(p))
        config = builder.create_from_goal(body.description)
        return BuilderPreviewResponse(config=config, preview_token=_preview_token(config))
    except Exception as e:
        logger.exception("preview_crew failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crew/confirm", response_model=BuilderConfirmResponse)
async def confirm_crew(body: BuilderConfirmRequest, request: Request):
    import yaml
    from agentos.core.config_models import AgentYAMLConfig, CrewYAMLConfig
    from agentos.core.project_ops import write_agent, write_crew, write_mission
    from agentos.core.config_models import MissionYAMLConfig, TaskYAMLConfig
    p = request.app.state.project_path
    proposed = body.config
    written = []
    try:
        for a in proposed.get("agents", []):
            a_cfg = AgentYAMLConfig(
                name=a["name"], role=a["role"], goal=a["goal"],
                backstory=a.get("backstory", ""),
                llm_tags=["fast"],
                tool_refs=a.get("suggested_tools", []),
            )
            written.append(write_agent(p, a_cfg))
        c_cfg = CrewYAMLConfig(
            name=proposed["name"],
            agents=[a["name"] for a in proposed.get("agents", [])],
            process=proposed.get("process", "sequential"),
        )
        written.append(write_crew(p, c_cfg))
        tasks = [
            TaskYAMLConfig(description=t["description"], assigned_agent=t.get("assigned_agent"))
            for t in proposed.get("tasks", [])
        ]
        m_cfg = MissionYAMLConfig(
            name=f"{proposed['name']}Mission",
            goal=proposed.get("goal", ""),
            description=f"Auto-generated mission for crew: {proposed['name']}",
            crew=proposed["name"],
            tasks=tasks,
        )
        written.append(write_mission(p, m_cfg))
        return BuilderConfirmResponse(file_path=";".join(written), config=body.config)
    except Exception as e:
        logger.exception("confirm_crew failed")
        raise HTTPException(status_code=400, detail=str(e))
