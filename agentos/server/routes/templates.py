"""templates.py — Phase 4 API routes for bundled template listing and installation."""
import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from agentos.templates.templates import list_templates, install_template, BUNDLED_TEMPLATES

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/templates", tags=["templates"])


class TemplateInfo(BaseModel):
    name: str
    display_name: str
    description: str
    agents: List[str]
    crews: List[str]
    missions: List[str]
    license_type: str
    tags: List[str]
    pack_available: bool


class TemplateInstallRequest(BaseModel):
    force: bool = False


class TemplateInstallResult(BaseModel):
    installed: dict
    pack: Optional[str]
    version: Optional[str]
    template_name: str


@router.get("", response_model=List[TemplateInfo])
async def get_templates():
    """List all bundled templates with their metadata."""
    templates = list_templates()
    return [TemplateInfo(**{k: v for k, v in t.items() if k != "pack_path"}) for t in templates]


@router.post("/{name}/install", response_model=TemplateInstallResult)
async def install_template_route(name: str, body: TemplateInstallRequest, request: Request):
    """
    Install a bundled template into the current project.
    Uses the same pack_format.install_pack() logic as the /packaging/install route.
    """
    project_path = request.app.state.project_path
    try:
        result = install_template(
            template_name=name,
            target_project=project_path,
            force=body.force,
        )
        return TemplateInstallResult(
            installed=result.get("installed", {}),
            pack=result.get("pack"),
            version=result.get("version"),
            template_name=name,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except FileExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.exception(f"Template install failed for '{name}'")
        raise HTTPException(status_code=500, detail=str(e))
