"""Health check route."""
from fastapi import APIRouter, Request
from agentos.server.models import HealthResponse
from agentos.core.project_ops import list_agents, list_tools, list_crews, list_missions

from agentos.__version__ import __version__

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request):
    p = request.app.state.project_path
    from agentos.llm.llm_client import get_last_used_provider, get_fallback_events_count
    return HealthResponse(
        status="ok",
        version=__version__,
        project=p,
        agents=len(list_agents(p)),
        tools=len(list_tools(p)),
        crews=len(list_crews(p)),
        missions=len(list_missions(p)),
        last_used_model=get_last_used_provider() or "No model used yet",
        fallback_events=get_fallback_events_count()
    )
