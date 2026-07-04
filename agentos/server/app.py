"""
FastAPI app factory for the AgentOS backend server.

Usage:
    from agentos.server.app import create_app
    app = create_app(project_path="/path/to/my-project")
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agentos.server.run_manager import RunManager
from agentos.core.governance import GovernanceEngine

logger = logging.getLogger(__name__)


from typing import Optional

def create_app(project_path: Optional[str] = None) -> FastAPI:
    """
    Create and configure the AgentOS FastAPI application.

    Args:
        project_path: Optional absolute path to the AgentOS project directory.
    """
    from agentos.core.logging_config import setup_logging
    from agentos.__version__ import __version__
    setup_logging()

    if project_path is None:
        project_path = os.environ.get("AGENTOS_PROJECT", os.getcwd())
    project_path = os.path.abspath(project_path)

    # Load API keys from .env (repo root first, then project directory overrides)
    try:
        from dotenv import load_dotenv
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        root_env = os.path.join(repo_root, ".env")
        if os.path.exists(root_env):
            load_dotenv(root_env)
        project_env = os.path.join(project_path, ".env")
        if os.path.exists(project_env):
            load_dotenv(project_env, override=True)
    except ImportError:
        pass

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from agentos.core.bootstrap import register_builtin_components
        register_builtin_components()
        logger.info(f"AgentOS API starting for project: {project_path}")
        yield
        logger.info("AgentOS API shutting down.")

    app = FastAPI(
        title="AgentOS API",
        description="REST API for the AgentOS multi-agent framework",
        version=__version__,
        lifespan=lifespan,
    )

    # -----------------------------------------------------------------------
    # CORS — allow the Vite dev server (port 5173) and any localhost origin
    # -----------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # App state — shared between all requests
    # -----------------------------------------------------------------------
    app.state.project_path = project_path
    gov = GovernanceEngine()
    gov.initialize_security_policies()
    app.state.governance = gov
    app.state.run_manager = RunManager(governance=gov)
    app.state.failed_providers = set()

    # -----------------------------------------------------------------------
    # Register API routes
    # -----------------------------------------------------------------------
    from agentos.server.routes.health import router as health_router
    from agentos.server.routes.agents import router as agents_router
    from agentos.server.routes.tools import router as tools_router
    from agentos.server.routes.crews import router as crews_router
    from agentos.server.routes.missions import router as missions_router
    from agentos.server.routes.runs import router as runs_router
    from agentos.server.routes.checkpoints import router as checkpoints_router
    from agentos.server.routes.builder import router as builder_router
    from agentos.server.routes.mcp_plugins import router as mcp_router
    from agentos.server.routes.governance import router as governance_router
    from agentos.server.routes.packaging import router as packaging_router
    from agentos.server.routes.templates import router as templates_router
    from agentos.server.routes.federation import router as federation_router
    from agentos.server.routes.providers import router as providers_router

    app.include_router(health_router, prefix="/api")
    app.include_router(agents_router, prefix="/api")
    app.include_router(tools_router, prefix="/api")
    app.include_router(crews_router, prefix="/api")
    app.include_router(missions_router, prefix="/api")
    app.include_router(runs_router, prefix="/api")
    app.include_router(checkpoints_router, prefix="/api")
    app.include_router(builder_router, prefix="/api")
    app.include_router(mcp_router, prefix="/api")
    app.include_router(governance_router, prefix="/api")
    app.include_router(packaging_router, prefix="/api")
    app.include_router(templates_router, prefix="/api")
    app.include_router(federation_router, prefix="/api")
    app.include_router(providers_router, prefix="/api")

    # -----------------------------------------------------------------------
    # Serve built frontend in production mode
    # -----------------------------------------------------------------------
    frontend_dist = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "agentos", "frontend", "dist",
    )
    if os.path.exists(frontend_dist):
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
        logger.info(f"Serving frontend from {frontend_dist}")

    return app
