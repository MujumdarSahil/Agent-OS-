"""
FastAPI app factory for the AgentOS backend server.

Usage:
    from agentos_server.app import create_app
    app = create_app(project_path="/path/to/my-project")
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agentos_server.run_manager import RunManager
from agentos.core.governance import GovernanceEngine

logger = logging.getLogger(__name__)


from typing import Any, Optional

def create_app(
    project_path: Optional[str] = None,
    storage: Optional[Any] = None,
) -> FastAPI:
    """
    Create and configure the AgentOS FastAPI application.

    Args:
        project_path: Optional absolute path to the AgentOS project directory.
        storage: Optional pre-configured Storage instance (File or Mongo).
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
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
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

        # If Mongo URI is configured and storage was not explicitly provided, open Mongo storage
        mongo_uri = os.environ.get("AGENTOS_MONGO_URI")
        if mongo_uri and getattr(app.state, "_storage_explicit", False) is False:
            try:
                from agentos.storage.mongo import open_mongo_storage
                app.state.storage = await open_mongo_storage(mongo_uri)
                from agentos.security.vault import Vault
                app.state.vault = Vault(app.state.storage.credentials, app.state.master_key)
            except Exception as e:
                logger.error(f"Failed to connect to Mongo at {mongo_uri}: {e}")
                raise RuntimeError(
                    f"AGENTOS_MONGO_URI is set but MongoDB is unreachable at {mongo_uri}: {e}"
                ) from e

        # Pre-load fallback policy cache into in-memory router cache
        try:
            configs = await app.state.storage.provider_configs.list()
            from agentos.llm.router_factory import set_fallback_policy_cache
            set_fallback_policy_cache([c.model_dump() for c in configs])
        except Exception as e:
            logger.warning(f"Failed to pre-load fallback policy cache: {e}")

        # Print one-time token access link with actual served UI port
        server_port = int(os.environ.get("AGENTOS_PORT", 8000))
        print_startup_auth_banner(app.state.api_token, server_port=server_port)

        yield
        # Close mongo client if present
        closer = getattr(app.state.storage, "_closer", None)
        if closer:
            try:
                await closer()
            except Exception:
                pass
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

    # Initialize 1.2 Storage port (File or Mongo)
    if storage is not None:
        app.state.storage = storage
        app.state._storage_explicit = True
    else:
        from agentos.storage.file import open_file_storage
        app.state.storage = open_file_storage(project_path)
        app.state._storage_explicit = False

    # Initialize Credentials Vault
    from agentos.security.vault import Vault, MasterKey
    try:
        master_key = MasterKey.load(create=True)
    except Exception as e:
        raise RuntimeError(f"Failed to load vault master key: {e}") from e
    app.state.master_key = master_key
    app.state.vault = Vault(app.state.storage.credentials, master_key)

    # Local API token
    from agentos_server.auth import get_or_create_api_token, print_startup_auth_banner, SecurityMiddleware
    api_token = get_or_create_api_token()
    app.state.api_token = api_token

    # -----------------------------------------------------------------------
    # Security Middleware: Host header validation & Token Authentication (HTTP & WS)
    # -----------------------------------------------------------------------
    app.add_middleware(SecurityMiddleware, api_token=api_token)

    # -----------------------------------------------------------------------
    # Register API routes
    # -----------------------------------------------------------------------
    from agentos_server.routes.health import router as health_router
    from agentos_server.routes.agents import router as agents_router
    from agentos_server.routes.tools import router as tools_router
    from agentos_server.routes.crews import router as crews_router
    from agentos_server.routes.missions import router as missions_router
    from agentos_server.routes.runs import router as runs_router
    from agentos_server.routes.checkpoints import router as checkpoints_router
    from agentos_server.routes.builder import router as builder_router
    from agentos_server.routes.mcp_plugins import router as mcp_router
    from agentos_server.routes.governance import router as governance_router
    from agentos_server.routes.packaging import router as packaging_router
    from agentos_server.routes.templates import router as templates_router
    from agentos_server.routes.federation import router as federation_router
    from agentos_server.routes.providers import router as providers_router

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

    from agentos_server.routes_v2 import router as v2_router
    app.include_router(v2_router, prefix="/api/v2")

    # -----------------------------------------------------------------------
    # Serve built frontend in production mode: packaged copy first (wheel
    # installs), then the ui/ build output (source checkouts).
    # -----------------------------------------------------------------------
    package_static = os.path.join(os.path.dirname(__file__), "static")
    checkout_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "dist")
    frontend_dist = package_static if os.path.isfile(os.path.join(package_static, "index.html")) else checkout_dist
    if os.path.exists(frontend_dist):
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
        logger.info(f"Serving frontend from {frontend_dist}")

    return app
