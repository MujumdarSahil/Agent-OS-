"""
Aggregated v2 API Router for AgentOS.
"""

from __future__ import annotations

from fastapi import APIRouter

from agentos_server.routes_v2.agents import router as agents_router
from agentos_server.routes_v2.mcp_servers import router as mcp_servers_router
from agentos_server.routes_v2.providers import router as providers_router
from agentos_server.routes_v2.squads import router as squads_router
from agentos_server.routes_v2.tools import router as tools_router
from agentos_server.routes_v2.vault import router as vault_router

router = APIRouter()

router.include_router(agents_router)
router.include_router(squads_router)
router.include_router(tools_router)
router.include_router(mcp_servers_router)
router.include_router(vault_router)
router.include_router(providers_router)
