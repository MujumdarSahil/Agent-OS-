"""
Aggregated v2 API Router for AgentOS.
"""

from __future__ import annotations

from fastapi import APIRouter

from agentos_server.routes_v2.access import router as access_router
from agentos_server.routes_v2.agents import router as agents_router
from agentos_server.routes_v2.audit import router as audit_router
from agentos_server.routes_v2.flows import router as flows_router
from agentos_server.routes_v2.mcp_servers import router as mcp_servers_router
from agentos_server.routes_v2.node_specs import router as node_specs_router
from agentos_server.routes_v2.notify import router as notify_router
from agentos_server.routes_v2.overview import router as overview_router
from agentos_server.routes_v2.providers import router as providers_router
from agentos_server.routes_v2.sandbox import router as sandbox_router
from agentos_server.routes_v2.schedules import router as schedules_router
from agentos_server.routes_v2.squads import router as squads_router
from agentos_server.routes_v2.tools import router as tools_router
from agentos_server.routes_v2.usage import router as usage_router
from agentos_server.routes_v2.vault import router as vault_router
from agentos_server.routes_v2.webhooks import router as webhooks_router

router = APIRouter()

router.include_router(agents_router)
router.include_router(flows_router)
router.include_router(squads_router)
router.include_router(tools_router)
router.include_router(mcp_servers_router)
router.include_router(vault_router)
router.include_router(providers_router)
router.include_router(webhooks_router)
router.include_router(schedules_router)
router.include_router(node_specs_router)
router.include_router(overview_router)
router.include_router(audit_router)
router.include_router(usage_router)
router.include_router(notify_router)
router.include_router(access_router)  # 3.4: auth, users, API tokens, legacy token
router.include_router(sandbox_router)  # 3.5: sandbox status and admin settings
