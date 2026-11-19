"""
Agent CRUD endpoints (/api/v2/agents).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request
from jsonschema import Draft202012Validator, ValidationError

from agentos.core.config_models import AgentYAMLConfig
from agentos.flows.specs import AGENT_NODE_SPEC, BUILTIN_NODE_SPECS

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agents", tags=["v2-agents"])


def validate_agent_config(config_dict: Dict[str, Any], catalog: Any = None) -> None:
    """Validate agent configuration against hardened agent schema (no mcps/apps/memory/knowledge_sources)."""
    validator = Draft202012Validator(AGENT_NODE_SPEC.config_schema)
    errors = sorted(validator.iter_errors(config_dict), key=lambda e: e.path)
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid agent config: {errors[0].message}",
        )

    # Tool validation: tools must resolve in the shared catalog (fail-closed rule). Built-ins by bare
    # name; MCP tools only as mcp.<server>.<tool> and only once an admin approved them (2.5a).
    from agentos.flows.tool_catalog import BUILTIN_CATALOG, ToolLookupError

    tools = config_dict.get("tools") or []
    for tool_name in tools:
        try:
            (catalog or BUILTIN_CATALOG).resolve(tool_name)
        except ToolLookupError as err:
            if err.reason == "not_an_agent_tool":
                detail = str(err)  # 3.2: a flow step type is not an agent tool
            else:
                detail = (
                    f"Tool '{tool_name}' has no declared NodeSpec (fail closed)"
                    if tool_name in BUILTIN_NODE_SPECS or not tool_name.startswith("mcp")
                    else f"{err} (fail closed)"
                )
            raise HTTPException(status_code=400, detail=detail)


@router.get("", response_model=List[AgentYAMLConfig])
async def list_agents(request: Request) -> List[AgentYAMLConfig]:
    storage = request.app.state.storage
    return await storage.agents.list()


@router.get("/tool-options")
async def agent_tool_options(request: Request) -> List[Dict[str, Any]]:
    """3.1: tools the agent picker may offer. Same ToolCatalog the save path resolves against (built-in agent
    tools + approved MCP tools of enabled servers), so the UI never offers a tool the server would refuse."""
    from agentos.flows.tool_catalog import ToolCatalog

    storage = request.app.state.storage
    records = await storage.mcp_servers.list() if getattr(storage, "mcp_servers", None) is not None else []
    out = []
    for e in ToolCatalog(records).agent_tool_options():
        out.append({
            "name": e.name,
            "kind": "mcp" if e.is_mcp else "builtin",
            "side_effect": e.spec.side_effect.value,
            "server": e.server,
            # admin-written text only: an MCP tool's own (untrusted) description is never shown as a label here
            "description": e.admin_description or "",
        })
    return out


@router.get("/{name}", response_model=AgentYAMLConfig)
async def get_agent(name: str, request: Request) -> AgentYAMLConfig:
    storage = request.app.state.storage
    agent = await storage.agents.get(name)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")
    return agent


@router.post("", response_model=AgentYAMLConfig)
async def put_agent(payload: Dict[str, Any], request: Request) -> AgentYAMLConfig:
    storage = request.app.state.storage

    # 1. Resolve tools
    tools = payload.get("tools") or payload.get("tool_refs") or []

    # 2. Build config dict for schema validation (matching AGENT_NODE_SPEC.config_schema)
    config_to_validate = {
        "role": payload.get("role", ""),
        "goal": payload.get("goal", ""),
        "backstory": payload.get("backstory", ""),
        "tools": tools,
        "verbose": payload.get("verbose", False),
        "llm": payload.get("llm", "agentos-default"),
    }
    for flag in ("cache", "allow_delegation", "allow_code_execution"):
        if flag in payload:
            config_to_validate[flag] = payload[flag]

    # Include any unexpected fields to let additionalProperties: false catch them
    STORAGE_METADATA_KEYS = {"name", "description", "type", "llm_tags", "tool_refs", "tools"}
    for k, v in payload.items():
        if k not in STORAGE_METADATA_KEYS and k not in config_to_validate:
            config_to_validate[k] = v

    catalog = None
    if any(str(t).startswith("mcp") for t in tools):
        from agentos.flows.tool_catalog import ToolCatalog

        catalog = ToolCatalog(await storage.mcp_servers.list())
    validate_agent_config(config_to_validate, catalog)

    # 3. Construct AgentYAMLConfig for storage
    storage_dict = {
        "name": payload.get("name"),
        "role": payload.get("role"),
        "goal": payload.get("goal"),
        "backstory": payload.get("backstory", ""),
        "type": payload.get("type", "Agent"),
        "llm_tags": payload.get("llm_tags", []),
        "tool_refs": tools,
        "memory_ref": payload.get("memory_ref"),
    }
    storage_dict = {k: v for k, v in storage_dict.items() if v is not None}

    try:
        agent_record = AgentYAMLConfig(**storage_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    await storage.agents.put(agent_record)
    return agent_record


@router.delete("/{name}")
async def delete_agent(name: str, request: Request) -> Dict[str, bool]:
    storage = request.app.state.storage
    deleted = await storage.agents.delete(name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")
    return {"deleted": True}
