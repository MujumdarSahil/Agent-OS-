"""
MCP Server endpoints (/api/v2/mcp-servers). Same token auth as every /api route (admin = local token
in Phase 2).

- CRUD. A save never overwrites discovered tools or approvals; changing the launch target (transport,
  command, args, url) disables the server, and every approval pinned to the old target needs review.
  ``env`` names are validated (no AGENTOS_*, no provider key variables: those go through secret_env).
- GET  /{name}/launch-preview      exact command line (or URL) that enabling will allow, env NAMES only
- POST /{name}/enable              {"enabled": bool}; returns the record and the preview
- POST /{name}/discover            enabled servers only; stores an UNTRUSTED snapshot per tool
- POST /{name}/tools/{tool}/approve   admin review (side effect, sink rules, confidentiality, description)
- POST /{name}/tools/{tool}/revoke
Tool descriptions and schemas in responses are server-controlled UNTRUSTED data; the UI shows them only
as plain text.
"""

from __future__ import annotations

import logging
import shlex
import sys
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from agentos.flows.net_guard import SSRFBlockedError
from agentos.flows.specs import BUILTIN_NODE_SPECS
from agentos.mcp.catalog import canonical_name, target_fingerprint, tool_status, wire_name
from agentos.mcp.env import FIXED, POSIX_COPIED, WINDOWS_COPIED, MCPEnvError, server_dir, validate_env_names
from agentos.storage.models import MCPServerRecord, MCPToolApproval
from agentos_server.audit_support import audit, audit_best_effort, source_of

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mcp-servers", tags=["v2-mcp-servers"])


class EnableBody(BaseModel):
    enabled: bool


class ApproveBody(BaseModel):
    expected_sha256: str = Field(..., min_length=64, max_length=64)  # the snapshot the admin reviewed
    side_effect: Literal["read", "write", "external_send", "destructive"]
    untrusted_ok_args: List[str] = Field(default_factory=list)
    sink_rules: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    output_confidentiality: Literal["public", "internal", "confidential", "secret"] = "internal"
    replacement_description: Optional[str] = Field(default=None, max_length=4000)


def _view(rec: MCPServerRecord) -> Dict[str, Any]:
    out = rec.model_dump(mode="json")
    for norm, state in rec.tools.items():
        t = out["tools"][norm]
        t["status"] = tool_status(rec, state)
        t["canonical_name"] = canonical_name(rec.name, norm)
        t["wire_name"] = wire_name(rec.name, norm)
    return out


def _preview(rec: MCPServerRecord, request: Request) -> Dict[str, Any]:
    base: Dict[str, Any] = {"transport": rec.transport, "target_fingerprint": target_fingerprint(rec)}
    if rec.transport == "stdio":
        project = getattr(request.app.state, "project_path", None) or "."
        essentials = list(WINDOWS_COPIED if sys.platform == "win32" else POSIX_COPIED)
        home_vars = (["USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"] if sys.platform == "win32"
                     else ["HOME", "TMPDIR", "LANG"])
        base.update({
            "command_line": shlex.join([rec.command or "", *rec.args]),
            "argv": [rec.command or "", *rec.args],
            "cwd": str(server_dir(project, rec.name)),
            "env_names": sorted(set(essentials) | set(home_vars) | set(FIXED) | set(rec.env)),
            "secret_env": dict(rec.secret_env),  # env var -> vault NAME (never a value)
            "inherits_parent_env": False,
        })
    else:
        base["url"] = rec.url
        if rec.transport == "sse":
            base["note"] = "sse is not supported (deprecated in the MCP spec); use the streamable http transport"
    return base


async def _get(request: Request, name: str) -> MCPServerRecord:
    rec = await request.app.state.storage.mcp_servers.get(name)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"MCP Server '{name}' not found")
    return rec


def _manager(request: Request) -> Any:
    return getattr(request.app.state, "mcp_manager", None)


@router.get("")
async def list_mcp_servers(request: Request) -> List[Dict[str, Any]]:
    return [_view(r) for r in await request.app.state.storage.mcp_servers.list()]


@router.get("/{name}")
async def get_mcp_server(name: str, request: Request) -> Dict[str, Any]:
    return _view(await _get(request, name))


@router.post("")
async def put_mcp_server(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    storage = request.app.state.storage
    data = {k: v for k, v in payload.items() if k not in ("tools", "last_discovery")}
    try:
        record = MCPServerRecord(**data)
        validate_env_names(record.env, record.secret_env)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    existing = await storage.mcp_servers.get(record.name)
    target_changed = existing is not None and target_fingerprint(existing) != target_fingerprint(record)
    # 3.1: names, transport, env NAMES and the target fingerprint only (never env values or URLs with tokens)
    await audit(request, "mcp.server.update" if existing is not None else "mcp.server.create", "mcp_server",
                record.name, details={
                    "transport": record.transport, "target_fingerprint": target_fingerprint(record),
                    "env_names": sorted(record.env)[:50], "secret_env_names": sorted(record.secret_env)[:50],
                    "target_changed": target_changed,
                })
    if existing is not None:
        update: Dict[str, Any] = {"tools": existing.tools, "last_discovery": existing.last_discovery}
        if target_fingerprint(existing) != target_fingerprint(record):
            # a different program or URL: never inherit "enabled"; approvals pinned to the old target need review
            update["enabled"] = False
            if _manager(request) is not None:
                await _manager(request).stop(record.name, "target changed")
        record = record.model_copy(update=update)
    await storage.mcp_servers.put(record)
    return _view(record)


@router.delete("/{name}")
async def delete_mcp_server(name: str, request: Request) -> Dict[str, bool]:
    await _get(request, name)
    await audit(request, "mcp.server.delete", "mcp_server", name)
    if _manager(request) is not None:
        await _manager(request).stop(name, "deleted")
    deleted = await request.app.state.storage.mcp_servers.delete(name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"MCP Server '{name}' not found")
    return {"deleted": True}


@router.get("/{name}/launch-preview")
async def launch_preview(name: str, request: Request) -> Dict[str, Any]:
    return _preview(await _get(request, name), request)


@router.post("/{name}/enable")
async def enable_mcp_server(name: str, body: EnableBody, request: Request) -> Dict[str, Any]:
    rec = (await _get(request, name)).model_copy(update={"enabled": body.enabled})
    await audit(request, "mcp.server.enable" if body.enabled else "mcp.server.disable", "mcp_server", name,
                details={"target_fingerprint": target_fingerprint(rec), "transport": rec.transport})
    await request.app.state.storage.mcp_servers.put(rec)
    manager = _manager(request)
    if manager is not None and not body.enabled:
        await manager.stop(name, "disabled")
    return {"server": _view(rec), "launch_preview": _preview(rec, request)}


@router.post("/{name}/discover")
async def discover_mcp_server(name: str, request: Request) -> Dict[str, Any]:
    from agentos.mcp.manager import MCPServerUnavailable, MCPTimeout

    rec = await _get(request, name)
    if not rec.enabled:
        raise HTTPException(status_code=409, detail=f"MCP server '{name}' is not enabled; enable it first")
    if rec.transport == "sse":
        raise HTTPException(status_code=400, detail="sse is not supported (deprecated in the MCP spec); use http")
    manager = _manager(request)
    await audit(request, "mcp.server.discover", "mcp_server", name, details={"transport": rec.transport})
    try:
        discovered = await manager.discover(rec, builtin_names=BUILTIN_NODE_SPECS.keys())
    except SSRFBlockedError as e:
        await manager.event(name, "mcp_url_blocked", {"reason": str(e)[:300]})
        raise HTTPException(status_code=400, detail=f"MCP server URL blocked: {e}")
    except MCPTimeout as e:
        raise HTTPException(status_code=504, detail=str(e))
    except (MCPServerUnavailable, MCPEnvError) as e:
        raise HTTPException(status_code=502, detail=str(e))
    current = await request.app.state.storage.mcp_servers.get(name) or rec
    updated = current.model_copy(update={"tools": discovered.tools, "last_discovery": discovered.last_discovery})
    await request.app.state.storage.mcp_servers.put(updated)
    return _view(updated)


@router.post("/{name}/tools/{tool}/approve")
async def approve_tool(name: str, tool: str, body: ApproveBody, request: Request) -> Dict[str, Any]:
    rec = await _get(request, name)
    state = rec.tools.get(tool)
    if state is None or state.missing:
        raise HTTPException(status_code=404, detail=f"Tool '{tool}' is not offered by '{name}'; run discovery")
    if body.expected_sha256 != state.snapshot.sha256:
        raise HTTPException(status_code=409, detail="The tool changed since you reviewed it; review it again")
    props = set((state.snapshot.input_schema or {}).get("properties") or {})
    unknown = [a for a in list(body.untrusted_ok_args) + list(body.sink_rules) if a not in props]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown argument(s) for this tool: {unknown}")
    approval = MCPToolApproval(
        approved_sha256=state.snapshot.sha256,
        target_fingerprint=target_fingerprint(rec),
        side_effect=body.side_effect,
        sink_rules=body.sink_rules,
        untrusted_ok_args=body.untrusted_ok_args,
        output_confidentiality=body.output_confidentiality,
        replacement_description=(body.replacement_description or None),
    )
    tools = dict(rec.tools)
    tools[tool] = state.model_copy(update={"approval": approval})
    rec = rec.model_copy(update={"tools": tools})
    await audit(request, "mcp.tool.approve", "mcp_tool", canonical_name(name, tool), details={
        "server": name, "tool": tool, "snapshot_sha256": approval.approved_sha256,
        "side_effect": approval.side_effect, "output_confidentiality": approval.output_confidentiality,
        "untrusted_ok_args": sorted(approval.untrusted_ok_args)[:50],
        "admin_description": approval.replacement_description is not None,
    })
    await request.app.state.storage.mcp_servers.put(rec)
    return _view(rec)


@router.post("/{name}/tools/{tool}/revoke")
async def revoke_tool(name: str, tool: str, request: Request) -> Dict[str, Any]:
    rec = await _get(request, name)
    state = rec.tools.get(tool)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Tool '{tool}' not found on '{name}'")
    tools = dict(rec.tools)
    tools[tool] = state.model_copy(update={"approval": None})
    rec = rec.model_copy(update={"tools": tools})
    await audit(request, "mcp.tool.revoke", "mcp_tool", canonical_name(name, tool), details={"server": name, "tool": tool})
    await request.app.state.storage.mcp_servers.put(rec)
    return _view(rec)
