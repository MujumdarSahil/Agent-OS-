"""Server glue for the 3.1 audit log: route helpers (fail closed with 503), source detection, aggregated
authentication failures, and the startup / config / shutdown entries. Design: docs/evidence/3.1.md.

Rule: audited admin and security actions validate first, then ``await audit(...)`` (raises HTTP 503 when the
entry cannot be written, so the action is NOT applied), then apply. Details are metadata only.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any

from fastapi import HTTPException, Request

from agentos.audit import AuditUnavailable

logger = logging.getLogger(__name__)

AUDIT_503 = "Audit log unavailable: the action was not applied"
UI_CLIENT_HEADER = "x-agentos-client"


def source_of(request: Request) -> str:
    return "ui" if request.headers.get(UI_CLIENT_HEADER, "").lower() == "ui" else "api"


async def audit(request: Request, action: str, target_type: str, target_id: str, *, outcome: str = "ok",
                details: dict[str, Any] | None = None, source: str | None = None) -> dict[str, Any]:
    """Write the audit entry or raise 503 (fail closed: the caller must not apply the action)."""
    log = getattr(request.app.state, "audit", None)
    if log is None:
        raise HTTPException(status_code=503, detail=AUDIT_503)
    try:
        return await log.record(action, target_type, target_id, outcome=outcome, details=details,
                                actor="local-admin", source=source or source_of(request))
    except AuditUnavailable as e:
        logger.error("audit write failed for %s: %s", action, e)
        raise HTTPException(status_code=503, detail=AUDIT_503) from None


async def audit_best_effort(app: Any, action: str, target_type: str, target_id: str, *, outcome: str = "ok",
                            details: dict[str, Any] | None = None, actor: str = "system",
                            source: str = "system") -> None:
    """For events that already happened (system lifecycle, a failure after an audited action): never raises."""
    log = getattr(app.state, "audit", None)
    if log is None:
        return
    try:
        await log.record(action, target_type, target_id, outcome=outcome, details=details, actor=actor,
                         source=source)
    except AuditUnavailable as e:
        logger.error("audit write failed for %s: %s", action, e)


class AuthFailureAggregator:
    """At most one ``auth.failure`` entry per minute per source, with a count. A closed minute is written when
    the next failure arrives in a later minute; the open minute is flushed at shutdown (no timers)."""

    def __init__(self, clock: Any = time.time) -> None:
        self._clock = clock
        self._open: dict[str, tuple[int, int]] = {}  # source -> (minute, count)

    async def note(self, app: Any, source: str) -> None:
        minute = int(self._clock() // 60)
        cur = self._open.get(source)
        if cur is not None and cur[0] != minute:
            await self._write(app, source, *cur)
            cur = None
        self._open[source] = (minute, (cur[1] if cur else 0) + 1)

    async def flush(self, app: Any) -> None:
        for source, (minute, count) in list(self._open.items()):
            await self._write(app, source, minute, count)
        self._open.clear()

    @staticmethod
    async def _write(app: Any, source: str, minute: int, count: int) -> None:
        import datetime as _dt

        start = _dt.datetime.fromtimestamp(minute * 60, tz=_dt.timezone.utc).isoformat()
        await audit_best_effort(app, "auth.failure", "api", "local-token", outcome="refused",
                                details={"count": count, "window_start": start, "window_s": 60}, source=source)


_SAFE_NAME = __import__("re").compile(r"^[A-Za-z0-9_./:-]{1,64}$")


def _safe(value: Any) -> str:
    """A server-supplied name is kept only if it is a short plain identifier (otherwise 'other')."""
    return value if isinstance(value, str) and _SAFE_NAME.fullmatch(value) else "other"


def mcp_event_to_audit(type_: str, payload: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """(action, outcome, details) for an MCP manager event. Server-controlled text (tool descriptions, raw names,
    error messages) never goes into details: only AgentOS-written reasons, normalized names, counts, hashes."""
    if type_ == "mcp_server_started":
        return "mcp.server.started", "ok", {k: v for k, v in payload.items()
                                             if k in ("transport", "pid", "tools") and isinstance(v, (int, str))
                                             and (not isinstance(v, str) or _SAFE_NAME.fullmatch(v))}
    if type_ == "mcp_server_stopped":
        return "mcp.server.stopped", "ok", {"reason": _safe(str(payload.get("reason", "stopped")).replace(" ", "_"))}
    if type_ == "mcp_server_start_failed":
        return "mcp.server.start_failed", "failed", {"error": _safe(payload.get("error"))}
    if type_ == "mcp_server_request_refused":
        return "mcp.server.request_refused", "refused", {"method": _safe(payload.get("method"))}
    if type_ == "mcp_discovery":
        names = sorted(n for n in (payload.get("tools") or {}) if _SAFE_NAME.fullmatch(str(n)))
        return "mcp.server.discovered", "ok", {"tool_count": len(payload.get("tools") or {}), "tools": names[:50]}
    if type_ == "mcp_tool_changed":
        return "mcp.tool.changed", "ok", {"tool": _safe(payload.get("tool"))}
    if type_ == "mcp_tool_name_rejected":
        raw = str(payload.get("tool", ""))
        return "mcp.tool.name_rejected", "refused", {"tool_name_sha256": hashlib.sha256(raw.encode()).hexdigest()}
    if type_ == "mcp_url_blocked":
        return "mcp.server.url_blocked", "refused", {}
    return "mcp.server.event", "ok", {"type": _safe(type_)}


def mcp_event_sink(app: Any) -> Any:
    """MCPManager event sink: lifecycle events go to the audit log (they already happened: best effort)."""
    async def sink(server: str, type_: str, payload: dict[str, Any]) -> None:
        action, outcome, details = mcp_event_to_audit(type_, payload)
        await audit_best_effort(app, action, "mcp_server", server, outcome=outcome, details=details)
    return sink


def config_sha256(project_path: str) -> str | None:
    path = os.path.join(project_path, "agentos.config.yaml")
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


async def audit_startup(app: Any, project_path: str, mode: str, version: str) -> None:
    """system.startup, config.loaded (with the config file's sha256 and name-only summary), and config.changed
    when the sha256 differs from the last config.loaded entry."""
    await audit_best_effort(app, "system.startup", "system", "server", details={"mode": mode, "version": version})
    log = getattr(app.state, "audit", None)
    if log is None:
        return
    sha = config_sha256(project_path)
    policy = getattr(app.state, "security_policy", None)
    summary = {
        "config_sha256": sha or "none",
        "internal_domains": len(getattr(policy, "internal_domains", ()) or ()),
        "http_allowlist": len(getattr(policy, "http_allowlist", ()) or ()),
        "allowlist_names": sorted((getattr(policy, "allowlists", None) or {}).keys())[:50],
        "allow_declassified_for_destructive": bool(getattr(policy, "allow_declassified_for_destructive", False)),
    }
    try:
        previous = await log.last("config.loaded")
    except Exception:
        previous = None
    if previous is not None and previous["details"].get("config_sha256") != summary["config_sha256"]:
        await audit_best_effort(app, "config.changed", "config", "agentos.config.yaml", details={
            "previous_sha256": previous["details"].get("config_sha256"), "config_sha256": summary["config_sha256"],
        })
    await audit_best_effort(app, "config.loaded", "config", "agentos.config.yaml", details=summary)


async def audit_shutdown(app: Any, mode: str, version: str) -> None:
    agg = getattr(app.state, "auth_failures", None)
    if agg is not None:
        await agg.flush(app)
    await audit_best_effort(app, "system.shutdown", "system", "server", details={"mode": mode, "version": version})
