"""Sandbox status and admin settings (/api/v2/sandbox) (3.5). Design: docs/evidence/3.5.md.

Every change is audited BEFORE it applies (fail closed: 503 and nothing changes if the audit store is down):
``sandbox.settings.update`` (old and new values), ``sandbox.wasm.install``, ``sandbox.test``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from agentos.sandbox import SandboxError, SandboxSettings
from agentos_server.audit_support import audit

router = APIRouter(prefix="/sandbox", tags=["v2-sandbox"])

TEST_CODE = "print(6 * 7)"


def _svc(request: Request) -> Any:
    svc = getattr(request.app.state, "sandbox", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="The sandbox service is not configured in this server")
    return svc


@router.get("/status")
async def sandbox_status(request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    s = await svc.get_settings()
    return await asyncio.to_thread(svc.status, s)


@router.get("/settings")
async def get_sandbox_settings(request: Request) -> Dict[str, Any]:
    return (await _svc(request).get_settings()).model_dump()


@router.put("/settings")
async def put_sandbox_settings(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    try:
        new = SandboxSettings.model_validate(payload)
    except ValidationError as e:
        err = e.errors()[0]
        where = ".".join(str(x) for x in err.get("loc", ()))
        raise HTTPException(status_code=400, detail=f"Invalid sandbox settings{' (' + where + ')' if where else ''}: "
                                                    f"{err['msg']}")
    old = await svc.get_settings()
    await audit(request, "sandbox.settings.update", "sandbox_settings", "sandbox",
                details={"old": old.flat(), "new": new.flat()})
    await svc.put_settings(new)
    return new.model_dump()


@router.post("/test")
async def test_sandbox(request: Request) -> Dict[str, Any]:
    """Runs a harmless check (``print(6 * 7)``) on the backend that would run Python now."""
    svc = _svc(request)
    await svc.get_settings()
    try:
        res = await asyncio.to_thread(svc.run, "python", TEST_CODE, {}, None, "sandbox-test")
        ok = res.exit_code == 0 and res.stdout.strip() == "42"
        out = {"ok": ok, **res.summary(), "stdout": res.stdout[:200], "stderr": res.stderr[-500:]}
    except SandboxError as e:
        out = {"ok": False, "error": str(e), "backend": None}
    await audit(request, "sandbox.test", "sandbox", out.get("backend") or "none",
                details={"ok": out["ok"], "backend": out.get("backend"), "limit_hit": out.get("limit_hit")})
    return out


@router.post("/wasm/install")
async def install_wasm(request: Request) -> Dict[str, Any]:
    """Download the pinned CPython WASI build and verify its sha256 (refused and deleted on mismatch)."""
    from agentos.sandbox.wasm_build import WASM_SHA256, WASM_URL, WasmBuildError, install

    svc = _svc(request)
    await audit(request, "sandbox.wasm.install", "sandbox", "wasm", details={"url": WASM_URL, "sha256": WASM_SHA256})
    try:
        path = await asyncio.to_thread(install, svc.data_dir)
    except (WasmBuildError, OSError) as e:
        raise HTTPException(status_code=502, detail=f"wasm runtime install failed: {str(e)[:300]}")
    return {"installed": True, "sha256": WASM_SHA256, "file": path.name, "wasm": svc.wasm.status()}
