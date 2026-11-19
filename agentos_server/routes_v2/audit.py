"""
Audit log endpoints (/api/v2/audit), same token auth as every /api route (3.1).

- GET /api/v2/audit          filters: action (prefix), actor, target_type, target_id, outcome, since, until;
                             newest first; cursor = before_seq; limit <= 200
- GET /api/v2/audit/verify   {status: ok|broken|empty, entries_checked, first_broken_seq, reason}
- GET /api/v2/audit/export   the chain as JSONL, exactly as stored
Entries hold metadata only (names, ids, versions, hashes, counts, rule names): never secret values or untrusted
payload text. Read-only: there is no API to change or delete audit entries.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/audit", tags=["v2-audit"])


def _log(request: Request) -> Any:
    log = getattr(request.app.state, "audit", None)
    if log is None:
        raise HTTPException(status_code=503, detail="Audit log is not configured")
    return log


@router.get("")
async def list_audit(
    request: Request,
    action: Optional[str] = Query(None, max_length=120),
    actor: Optional[str] = Query(None, max_length=64),
    target_type: Optional[str] = Query(None, max_length=64),
    target_id: Optional[str] = Query(None, max_length=200),
    outcome: Optional[str] = Query(None, pattern="^(ok|refused|failed)$"),
    since: Optional[str] = Query(None, max_length=40),
    until: Optional[str] = Query(None, max_length=40),
    before_seq: Optional[int] = Query(None, ge=1),
    limit: int = Query(50, ge=1, le=200),
) -> Dict[str, Any]:
    return await _log(request).query(action=action, actor=actor, target_type=target_type, target_id=target_id,
                                     outcome=outcome, since=since, until=until, before_seq=before_seq, limit=limit)


@router.get("/verify")
async def verify_audit(request: Request) -> Dict[str, Any]:
    return await _log(request).verify()


@router.get("/export")
async def export_audit(request: Request) -> PlainTextResponse:
    body = await _log(request).export_jsonl()
    return PlainTextResponse(body, media_type="application/x-ndjson",
                             headers={"Content-Disposition": 'attachment; filename="agentos-audit.jsonl"'})
