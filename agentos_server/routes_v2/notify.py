"""
Notification channels and alerts (3.3), same token auth as every /api route; admin = the local token until Phase 3
RBAC. Every change is audited BEFORE it applies (503 and nothing changes if the entry cannot be written).
Secret values are write-only: ``password`` / ``webhook_url`` go to the vault; responses only say ``*_set``.

- GET/POST /api/v2/notify/channels, PUT/DELETE /api/v2/notify/channels/{name}, POST .../{name}/test
- GET /api/v2/alerts/rules, PUT /api/v2/alerts/rules/{id}
- GET /api/v2/alerts?rule=&acknowledged=&status=&limit=, POST /api/v2/alerts/{id}/acknowledge
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import ValidationError

from agentos.notify.channels import ChannelError, EmailChannel, SlackChannel, check_slack_webhook_url, parse_channel
from agentos.notify.service import RULE_TYPES, AlertRule
from agentos_server.audit_support import audit, audit_best_effort

router = APIRouter(tags=["v2-notify"])
_SECRET_FIELDS = ("password", "webhook_url")


def _svc(request: Request) -> Any:
    svc = getattr(request.app.state, "notify", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="Notifications are not configured")
    return svc


def _meta(ch: EmailChannel | SlackChannel, secret_changed: bool) -> Dict[str, Any]:
    """Audit details: metadata only (never a secret value; the secret NAME is not a secret)."""
    if isinstance(ch, EmailChannel):
        return {"type": "email", "enabled": ch.enabled, "host": ch.host, "port": ch.port, "security": ch.security,
                "allow_insecure_local": ch.allow_insecure_local, "use_for_flows": ch.use_for_flows,
                "username_set": bool(ch.username), "password_secret": ch.password_secret,
                "allowed_recipient_domains": len(ch.allowed_recipient_domains),
                "alert_recipients": len(ch.alert_recipients), "secret_changed": secret_changed}
    return {"type": "slack", "enabled": ch.enabled, "internal": ch.internal, "webhook_secret": ch.webhook_secret,
            "secret_changed": secret_changed}


def _parse(payload: Dict[str, Any]) -> tuple[EmailChannel | SlackChannel, Optional[str]]:
    body = {k: v for k, v in payload.items() if k not in _SECRET_FIELDS + ("password_set", "webhook_set")}
    secret = payload.get("webhook_url") if body.get("type") == "slack" else payload.get("password")
    if secret is not None and (not isinstance(secret, str) or not secret or len(secret) > 2000):
        raise HTTPException(status_code=400, detail="The secret must be non-empty text")
    try:
        ch = parse_channel(body)
    except ValidationError as e:
        err = e.errors()[0]
        loc = ".".join(str(x) for x in err.get("loc", ()) if not isinstance(x, int))
        raise HTTPException(status_code=400, detail=f"Invalid channel ({loc or 'body'}): {err['msg']}") from None
    return ch, secret


async def _check(svc: Any, ch: EmailChannel | SlackChannel, secret: Optional[str]) -> None:
    try:
        await svc.check_channel(ch)
        if isinstance(ch, SlackChannel) and secret is not None:
            check_slack_webhook_url(secret)
    except ChannelError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@router.get("/notify/channels")
async def list_channels(request: Request) -> Dict[str, Any]:
    return {"channels": [c.public() for c in await _svc(request).channels()]}


@router.post("/notify/channels", status_code=201)
async def create_channel(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    ch, secret = _parse(payload)
    if await svc.channel(ch.name) is not None:
        raise HTTPException(status_code=409, detail=f"Channel {ch.name!r} already exists")
    if isinstance(ch, SlackChannel) and secret is None and not ch.webhook_secret:
        raise HTTPException(status_code=400, detail="A Slack channel needs webhook_url")
    await _check(svc, ch, secret)
    await audit(request, "notify.channel.create", "notify_channel", ch.name, details=_meta(ch, secret is not None))
    await svc.save_channel(ch, secret_value=secret)
    return (await svc.channel(ch.name)).public()


@router.put("/notify/channels/{name}")
async def update_channel(name: str, payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    old = await svc.channel(name)
    if old is None:
        raise HTTPException(status_code=404, detail=f"Channel {name!r} not found")
    payload = {**payload, "name": name, "type": old.type}
    if isinstance(old, SlackChannel):
        payload.setdefault("webhook_secret", old.webhook_secret)
    else:
        payload.setdefault("password_secret", old.password_secret)
    ch, secret = _parse(payload)
    await _check(svc, ch, secret)
    await audit(request, "notify.channel.update", "notify_channel", name, details=_meta(ch, secret is not None))
    await svc.save_channel(ch, secret_value=secret)
    return (await svc.channel(name)).public()


@router.delete("/notify/channels/{name}")
async def delete_channel(name: str, request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    ch = await svc.channel(name)
    if ch is None:
        raise HTTPException(status_code=404, detail=f"Channel {name!r} not found")
    rules = [r for r in await svc.rules() if name in r.channels]
    await audit(request, "notify.channel.delete", "notify_channel", name,
                details={"type": ch.type, "removed_from_rules": [r.id for r in rules]})
    for r in rules:
        await svc.put_rule(r.model_copy(update={"channels": [c for c in r.channels if c != name]}))
    await svc.delete_channel(name)
    return {"deleted": name}


@router.post("/notify/channels/{name}/test")
async def test_channel(name: str, request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    ch = await svc.channel(name)
    if ch is None:
        raise HTTPException(status_code=404, detail=f"Channel {name!r} not found")
    await audit(request, "notify.channel.test", "notify_channel", name, details={"type": ch.type})
    result = await svc.test_channel(name)
    await audit_best_effort(request.app, "notify.channel.test_result", "notify_channel", name,
                            outcome="ok" if result["ok"] else "failed",
                            details={"error": result.get("error")} if not result["ok"] else {},
                            actor="local-admin", source="api")
    return result


@router.get("/alerts/rules")
async def list_rules(request: Request) -> Dict[str, Any]:
    return {"rules": [{**r.model_dump(), "title": RULE_TYPES[r.id]} for r in await _svc(request).rules()]}


@router.put("/alerts/rules/{rule_id}")
async def put_rule(rule_id: str, payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    if rule_id not in RULE_TYPES:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    old = await svc.rule(rule_id)
    try:
        new = AlertRule.model_validate({**old.model_dump(), **payload, "id": rule_id})
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid rule: {e.errors()[0]['msg']}") from None
    known = {c.name for c in await svc.channels()}
    missing = [c for c in new.channels if c not in known]
    if missing:
        raise HTTPException(status_code=400, detail=f"Unknown channel(s): {', '.join(sorted(missing))[:200]}")
    await audit(request, "alert.rule.update", "alert_rule", rule_id, details={
        "old": {"enabled": old.enabled, "channels": old.channels, "cooldown_min": old.cooldown_min, **old.params},
        "new": {"enabled": new.enabled, "channels": new.channels, "cooldown_min": new.cooldown_min, **new.params},
    })
    await svc.put_rule(new)
    return {**new.model_dump(), "title": RULE_TYPES[rule_id]}


@router.get("/alerts")
async def list_alerts(
    request: Request,
    rule: Optional[str] = Query(None, max_length=40),
    acknowledged: Optional[bool] = Query(None),
    status: Optional[str] = Query(None, pattern="^(sent|pending|retrying|failed|partial|no_channel)$"),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    svc = _svc(request)
    alerts = await svc.alerts_view(rule=rule, acknowledged=acknowledged, status=status, limit=limit)
    return {"alerts": alerts, "unacknowledged": await svc.unacknowledged_count()}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge(alert_id: str, request: Request) -> Dict[str, Any]:
    svc = _svc(request)
    a = await svc.store.alerts.get(alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    await audit(request, "alert.acknowledge", "alert", alert_id, details={"rule": a.get("rule")})
    return {k: v for k, v in (await svc.acknowledge(alert_id) or {}).items() if k != "created_ts"}
