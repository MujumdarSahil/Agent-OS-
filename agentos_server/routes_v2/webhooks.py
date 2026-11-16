"""
CRUD API endpoints for Webhook triggers under /api/v2/webhooks.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from agentos.storage.models import WebhookRecord, utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class CreateWebhookRequest(BaseModel):
    name: str = Field(..., min_length=1)
    flow_id: str = Field(..., min_length=1)
    rate_limit_per_minute: int = 60


class UpdateWebhookRequest(BaseModel):
    name: Optional[str] = None
    flow_id: Optional[str] = None
    rate_limit_per_minute: Optional[int] = None
    enabled: Optional[bool] = None


class WebhookResponse(BaseModel):
    webhook_id: str
    name: str
    flow_id: str
    rate_limit_per_minute: int
    enabled: bool
    created_at: Any
    updated_at: Any
    secret_path_hash: str
    secret_path: Optional[str] = None  # Returned ONLY on create or rotate
    secret_key: Optional[str] = None   # Returned ONLY on create or rotate


@router.post("", response_model=WebhookResponse, status_code=201)
async def create_webhook(req: CreateWebhookRequest, request: Request) -> WebhookResponse:
    storage = request.app.state.storage
    vault = request.app.state.vault

    if not storage.webhooks:
        raise HTTPException(status_code=500, detail="Webhook storage repository unavailable")

    # Verify flow exists
    if storage.flows:
        flow = await storage.flows.get_draft(req.flow_id)
        if not flow:
            raise HTTPException(status_code=404, detail=f"Flow {req.flow_id!r} not found")

    webhook_id = f"wh_{uuid.uuid4().hex[:12]}"
    # Secret path: random >= 128 bits (token_urlsafe(24) = 192 bits of entropy)
    secret_path = secrets.token_urlsafe(24)
    secret_path_hash = hashlib.sha256(secret_path.encode("utf-8")).hexdigest()

    # Secret key for HMAC: 256 bits
    secret_key = secrets.token_hex(32)
    secret_key_ref = f"wh_key_{uuid.uuid4().hex[:16]}"
    await vault.put(secret_key_ref, secret_key)

    record = WebhookRecord(
        webhook_id=webhook_id,
        name=req.name,
        flow_id=req.flow_id,
        secret_path_hash=secret_path_hash,
        secret_key_ref=secret_key_ref,
        rate_limit_per_minute=req.rate_limit_per_minute,
        enabled=True,
    )
    await storage.webhooks.put(record)

    return WebhookResponse(
        webhook_id=record.webhook_id,
        name=record.name,
        flow_id=record.flow_id,
        rate_limit_per_minute=record.rate_limit_per_minute,
        enabled=record.enabled,
        created_at=record.created_at,
        updated_at=record.updated_at,
        secret_path_hash=record.secret_path_hash,
        secret_path=secret_path,
        secret_key=secret_key,
    )


@router.get("", response_model=List[WebhookResponse])
async def list_webhooks(request: Request) -> List[WebhookResponse]:
    storage = request.app.state.storage
    if not storage.webhooks:
        return []
    hooks = await storage.webhooks.list()
    return [
        WebhookResponse(
            webhook_id=h.webhook_id,
            name=h.name,
            flow_id=h.flow_id,
            rate_limit_per_minute=h.rate_limit_per_minute,
            enabled=h.enabled,
            created_at=h.created_at,
            updated_at=h.updated_at,
            secret_path_hash=h.secret_path_hash,
        )
        for h in hooks
    ]


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(webhook_id: str, request: Request) -> WebhookResponse:
    storage = request.app.state.storage
    if not storage.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    hook = await storage.webhooks.get(webhook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return WebhookResponse(
        webhook_id=hook.webhook_id,
        name=hook.name,
        flow_id=hook.flow_id,
        rate_limit_per_minute=hook.rate_limit_per_minute,
        enabled=hook.enabled,
        created_at=hook.created_at,
        updated_at=hook.updated_at,
        secret_path_hash=hook.secret_path_hash,
    )


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(webhook_id: str, req: UpdateWebhookRequest, request: Request) -> WebhookResponse:
    storage = request.app.state.storage
    if not storage.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    hook = await storage.webhooks.get(webhook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    if req.name is not None:
        hook.name = req.name
    if req.flow_id is not None:
        hook.flow_id = req.flow_id
    if req.rate_limit_per_minute is not None:
        hook.rate_limit_per_minute = req.rate_limit_per_minute
    if req.enabled is not None:
        hook.enabled = req.enabled
    hook.updated_at = utcnow()

    await storage.webhooks.put(hook)
    return WebhookResponse(
        webhook_id=hook.webhook_id,
        name=hook.name,
        flow_id=hook.flow_id,
        rate_limit_per_minute=hook.rate_limit_per_minute,
        enabled=hook.enabled,
        created_at=hook.created_at,
        updated_at=hook.updated_at,
        secret_path_hash=hook.secret_path_hash,
    )


@router.post("/{webhook_id}/rotate", response_model=WebhookResponse)
async def rotate_webhook(webhook_id: str, request: Request) -> WebhookResponse:
    storage = request.app.state.storage
    vault = request.app.state.vault
    if not storage.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    hook = await storage.webhooks.get(webhook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    new_secret_path = secrets.token_urlsafe(24)
    new_secret_path_hash = hashlib.sha256(new_secret_path.encode("utf-8")).hexdigest()
    new_secret_key = secrets.token_hex(32)

    await vault.put(hook.secret_key_ref, new_secret_key)
    hook.secret_path_hash = new_secret_path_hash
    hook.updated_at = utcnow()
    await storage.webhooks.put(hook)

    return WebhookResponse(
        webhook_id=hook.webhook_id,
        name=hook.name,
        flow_id=hook.flow_id,
        rate_limit_per_minute=hook.rate_limit_per_minute,
        enabled=hook.enabled,
        created_at=hook.created_at,
        updated_at=hook.updated_at,
        secret_path_hash=hook.secret_path_hash,
        secret_path=new_secret_path,
        secret_key=new_secret_key,
    )


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(webhook_id: str, request: Request) -> None:
    storage = request.app.state.storage
    vault = request.app.state.vault
    if not storage.webhooks:
        raise HTTPException(status_code=404, detail="Webhook not found")
    hook = await storage.webhooks.get(webhook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    try:
        await vault.delete(hook.secret_key_ref)
    except Exception:
        pass

    deleted = await storage.webhooks.delete(webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
