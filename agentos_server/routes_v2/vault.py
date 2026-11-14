"""
Credentials Vault endpoints (/api/v2/vault).
"""

from __future__ import annotations

import logging
from typing import Dict, List

from fastapi import APIRouter, HTTPException, Request

from agentos_server.routes_v2.models import SecretInfoResponse, VaultPutRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/vault", tags=["v2-vault"])


@router.get("/keys", response_model=List[SecretInfoResponse])
async def list_vault_keys(request: Request) -> List[SecretInfoResponse]:
    vault = request.app.state.vault
    items = await vault.list()
    # Masked form only; plaintext and ciphertext are NEVER returned
    return [
        SecretInfoResponse(
            name=item.name,
            provider=item.provider,
            hint=item.hint,
            key_id=item.key_id,
            created_at=item.created_at.isoformat() if hasattr(item.created_at, "isoformat") else str(item.created_at),
            updated_at=item.updated_at.isoformat() if hasattr(item.updated_at, "isoformat") else str(item.updated_at),
        )
        for item in items
    ]


@router.post("/keys", response_model=SecretInfoResponse)
async def put_vault_key(req: VaultPutRequest, request: Request) -> SecretInfoResponse:
    vault = request.app.state.vault
    if not req.secret.strip():
        raise HTTPException(status_code=400, detail="Secret must not be empty")

    info = await vault.put(req.name, req.secret.strip(), req.provider)
    return SecretInfoResponse(
        name=info.name,
        provider=info.provider,
        hint=info.hint,
        key_id=info.key_id,
        created_at=info.created_at.isoformat() if hasattr(info.created_at, "isoformat") else str(info.created_at),
        updated_at=info.updated_at.isoformat() if hasattr(info.updated_at, "isoformat") else str(info.updated_at),
    )


@router.delete("/keys/{name}")
async def delete_vault_key(name: str, request: Request) -> Dict[str, bool]:
    vault = request.app.state.vault
    deleted = await vault.delete(name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Secret '{name}' not found")
    return {"deleted": True}
