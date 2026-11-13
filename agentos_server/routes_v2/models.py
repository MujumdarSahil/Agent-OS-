"""
Pydantic schemas for the AgentOS /api/v2 REST endpoints.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class SecretInfoResponse(BaseModel):
    name: str
    provider: Optional[str] = None
    hint: str
    key_id: str
    created_at: str
    updated_at: str


class VaultPutRequest(BaseModel):
    name: str = Field(..., min_length=1)
    secret: str = Field(..., min_length=1)
    provider: Optional[str] = None


class V2ProviderStatusResponse(BaseModel):
    name: str
    display_name: str
    litellm_model: str
    priority: int
    tags: List[str]
    api_key_configured: bool
    api_key_env: Optional[str] = None
    api_base_env: Optional[str] = None
    is_local: bool


class ProviderTestRequest(BaseModel):
    provider_name: str
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None


class ProviderTestResult(BaseModel):
    ok: bool
    error_class: Optional[str] = None
    message: Optional[str] = None


class FallbackPolicyItem(BaseModel):
    name: str
    order: int
    enabled: bool = True
    timeout_s: Optional[float] = None
    display_name: Optional[str] = None
    litellm_model: Optional[str] = None


class FallbackPolicyUpdateRequest(BaseModel):
    items: List[FallbackPolicyItem]
