"""
Provider management and fallback policy endpoints (/api/v2/providers).
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request

from agentos.llm.provider_registry import PROVIDER_REGISTRY
from agentos.llm.router_factory import set_fallback_policy_cache
from agentos.storage.models import ProviderConfigRecord
from agentos_server.routes_v2.models import (
    FallbackPolicyItem,
    FallbackPolicyUpdateRequest,
    ProviderTestRequest,
    ProviderTestResult,
    V2ProviderStatusResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/providers", tags=["v2-providers"])


@router.get("", response_model=List[V2ProviderStatusResponse])
async def list_providers(request: Request) -> List[V2ProviderStatusResponse]:
    """
    Returns provider catalog annotated with configuration status.
    DOES NO NETWORK CALLS (reachability is verified exclusively via test-connection).
    """
    vault = request.app.state.vault
    vault_keys = {item.name: item for item in await vault.list()}

    result: List[V2ProviderStatusResponse] = []
    for prov in PROVIDER_REGISTRY:
        name = prov["name"]
        is_local = "local" in prov.get("tags", []) or name.startswith("ollama")
        api_key_env = prov.get("api_key_env")

        # Key configured check: in vault or in environment
        api_key_configured = is_local
        if not api_key_configured:
            if name in vault_keys or (api_key_env and os.environ.get(api_key_env, "").strip()):
                api_key_configured = True

        result.append(
            V2ProviderStatusResponse(
                name=name,
                display_name=prov.get("display_name", name),
                litellm_model=prov["litellm_model"],
                priority=prov["priority"],
                tags=prov["tags"],
                api_key_configured=api_key_configured,
                api_key_env=api_key_env,
                api_base_env=prov.get("api_base_env"),
                is_local=is_local,
            )
        )
    return result


@router.post("/test-connection", response_model=ProviderTestResult)
async def test_connection(req: ProviderTestRequest, request: Request) -> ProviderTestResult:
    """
    Server-side connectivity test for a specific provider.
    Security:
    - Only calls registry-known provider endpoints or localhost Ollama (SSRF defense).
    - Returns ONLY ok/error and error class. NEVER returns the key or raw response body.
    """
    provider = next((p for p in PROVIDER_REGISTRY if p["name"] == req.provider_name), None)
    if not provider:
        raise HTTPException(
            status_code=400,
            detail=f"Provider '{req.provider_name}' is not recognized in the provider registry (SSRF prevention)",
        )

    # 1. Resolve key: passed in request or retrieved from vault or environment
    api_key = req.api_key
    if not api_key:
        vault = request.app.state.vault
        try:
            api_key = await vault.reveal(req.provider_name)
        except Exception:
            if provider.get("api_key_env"):
                api_key = os.environ.get(provider["api_key_env"], "").strip()

    is_local = "local" in provider.get("tags", []) or req.provider_name.startswith("ollama")
    if not is_local and not api_key and os.environ.get("AGENTOS_MOCK_LLM") != "1":
        return ProviderTestResult(
            ok=False,
            error_class="MissingCredentialsError",
            message=f"No API key configured for provider '{req.provider_name}'",
        )

    # 2. Mock mode handling
    if os.environ.get("AGENTOS_MOCK_LLM") == "1":
        # Simulate quick successful probe
        return ProviderTestResult(ok=True)

    # 3. Live connectivity probe
    try:
        import litellm

        kwargs = {
            "model": provider["litellm_model"],
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "timeout": 10.0,
        }
        if api_key:
            kwargs["api_key"] = api_key
        if req.api_base_url:
            # Only allow localhost/127.0.0.1 for custom base URLs in 1.4
            if not req.api_base_url.startswith(("http://localhost", "http://127.0.0.1", "https://localhost", "https://127.0.0.1")):
                raise ValueError("Custom base URLs are restricted to localhost/127.0.0.1")
            kwargs["api_base"] = req.api_base_url

        litellm.completion(**kwargs)
        return ProviderTestResult(ok=True)
    except Exception as err:
        error_class = err.__class__.__name__
        msg = str(err)
        # Redact any accidental secret values from error message
        if api_key and api_key in msg:
            msg = msg.replace(api_key, "[REDACTED]")
        return ProviderTestResult(ok=False, error_class=error_class, message=msg)


@router.get("/fallback", response_model=List[FallbackPolicyItem])
async def get_fallback_policy(request: Request) -> List[FallbackPolicyItem]:
    """Returns the persistent fallback policy."""
    storage = request.app.state.storage
    records = await storage.provider_configs.list()
    if records:
        sorted_records = sorted(records, key=lambda r: r.order)
        result: List[FallbackPolicyItem] = []
        for r in sorted_records:
            prov = next((p for p in PROVIDER_REGISTRY if p["name"] == r.name), None)
            result.append(
                FallbackPolicyItem(
                    name=r.name,
                    order=r.order,
                    enabled=r.enabled,
                    timeout_s=r.timeout_s,
                    display_name=prov.get("display_name", r.name) if prov else r.name,
                    litellm_model=prov.get("litellm_model") if prov else None,
                )
            )
        return result

    # Default policy from PROVIDER_REGISTRY order
    default_items: List[FallbackPolicyItem] = []
    for idx, prov in enumerate(PROVIDER_REGISTRY):
        default_items.append(
            FallbackPolicyItem(
                name=prov["name"],
                order=idx + 1,
                enabled=True,
                timeout_s=None,
                display_name=prov.get("display_name", prov["name"]),
                litellm_model=prov["litellm_model"],
            )
        )
    return default_items


@router.put("/fallback", response_model=List[FallbackPolicyItem])
async def update_fallback_policy(
    req: FallbackPolicyUpdateRequest, request: Request
) -> List[FallbackPolicyItem]:
    """
    Updates the fallback policy: persists to storage and updates in-memory router cache.
    """
    storage = request.app.state.storage

    # 1. Persist each provider config record to storage
    for item in req.items:
        record = ProviderConfigRecord(
            name=item.name,
            order=item.order,
            enabled=item.enabled,
            timeout_s=item.timeout_s,
        )
        await storage.provider_configs.put(record)

    # 2. Update the in-memory fallback policy cache for the synchronous router hook
    set_fallback_policy_cache([item.model_dump() for item in req.items])
    request.app.state.fallback_policy_cache = req.items

    return req.items
