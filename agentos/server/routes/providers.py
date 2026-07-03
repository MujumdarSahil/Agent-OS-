"""
LLM Provider management routes.
"""
import logging
import os
import time
import requests
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, HTTPException, Request
import litellm

from agentos.llm.provider_registry import PROVIDER_REGISTRY
from agentos.llm.router_factory import build_router
from agentos.server.models import (
    ProviderStatusResponse,
    ProviderKeysRequest,
    ProviderKeysResponse,
    FallbackChainItem,
    ProviderTestResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["providers"])


def check_ollama_reachable_live(base_url: Optional[str] = None) -> bool:
    """
    Live connectivity probe to check if Ollama is reachable without caching.
    """
    if not base_url:
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").strip()
    if not base_url:
        base_url = "http://localhost:11434"
    try:
        response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=1.0)
        if response.status_code == 200:
            return True
    except Exception:
        pass
    return False


def get_provider_by_model(litellm_model: str) -> Optional[Dict[str, Any]]:
    # Exact match first
    for p in PROVIDER_REGISTRY:
        if p["litellm_model"] == litellm_model:
            return p
    # For openai_compatible custom models
    if litellm_model.startswith("openai/"):
        for p in PROVIDER_REGISTRY:
            if p["name"] == "openai_compatible":
                return p
    return None


@router.get("/providers", response_model=List[ProviderStatusResponse])
async def get_providers(request: Request):
    """
    Returns the full PROVIDER_REGISTRY list, annotated with live status for each entry.
    """
    ollama_reachable = check_ollama_reachable_live()
    failed_providers = getattr(request.app.state, "failed_providers", set())

    result = []
    for prov in PROVIDER_REGISTRY:
        name = prov["name"]
        is_local = "local" in prov.get("tags", []) or name.startswith("ollama")
        api_key_env = prov["api_key_env"]
        api_base_env = prov["api_base_env"]

        # Check if key is configured
        api_key_configured = False
        if api_key_env:
            key_val = os.environ.get(api_key_env, "").strip()
            api_key_configured = bool(key_val)
        else:
            api_key_configured = True  # Local doesn't need key

        # Determine status
        if name in failed_providers:
            status = "probe_failed"
        elif is_local:
            status = "active" if ollama_reachable else "probe_failed"
        else:
            status = "active" if api_key_configured else "unconfigured"

        result.append(
            ProviderStatusResponse(
                name=name,
                litellm_model=prov["litellm_model"],
                priority=prov["priority"],
                tags=prov["tags"],
                api_key_configured=api_key_configured,
                api_key_env=api_key_env,
                api_base_env=api_base_env,
                status=status,
                is_local=is_local,
            )
        )

    return result


@router.post("/providers/keys", response_model=ProviderKeysResponse)
async def save_provider_keys(req: ProviderKeysRequest, request: Request):
    """
    Writes the key to the project's .env file.
    Security note: this writes to the disk .env file and is only intended for local dev use.
    """
    project_path = request.app.state.project_path
    dotenv_path = os.path.join(project_path, ".env")

    # Find provider in registry
    provider = next((p for p in PROVIDER_REGISTRY if p["name"] == req.provider_name), None)
    if not provider:
        raise HTTPException(status_code=400, detail=f"Provider '{req.provider_name}' not found in registry")

    from dotenv import set_key

    # Save key
    key_env_var = provider.get("api_key_env")
    if key_env_var and req.api_key:
        set_key(dotenv_path, key_env_var, req.api_key)
        os.environ[key_env_var] = req.api_key

    # Save base URL
    base_env_var = provider.get("api_base_env")
    if base_env_var and req.api_base_url:
        set_key(dotenv_path, base_env_var, req.api_base_url)
        os.environ[base_env_var] = req.api_base_url

    # Save custom model name for openai_compatible
    if req.provider_name == "openai_compatible" and req.model_name:
        set_key(dotenv_path, "OPENAI_COMPATIBLE_MODEL_NAME", req.model_name)
        os.environ["OPENAI_COMPATIBLE_MODEL_NAME"] = req.model_name

    # Clear router factory cached check
    from agentos.llm.router_factory import check_ollama_reachable
    check_ollama_reachable.cache_clear()

    # Clear failed provider status upon update
    failed_providers = getattr(request.app.state, "failed_providers", set())
    failed_providers.discard(req.provider_name)

    return ProviderKeysResponse(
        success=True,
        provider_name=req.provider_name,
        key_env_var=key_env_var,
    )


@router.delete("/providers/keys/{provider_name}")
async def delete_provider_keys(provider_name: str, request: Request):
    """
    Removes (blanks out) the key for that provider from .env.
    """
    project_path = request.app.state.project_path
    dotenv_path = os.path.join(project_path, ".env")

    provider = next((p for p in PROVIDER_REGISTRY if p["name"] == provider_name), None)
    if not provider:
        raise HTTPException(status_code=400, detail=f"Provider '{provider_name}' not found")

    from dotenv import unset_key

    # Remove key
    key_env_var = provider.get("api_key_env")
    if key_env_var:
        unset_key(dotenv_path, key_env_var)
        os.environ.pop(key_env_var, None)

    # Remove base URL
    base_env_var = provider.get("api_base_env")
    if base_env_var:
        unset_key(dotenv_path, base_env_var)
        os.environ.pop(base_env_var, None)

    # Remove custom model name for openai_compatible
    if provider_name == "openai_compatible":
        unset_key(dotenv_path, "OPENAI_COMPATIBLE_MODEL_NAME")
        os.environ.pop("OPENAI_COMPATIBLE_MODEL_NAME", None)

    # Clear router factory cached check
    from agentos.llm.router_factory import check_ollama_reachable
    check_ollama_reachable.cache_clear()

    # Discard from failed_providers if present
    failed_providers = getattr(request.app.state, "failed_providers", set())
    failed_providers.discard(provider_name)

    return {"success": True}


@router.get("/providers/fallback-chain", response_model=List[FallbackChainItem])
async def get_fallback_chain(request: Request):
    """
    Returns the CURRENT ordered fallback chain as the router would build it right now.
    """
    try:
        router_instance = build_router()
    except Exception as e:
        logger.warning(f"Could not build router: {e}")
        return []

    failed_providers = getattr(request.app.state, "failed_providers", set())

    # Sort model_list by litellm_params["order"]
    sorted_models = sorted(router_instance.model_list, key=lambda m: m["litellm_params"].get("order", 999))
    chain = []
    for idx, model_entry in enumerate(sorted_models):
        litellm_params = model_entry["litellm_params"]
        litellm_model = litellm_params["model"]
        prov = get_provider_by_model(litellm_model)
        prov_name = prov["name"] if prov else "unknown"

        # Determine status
        status = "active"
        if prov_name in failed_providers:
            status = "probe_failed"
        chain.append(
            FallbackChainItem(
                order=idx + 1,
                name=prov_name,
                litellm_model=litellm_model,
                status=status,
            )
        )

    return chain


@router.post("/providers/test/{provider_name}", response_model=ProviderTestResponse)
async def test_provider(provider_name: str, request: Request):
    """
    Sends a trivial test completion to that specific provider, bypassing the fallback chain.
    """
    provider = next((p for p in PROVIDER_REGISTRY if p["name"] == provider_name), None)
    if not provider:
        raise HTTPException(status_code=400, detail=f"Provider '{provider_name}' not found")

    # If mock LLM is enabled
    if os.environ.get("AGENTOS_MOCK_LLM") == "1":
        # Simulate quick latency
        time.sleep(0.05)
        # Clear failure status just in case
        failed_providers = getattr(request.app.state, "failed_providers", set())
        failed_providers.discard(provider_name)
        return ProviderTestResponse(
            success=True,
            latency_ms=42,
            response="OK",
            error=None,
        )

    # Check key configuration
    api_key = None
    if provider["api_key_env"]:
        api_key = os.environ.get(provider["api_key_env"], "").strip()
        if not api_key:
            raise HTTPException(status_code=400, detail=f"Provider '{provider_name}' is not configured (missing API key).")

    # Check base URL
    api_base = None
    if provider["api_base_env"]:
        api_base = os.environ.get(provider["api_base_env"], "").strip()
        if not api_base and provider["api_base_env"] == "OLLAMA_BASE_URL":
            api_base = "http://localhost:11434"

    model = provider["litellm_model"]
    if provider_name == "openai_compatible":
        custom_model = os.environ.get("OPENAI_COMPATIBLE_MODEL_NAME", "").strip()
        if custom_model:
            model = f"openai/{custom_model}"

    failed_providers = getattr(request.app.state, "failed_providers", set())
    start_time = time.perf_counter()
    try:
        resp = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": "Say 'OK' in one word"}],
            api_key=api_key,
            api_base=api_base,
            timeout=10.0,
        )
        latency = int((time.perf_counter() - start_time) * 1000)
        content = resp.choices[0].message.content.strip()
        failed_providers.discard(provider_name)
        return ProviderTestResponse(
            success=True,
            latency_ms=latency,
            response=content,
            error=None,
        )
    except Exception as e:
        latency = int((time.perf_counter() - start_time) * 1000)
        failed_providers.add(provider_name)
        return ProviderTestResponse(
            success=False,
            latency_ms=latency,
            response=None,
            error=str(e),
        )
