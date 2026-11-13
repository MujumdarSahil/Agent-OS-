"""
Router Factory - Builds a LiteLLM Router with fallback prioritization
"""

from typing import List, Dict, Any, Optional
import os
import requests
import logging
import litellm
from litellm import Router

from agentos.llm.provider_registry import get_available_providers, PROVIDER_REGISTRY, AgentOSLLMError

# In-memory fallback policy cache for the router override hook.
# Synchronously read by build_router without calling async code.
_fallback_policy_cache: Optional[List[Dict[str, Any]]] = None


def set_fallback_policy_cache(cache: Optional[List[Any]]) -> None:
    """Set the in-memory fallback policy cache (called on startup and on PUT /api/v2/providers/fallback)."""
    global _fallback_policy_cache
    if cache is None:
        _fallback_policy_cache = None
        return
    normalized = []
    for item in cache:
        if hasattr(item, "model_dump"):
            normalized.append(item.model_dump())
        elif isinstance(item, dict):
            normalized.append(dict(item))
        elif hasattr(item, "__dict__"):
            normalized.append(dict(item.__dict__))
    _fallback_policy_cache = normalized


def get_fallback_policy_cache() -> Optional[List[Dict[str, Any]]]:
    """Get the current in-memory fallback policy cache."""
    return _fallback_policy_cache


# Drop parameters that are unsupported by a given provider (e.g. cache_breakpoint on Groq).
# LiteLLM sometimes forwards OpenAI/Anthropic prompt-caching metadata to providers that
# don't support it. Setting this at module load ensures it applies globally for the process.
litellm.drop_params = True

logger = logging.getLogger(__name__)

import functools

@functools.lru_cache(maxsize=1)
def check_ollama_reachable() -> bool:
    """
    Lightweight connectivity probe to check if Ollama is reachable.
    """
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").strip()
    if not base_url:
        base_url = "http://localhost:11434"
    try:
        # Probe using /api/tags or root with short timeout
        response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=1.0)
        if response.status_code == 200:
            return True
    except Exception as e:
        logger.debug(f"Ollama connectivity probe failed: {e}")
    return False

def build_router(
    preferred_tags: Optional[List[str]] = None,
    provider_configs: Optional[List[Any]] = None,
) -> Router:
    """
    Reads available providers, builds a litellm Router model_list where every
    available provider becomes one model_list entry under a shared model_name group
    ("agentos-default"), with an 'order' parameter for fallback priority.

    Respects synchronous fallback policy overrides from provider_configs or the
    in-memory cache set via set_fallback_policy_cache().
    """
    available_providers = get_available_providers()
    ollama_reachable = check_ollama_reachable()

    # Omit Ollama entries if Ollama is unreachable
    if not ollama_reachable:
        available_providers = [p for p in available_providers if p["api_key_env"] is not None]
        logger.warning(
            "Ollama is unreachable at OLLAMA_BASE_URL. Ollama providers are omitted from fallback chain."
        )

    # Resolve policy overrides from parameter or in-memory cache
    if provider_configs is None:
        provider_configs = _fallback_policy_cache

    overrides_by_name: Dict[str, Dict[str, Any]] = {}
    if provider_configs:
        for item in provider_configs:
            d = item.model_dump() if hasattr(item, "model_dump") else dict(item)
            overrides_by_name[d["name"]] = d

    # Filter out disabled providers from overrides
    if overrides_by_name:
        available_providers = [
            p for p in available_providers
            if overrides_by_name.get(p["name"], {}).get("enabled", True)
        ]

    # If completely empty, raise clear error
    if not available_providers:
        if os.environ.get("AGENTOS_MOCK_LLM") == "1":
            available_providers = [{
                "name": "mock-provider",
                "litellm_model": "openai/mock-model",
                "api_key_env": None,
                "api_base_env": None,
                "priority": 100,
                "tags": ["fast"]
            }]
        else:
            raise AgentOSLLMError(
                "No LLM providers are available. Please configure at least one API key in "
                "your environment (.env) or ensure Ollama is running locally."
            )

    # Sort/Reorder based on fallback overrides, preferred tags, and priority
    def get_sort_key(p: Dict[str, Any]):
        override = overrides_by_name.get(p["name"])
        if override is not None and "order" in override:
            return (override["order"], 0, p.get("priority", 100))
        if preferred_tags:
            has_match = any(tag in p.get("tags", []) for tag in preferred_tags)
            match_val = 0 if has_match else 1
            return (1000, match_val, p.get("priority", 100))
        return (1000, 1, p.get("priority", 100))

    sorted_providers = sorted(available_providers, key=get_sort_key)

    # Always ensure at least one Ollama entry is appended last as the ultimate free fallback,
    # unless Ollama is unreachable.
    if ollama_reachable:
        # Check if an Ollama entry is already present in sorted_providers
        has_ollama = any(p["name"].startswith("ollama") for p in sorted_providers)
        if not has_ollama:
            # Find the highest priority Ollama provider from provider registry
            ollama_prov = next((p for p in PROVIDER_REGISTRY if p["name"].startswith("ollama")), None)
            if ollama_prov:
                sorted_providers.append(ollama_prov)

    # Build the model list for litellm Router
    model_list = []
    for idx, p in enumerate(sorted_providers):
        # Determine API Key and Base URL
        api_key = None
        if p["api_key_env"]:
            api_key = os.environ.get(p["api_key_env"], "").strip()
            
        api_base = None
        if p["api_base_env"]:
            api_base = os.environ.get(p["api_base_env"], "").strip()
            if not api_base and p["api_base_env"] == "OLLAMA_BASE_URL":
                api_base = "http://localhost:11434"

        # Construct litellm_params
        override = overrides_by_name.get(p["name"])
        order_val = override["order"] if override and "order" in override else (idx + 1)
        litellm_params = {
            "model": p["litellm_model"],
            "order": order_val,
        }
        if override and override.get("timeout_s"):
            litellm_params["request_timeout"] = override["timeout_s"]
        if api_key:
            litellm_params["api_key"] = api_key
        if api_base:
            litellm_params["api_base"] = api_base

        model_list.append({
            "model_name": "agentos-default",
            "litellm_params": litellm_params
        })

    # Initialize and return Router
    return Router(model_list=model_list)
