"""
Router Factory - Builds a LiteLLM Router with fallback prioritization
"""

from typing import List, Dict, Any, Optional
import os
import requests
import logging
import litellm
from litellm import Router

from agentos.llm.provider_registry import get_available_providers, PROVIDER_REGISTRY

logger = logging.getLogger(__name__)

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
    except Exception:
        pass
    return False

def build_router(preferred_tags: Optional[List[str]] = None) -> Router:
    """
    Reads available providers, builds a litellm Router model_list where every
    available provider becomes one model_list entry under a shared model_name group
    ("agentos-default"), with an 'order' parameter for fallback priority.
    """
    available_providers = get_available_providers()
    ollama_reachable = check_ollama_reachable()

    # Omit Ollama entries if Ollama is unreachable
    if not ollama_reachable:
        available_providers = [p for p in available_providers if p["api_key_env"] is not None]
        logger.warning(
            "Ollama is unreachable at OLLAMA_BASE_URL. Ollama providers are omitted from fallback chain."
        )

    # If completely empty, raise clear error
    if not available_providers:
        raise RuntimeError(
            "No LLM providers are available. Please configure at least one API key in "
            "your environment (.env) or ensure Ollama is running locally."
        )

    # Sort/Reorder based on preferred tags and priority
    # Providers matching preferred tags should run first
    def get_sort_key(p: Dict[str, Any]):
        if preferred_tags:
            # Check if any tag matches preferred_tags
            has_match = any(tag in p.get("tags", []) for tag in preferred_tags)
            match_val = 0 if has_match else 1
            return (match_val, p["priority"])
        return (p["priority"],)

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
        litellm_params = {
            "model": p["litellm_model"],
            "order": idx + 1,  # Lower order runs first
        }
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
