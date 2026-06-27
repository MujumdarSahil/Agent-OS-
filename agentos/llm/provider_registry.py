"""
Provider Registry - Configured LLM providers and availability checks
"""

from typing import List, Dict, Any, Optional
import os

PROVIDER_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "openai_gpt4o",
        "litellm_model": "openai/gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
        "api_base_env": None,
        "priority": 10,
        "tags": ["paid", "fast"]
    },
    {
        "name": "openai_gpt4o_mini",
        "litellm_model": "openai/gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "api_base_env": None,
        "priority": 20,
        "tags": ["paid", "fast"]
    },
    {
        "name": "anthropic_claude_sonnet",
        "litellm_model": "anthropic/claude-3-5-sonnet-20241022",
        "api_key_env": "ANTHROPIC_API_KEY",
        "api_base_env": None,
        "priority": 15,
        "tags": ["paid", "fast"]
    },
    {
        "name": "gemini_flash",
        "litellm_model": "gemini/gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "api_base_env": None,
        "priority": 30,
        "tags": ["paid", "fast"]
    },
    {
        "name": "groq_llama3_3",
        "litellm_model": "groq/llama-3.3-70b-specdec",
        "api_key_env": "GROQ_API_KEY",
        "api_base_env": None,
        "priority": 40,
        "tags": ["paid", "fast"]
    },
    {
        "name": "ollama_qwen",
        "litellm_model": "ollama/qwen2.5-coder",
        "api_key_env": None,
        "api_base_env": "OLLAMA_BASE_URL",
        "priority": 100,
        "tags": ["free", "local"]
    },
    {
        "name": "ollama_llama",
        "litellm_model": "ollama/llama3.2",
        "api_key_env": None,
        "api_base_env": "OLLAMA_BASE_URL",
        "priority": 110,
        "tags": ["free", "local"]
    },
    {
        "name": "openai_compatible",
        "litellm_model": "openai/custom-model",
        "api_key_env": "OPENAI_COMPATIBLE_API_KEY",
        "api_base_env": "OPENAI_COMPATIBLE_BASE_URL",
        "priority": 50,
        "tags": ["open-weight"]
    }
]

def get_available_providers() -> List[Dict[str, Any]]:
    """
    Returns a list of LLM providers whose required environment variables are set.
    For Ollama/local providers (where api_key_env is None), they are considered
    available by default and checked for runtime connectivity.
    """
    available = []
    for prov in PROVIDER_REGISTRY:
        if prov["api_key_env"] is None:
            # Always considered available structurally; connectivity check is done in router_factory
            available.append(prov)
        else:
            api_key = os.environ.get(prov["api_key_env"], "").strip()
            if api_key:
                prov_copy = prov.copy()
                # For generic openai_compatible, customize name from env if present
                if prov["name"] == "openai_compatible":
                    custom_model = os.environ.get("OPENAI_COMPATIBLE_MODEL_NAME", "").strip()
                    if custom_model:
                        prov_copy["litellm_model"] = f"openai/{custom_model}"
                available.append(prov_copy)
    available.sort(key=lambda x: x["priority"])
    return available
