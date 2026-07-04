"""
Provider Registry - Configured LLM providers and availability checks

Phase 4 additions:
  - OpenRouter (aggregator — access to 100+ models via one key)
  - Together AI (GPU cloud — fast open-weight models)
  - Fireworks AI (GPU cloud — fast open-weight models)
  - DeepSeek (Chinese AI lab — strong coding/reasoning models)
  - Additional Groq models (gemma2, llama3.1 instant)
  
All entries follow the exact same schema as Phase 1-3 entries:
  litellm_model, api_key_env, api_base_env, priority, tags
No special casing added to router_factory.py — adding a provider is a data change only.

Provider model names verified against current docs (June 2026).
LiteLLM prefixes: openrouter/, together_ai/, fireworks_ai/, deepseek/, groq/
"""

from typing import List, Dict, Any
import os

from agentos.exceptions import AgentOSLLMError


PROVIDER_REGISTRY: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # Tier 1: Premium paid providers (lowest priority number = first in fallback)
    # -------------------------------------------------------------------------
    {
        "name": "openai_gpt4o",
        "display_name": "GPT-4o",
        "litellm_model": "openai/gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
        "api_base_env": None,
        "priority": 10,
        "tags": ["paid", "fast", "openai"]
    },
    {
        "name": "anthropic_claude_sonnet",
        "display_name": "Claude Sonnet",
        "litellm_model": "anthropic/claude-3-5-sonnet-20241022",
        "api_key_env": "ANTHROPIC_API_KEY",
        "api_base_env": None,
        "priority": 15,
        "tags": ["paid", "fast", "anthropic"]
    },
    {
        "name": "openai_gpt4o_mini",
        "display_name": "GPT-4o Mini",
        "litellm_model": "openai/gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "api_base_env": None,
        "priority": 20,
        "tags": ["paid", "fast", "openai"]
    },
    # Phase 4: OpenRouter — access to 100+ models via single key
    # Docs: https://openrouter.ai/docs  LiteLLM prefix: openrouter/
    {
        "name": "openrouter_claude_sonnet",
        "display_name": "Claude Sonnet (OpenRouter)",
        "litellm_model": "openrouter/anthropic/claude-3.5-sonnet",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        "priority": 22,
        "tags": ["paid", "fast", "openrouter"]
    },
    {
        "name": "openrouter_gpt4o",
        "display_name": "GPT-4o (OpenRouter)",
        "litellm_model": "openrouter/openai/gpt-4o",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        "priority": 23,
        "tags": ["paid", "fast", "openrouter"]
    },
    {
        "name": "gemini_flash",
        "display_name": "Gemini 2.0 Flash",
        "litellm_model": "gemini/gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "api_base_env": None,
        "priority": 30,
        "tags": ["paid", "fast", "gemini"]
    },
    # Phase 4: DeepSeek — strong coding/reasoning at competitive pricing
    # Docs: https://platform.deepseek.com/  LiteLLM prefix: deepseek/
    # NOTE: deepseek-chat is scheduled for retirement Jul 24 2026; using deepseek-v4-flash as fallback name
    {
        "name": "deepseek_v4_flash",
        "display_name": "DeepSeek Chat",
        "litellm_model": "deepseek/deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "api_base_env": None,
        "priority": 33,
        "tags": ["paid", "fast", "deepseek"]
    },
    # -------------------------------------------------------------------------
    # Tier 2: Fast/cheap open-weight cloud providers
    # -------------------------------------------------------------------------
    # Phase 4: Groq additional models (llama3.1 instant and gemma2)
    {
        "name": "groq_llama3_3",
        "display_name": "Llama 3.3 70B",
        "litellm_model": "groq/llama-3.3-70b-specdec",
        "api_key_env": "GROQ_API_KEY",
        "api_base_env": None,
        "priority": 40,
        "tags": ["paid", "fast", "groq"]
    },
    {
        "name": "groq_llama3_1_instant",
        "display_name": "Llama 3.1 Instant",
        "litellm_model": "groq/llama-3.1-8b-instant",
        "api_key_env": "GROQ_API_KEY",
        "api_base_env": None,
        "priority": 42,
        "tags": ["paid", "fast", "groq"]
    },
    {
        "name": "groq_gemma2",
        "display_name": "Gemma 2 9B",
        "litellm_model": "groq/gemma2-9b-it",
        "api_key_env": "GROQ_API_KEY",
        "api_base_env": None,
        "priority": 44,
        "tags": ["paid", "fast", "groq"]
    },
    # Phase 4: Together AI — GPU cloud with wide open-weight model selection
    # Docs: https://together.ai/  LiteLLM prefix: together_ai/
    # Env var: TOGETHERAI_API_KEY (LiteLLM's convention)
    {
        "name": "together_llama3_3_70b",
        "display_name": "Meta Llama 3.3",
        "litellm_model": "together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "api_key_env": "TOGETHERAI_API_KEY",
        "api_base_env": None,
        "priority": 46,
        "tags": ["paid", "fast", "together"]
    },
    {
        "name": "together_qwen2_5_72b",
        "display_name": "Qwen 2.5 72B",
        "litellm_model": "together_ai/Qwen/Qwen2.5-72B-Instruct-Turbo",
        "api_key_env": "TOGETHERAI_API_KEY",
        "api_base_env": None,
        "priority": 48,
        "tags": ["paid", "fast", "together"]
    },
    # Phase 4: Fireworks AI — GPU cloud, very fast inference
    # Docs: https://fireworks.ai/  LiteLLM prefix: fireworks_ai/
    # Model format: fireworks_ai/accounts/fireworks/models/<model-id>
    {
        "name": "fireworks_llama3_1_70b",
        "display_name": "Llama 3.1 70B",
        "litellm_model": "fireworks_ai/accounts/fireworks/models/llama-v3p1-70b-instruct",
        "api_key_env": "FIREWORKS_AI_API_KEY",
        "api_base_env": None,
        "priority": 50,
        "tags": ["paid", "fast", "fireworks"]
    },
    {
        "name": "fireworks_qwen2_5_72b",
        "display_name": "Qwen 2.5 72B",
        "litellm_model": "fireworks_ai/accounts/fireworks/models/qwen2p5-72b-instruct",
        "api_key_env": "FIREWORKS_AI_API_KEY",
        "api_base_env": None,
        "priority": 52,
        "tags": ["paid", "fast", "fireworks"]
    },
    # Phase 4: OpenRouter free tier — great for "no API key" accessibility
    # Free models are rate-limited but require only an OpenRouter key.
    # NOTE: meta-llama/llama-3.1-8b-instruct:free was retired; mistral-7b-instruct:free is active (verified Jun 2026).
    {
        "name": "openrouter_mistral_7b_free",
        "display_name": "Mistral 7B Free (OpenRouter)",
        "litellm_model": "openrouter/mistralai/mistral-7b-instruct:free",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        "priority": 70,
        "tags": ["free-tier", "openrouter"]
    },
    # -------------------------------------------------------------------------
    # Tier 3: Custom OpenAI-compatible endpoint
    # -------------------------------------------------------------------------
    {
        "name": "openai_compatible",
        "display_name": "Custom OpenAI-Compatible",
        "litellm_model": "openai/custom-model",
        "api_key_env": "OPENAI_COMPATIBLE_API_KEY",
        "api_base_env": "OPENAI_COMPATIBLE_BASE_URL",
        "priority": 80,
        "tags": ["open-weight"]
    },
    # -------------------------------------------------------------------------
    # Tier 4: Local Ollama (free, zero cost, zero API key required)
    # -------------------------------------------------------------------------
    {
        "name": "ollama_qwen",
        "display_name": "Ollama · Qwen 2.5 Coder",
        "litellm_model": "ollama/qwen2.5-coder",
        "api_key_env": None,
        "api_base_env": "OLLAMA_BASE_URL",
        "priority": 100,
        "tags": ["free", "local"]
    },
    {
        "name": "ollama_llama",
        "display_name": "Ollama · Llama 3.2",
        "litellm_model": "ollama/llama3.2",
        "api_key_env": None,
        "api_base_env": "OLLAMA_BASE_URL",
        "priority": 110,
        "tags": ["free", "local"]
    },
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
