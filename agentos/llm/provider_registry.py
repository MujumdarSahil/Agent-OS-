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
import logging

logger = logging.getLogger(__name__)

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
        # 2.4c: anthropic/claude-3.5-sonnet is no longer listed by OpenRouter (checked 2026-11-17).
        "litellm_model": "openrouter/anthropic/claude-sonnet-5.5",
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
        # 2.4c: LIVE run returned NotFoundError for this id (raw/2.4c-live.txt). The replacement id is
        # not verified here, so it is off unless the fallback policy enables it.
        "default_enabled": False,
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
        "litellm_model": "groq/llama-3.3-70b-versatile",
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
        "name": "groq_qwen3_32b",
        "display_name": "Qwen 3 32B",
        "litellm_model": "groq/qwen/qwen3-32b",
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
    # Phase 2: Zhipu AI / Z.ai international API platform (https://docs.z.ai/)
    # LiteLLM routes zai/ prefix to https://api.z.ai/api/paas/v4
    # Requires ZAI_API_KEY in environment or credentials vault.
    {
        "name": "zai_glm_5_3",
        "display_name": "GLM-5.3 (Z.ai)",
        "litellm_model": "zai/glm-5.3",
        "api_key_env": "ZAI_API_KEY",
        "api_base_env": None,
        "priority": 54,
        "tags": ["paid", "zai", "flagship"]
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
        # 2.4c: no longer listed by OpenRouter (checked 2026-11-17) -> off unless the fallback policy enables it.
        "default_enabled": False,
        "priority": 70,
        "tags": ["free-tier", "openrouter"]
    },
    # Free endpoint context window is 262,144 tokens, NOT the model's full 1M — do not assume long-context tasks will fit.
    # Poolside's free-tier terms state inputs/outputs may be used for training. Flag this in user-facing docs, not just code comments, so users routing proprietary code through it are actually informed, not just covered by a buried comment.
    {
        "name": "openrouter_laguna_s_2_1_free",
        "display_name": "Laguna S 2.1 Free (OpenRouter)",
        "litellm_model": "openrouter/poolside/laguna-s-2.1:free",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        # 2.4c: no longer listed by OpenRouter (checked 2026-11-17) -> off unless the fallback policy enables it.
        "default_enabled": False,
        "priority": 72,
        "tags": ["free-tier", "openrouter"]
    },
    # Zhipu AI / Z.ai free tier flash model via international API (https://docs.z.ai/).
    # Requires ZAI_API_KEY in environment or credentials vault.
    {
        "name": "zai_glm_4_7_flash",
        "display_name": "GLM-4.7 Flash (Z.ai Free)",
        "litellm_model": "zai/glm-4.7-flash",
        "api_key_env": "ZAI_API_KEY",
        "api_base_env": None,
        "priority": 71,
        "tags": ["free-tier", "zai", "fast"]
    },
    # OpenRouter free tier for Zhipu AI GLM-5.2.
    # Free endpoint subject to daily rate limits; prompts may be logged or used for training
    # by upstream providers. Do NOT send secret-labelled data or sensitive internal information.
    {
        "name": "openrouter_glm_5_2_free",
        "display_name": "GLM-5.2 Free (OpenRouter)",
        "litellm_model": "openrouter/z-ai/glm-5.2:free",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        # 2.4c: the :free variant is no longer listed by OpenRouter (checked 2026-11-17; only paid
        # z-ai/glm-5.2 remains). Off unless the fallback policy enables it.
        "default_enabled": False,
        "priority": 73,
        "tags": ["free-tier", "openrouter"]
    },
    {
        "name": "openrouter_gemma_4_31b_free",
        "display_name": "Gemma 4 31B Free (OpenRouter)",
        "litellm_model": "openrouter/google/gemma-4-31b-it:free",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        "priority": 74,
        "tags": ["free-tier", "openrouter", "vision"]
    },
    {
        "name": "openrouter_nemotron_3_nano_omni_free",
        "display_name": "Nemotron-3 Nano Omni Free (OpenRouter)",
        "litellm_model": "openrouter/nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
        "api_key_env": "OPENROUTER_API_KEY",
        "api_base_env": None,
        "priority": 75,
        "tags": ["free-tier", "openrouter", "vision"]
    },
    # Hugging Face Inference API (discovery-first, serverless endpoints via LiteLLM).
    # Does NOT perform local model download or self-hosted serving.
    # Requires a valid HUGGINGFACE_API_KEY (or HF_TOKEN) in environment.
    {
        "name": "huggingface_llama3_2_1b",
        "display_name": "Hugging Face · Llama 3.2 1B",
        "litellm_model": "huggingface/meta-llama/Llama-3.2-1B-Instruct",
        "api_key_env": "HUGGINGFACE_API_KEY",
        "api_base_env": None,
        "priority": 75,
        "tags": ["free-tier", "huggingface"]
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

# 2.4c: OmniRoute gateway (UNVERIFIED). OpenAI-compatible; base URL from AGENTOS_OMNIROUTE_BASE_URL
# (default http://127.0.0.1:20128/v1), model from AGENTOS_OMNIROUTE_MODEL, key OMNIROUTE_API_KEY (vault
# or env). It relays to hosted models, so it never counts as a local provider (THREAT_MODEL T-13).
# Run it on 127.0.0.1 with REQUIRE_API_KEY=true; upstream terms may forbid relaying; its request
# logging can capture prompts.
PROVIDER_REGISTRY.append({
    "name": "omniroute",
    "display_name": "OmniRoute gateway (UNVERIFIED)",
    "litellm_model": "openai/auto",
    "api_key_env": "OMNIROUTE_API_KEY",
    "api_base_env": "AGENTOS_OMNIROUTE_BASE_URL",
    "priority": 90,
    "hosted_relay": True,
    "tags": ["unverified", "openai-compatible", "gateway"],
})


async def export_vault_provider_keys(vault: Any) -> List[str]:
    """Load vault secrets named like a provider key variable (e.g. GROQ_API_KEY) into this process's
    environment (in memory only, never written). Vault values take precedence over env ("vault first").
    Returns the variable names loaded (never the values)."""
    wanted = {p["api_key_env"] for p in PROVIDER_REGISTRY if p.get("api_key_env")}
    loaded: List[str] = []
    for info in await vault.list():
        name = getattr(info, "name", None)
        if name in wanted:
            try:
                os.environ[name] = (await vault.reveal(name)).strip()
                loaded.append(name)
            except Exception:
                continue
    return sorted(loaded)


def enabled_model_ids(policy_configs: Any = None) -> set:
    """Model identifiers a flow node may select (2.3 per-node model choice).

    A provider counts as enabled when it is available (key configured or local) - or every registry
    provider in MOCK mode (AGENTOS_MOCK_LLM=1) - and it is not disabled in the fallback policy.
    Both the provider name and its LiteLLM model string are accepted.
    """
    disabled = {
        c.get("name")
        for c in (policy_configs or [])
        if isinstance(c, dict) and c.get("enabled", True) is False
    }
    providers = PROVIDER_REGISTRY if os.environ.get("AGENTOS_MOCK_LLM") == "1" else get_available_providers()
    ids: set = set()
    for prov in providers:
        if prov["name"] in disabled:
            continue
        ids.add(prov["name"])
        ids.add(prov["litellm_model"])
    return ids


def get_available_providers() -> List[Dict[str, Any]]:
    """
    Returns a list of LLM providers whose required environment variables are set.
    For Ollama/local providers (where api_key_env is None), they are considered
    available by default and checked for runtime connectivity.
    """
    available = []
    for prov in PROVIDER_REGISTRY:
        if prov.get("default_enabled", True) is False:
            continue  # outdated model id: only an explicit fallback-policy entry re-enables it (router_factory)
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


def is_any_provider_configured() -> bool:
    """
    Returns True if at least one provider in PROVIDER_REGISTRY has its required API key
    present in os.environ, or if local Ollama server is reachable.
    """
    for prov in PROVIDER_REGISTRY:
        key_env = prov.get("api_key_env")
        if key_env and os.environ.get(key_env, "").strip():
            return True
    try:
        from agentos.llm.router_factory import check_ollama_reachable
        if check_ollama_reachable():
            return True
    except Exception as e:
        logger.debug(f"Error checking Ollama reachability: {e}")
    return False

