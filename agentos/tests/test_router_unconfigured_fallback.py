"""Unit tests verifying that the LLM router excludes unconfigured fallback providers."""

import os
from agentos.llm.router_factory import build_router


def test_unconfigured_fallback_provider_omitted_when_not_mock(monkeypatch):
    """Router must not add a fallback-policy provider that has no configured key unless local or mock."""
    # 1. When AGENTOS_MOCK_LLM is disabled and key is missing:
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "0")
    monkeypatch.delenv("CUSTOM_TEST_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-valid-key")

    policy = [
        {
            "name": "custom_unconfigured",
            "order": 1,
            "enabled": True,
            "litellm_model": "custom/no-key-model",
        },
    ]

    router = build_router(provider_configs=policy)
    models = [m["litellm_params"]["model"] for m in router.model_list]
    assert "custom/no-key-model" not in models, (
        f"Security violation: unconfigured provider 'custom/no-key-model' was added to router: {models}"
    )

    # 2. When AGENTOS_MOCK_LLM is enabled (offline CI mode):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    mock_router = build_router(provider_configs=policy)
    mock_models = [m["litellm_params"]["model"] for m in mock_router.model_list]
    assert "custom/no-key-model" in mock_models, (
        f"Expected custom model to be present under AGENTOS_MOCK_LLM=1, got: {mock_models}"
    )
