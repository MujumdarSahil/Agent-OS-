import os
import pytest
import vcr
from dotenv import load_dotenv
load_dotenv()
from unittest.mock import patch
from agentos.llm.llm_client import LLMClient
from agentos.llm.provider_registry import PROVIDER_REGISTRY

# Configure VCR
my_vcr = vcr.VCR(
    cassette_library_dir="agentos/tests/cassettes",
    record_mode="once",
    filter_headers=["authorization", "api-key", "x-api-key", "X-Goog-Api-Key"],
    match_on=["method", "scheme", "host", "port", "path", "query"],
)

@pytest.mark.parametrize("prov", PROVIDER_REGISTRY, ids=lambda p: p["name"])
def test_provider_endpoint(prov):
    name = prov["name"]
    # We skip ollama tests because they require a local running instance
    if "ollama" in name:
        pytest.skip("Skipping Ollama provider test (requires local service)")
        
    cassette_path = os.path.join("agentos/tests/cassettes", f"{name}.yaml")
    cassette_exists = os.path.exists(cassette_path)
    
    key_env = prov["api_key_env"]
    has_key = key_env is None or (key_env in os.environ and bool(os.environ[key_env].strip()))
    
    if not cassette_exists and not has_key:
        pytest.skip(f"No cassette for {name} and API key {key_env} is not set in env.")
        
    # Ensure some dummy key exists so provider checks pass for replay
    key_was_set = bool(key_env and key_env in os.environ and os.environ[key_env].strip())
    if key_env and not key_was_set:
        os.environ[key_env] = "dummy-vcr-key"
        
    old_mock = os.environ.get("AGENTOS_MOCK_LLM")
    if "AGENTOS_MOCK_LLM" in os.environ:
        del os.environ["AGENTOS_MOCK_LLM"]
        
    try:
        # Mock get_available_providers to return only this provider
        with patch("agentos.llm.router_factory.get_available_providers") as mock_get:
            mock_get.return_value = [prov]
            
            # Use VCR to run the completion call
            with my_vcr.use_cassette(f"{name}.yaml"):
                client = LLMClient()
                messages = [{"role": "user", "content": "Respond only with the word OK."}]
                response = client.complete(messages=messages, temperature=0.0)
                
                content = response.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                assert len(content) > 0
                print(f"Provider {name} returned: {content}")
    finally:
        # Restore environment
        if old_mock is not None:
            os.environ["AGENTOS_MOCK_LLM"] = old_mock
        elif "AGENTOS_MOCK_LLM" in os.environ:
            del os.environ["AGENTOS_MOCK_LLM"]
            
        if key_env and not key_was_set and key_env in os.environ:
            del os.environ[key_env]
