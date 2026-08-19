import os
import base64
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
    record_mode="none",
    filter_headers=["authorization", "api-key", "x-api-key", "X-Goog-Api-Key", "cookie", "user-agent", "content-length"],
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
    
    if not cassette_exists:
        pytest.skip(f"No cassette file found at {cassette_path}")
        
    # Always set dummy key during VCR cassette replay so LiteLLM doesn't bypass VCR with async calls
    old_key = os.environ.get(key_env)
    if key_env:
        os.environ[key_env] = "dummy-vcr-key"
        
    old_mock = os.environ.get("AGENTOS_MOCK_LLM")
    if "AGENTOS_MOCK_LLM" in os.environ:
        del os.environ["AGENTOS_MOCK_LLM"]
        
    try:
        # Mock get_available_providers to return only this provider
        with patch("agentos.llm.router_factory.get_available_providers") as mock_get:
            mock_get.return_value = [prov]
            
            # Use VCR to run the completion call
            with my_vcr.use_cassette(f"{name}.yaml", match_on=["method", "scheme", "host", "port", "path", "query"]):
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
            
        if key_env:
            if old_key is not None:
                os.environ[key_env] = old_key
            elif key_env in os.environ:
                del os.environ[key_env]


def test_gemma_4_31b_vision():
    """Vision integration test for openrouter_gemma_4_31b_free sending image fixture."""
    img_path = os.path.join("agentos/tests/fixtures", "test_image.png")
    assert os.path.exists(img_path), f"Test image fixture missing at {img_path}"
    with open(img_path, "rb") as f:
        b64_img = base64.b64encode(f.read()).decode("utf-8")
        
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What color is the shape in this image?"},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64_img}"}}
            ]
        }
    ]
    
    prov = next(p for p in PROVIDER_REGISTRY if p["name"] == "openrouter_gemma_4_31b_free")
    key_env = prov["api_key_env"]
    old_key = os.environ.get(key_env)
    if key_env:
        os.environ[key_env] = "dummy-vcr-key"
        
    old_mock = os.environ.get("AGENTOS_MOCK_LLM")
    if "AGENTOS_MOCK_LLM" in os.environ:
        del os.environ["AGENTOS_MOCK_LLM"]
        
    try:
        with patch("agentos.llm.router_factory.get_available_providers") as mock_get:
            mock_get.return_value = [prov]
            with my_vcr.use_cassette("openrouter_gemma_4_31b_vision.yaml", match_on=["method", "scheme", "host", "port", "path", "query"]):
                client = LLMClient()
                response = client.complete(messages=messages, temperature=0.0)
                content = response.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                assert len(content) > 0
                assert "red" in content.lower()
                print(f"Gemma 4 31B Vision returned: {content}")
    finally:
        if old_mock is not None:
            os.environ["AGENTOS_MOCK_LLM"] = old_mock
        elif "AGENTOS_MOCK_LLM" in os.environ:
            del os.environ["AGENTOS_MOCK_LLM"]
        if key_env:
            if old_key is not None:
                os.environ[key_env] = old_key
            elif key_env in os.environ:
                del os.environ[key_env]


def test_nemotron_3_nano_omni_vision():
    """Vision integration test for openrouter_nemotron_3_nano_omni_free sending image fixture."""
    img_path = os.path.join("agentos/tests/fixtures", "test_image.png")
    assert os.path.exists(img_path), f"Test image fixture missing at {img_path}"
    with open(img_path, "rb") as f:
        b64_img = base64.b64encode(f.read()).decode("utf-8")
        
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What color is the shape in this image?"},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64_img}"}}
            ]
        }
    ]
    
    prov = next(p for p in PROVIDER_REGISTRY if p["name"] == "openrouter_nemotron_3_nano_omni_free")
    key_env = prov["api_key_env"]
    old_key = os.environ.get(key_env)
    if key_env:
        os.environ[key_env] = "dummy-vcr-key"
        
    old_mock = os.environ.get("AGENTOS_MOCK_LLM")
    if "AGENTOS_MOCK_LLM" in os.environ:
        del os.environ["AGENTOS_MOCK_LLM"]
        
    try:
        with patch("agentos.llm.router_factory.get_available_providers") as mock_get:
            mock_get.return_value = [prov]
            cassette_file = "openrouter_nemotron_3_nano_omni_vision.yaml" if os.path.exists("agentos/tests/cassettes/openrouter_nemotron_3_nano_omni_vision.yaml") else "openrouter_nemotron_nano_12b_vl_vision.yaml"
            with my_vcr.use_cassette(cassette_file, match_on=["method", "scheme", "host", "port", "path", "query"]):
                client = LLMClient()
                response = client.complete(messages=messages, temperature=0.0)
                content = response.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                assert len(content) > 0
                assert "red" in content.lower()
                print(f"Nemotron Vision returned: {content}")
    finally:
        if old_mock is not None:
            os.environ["AGENTOS_MOCK_LLM"] = old_mock
        elif "AGENTOS_MOCK_LLM" in os.environ:
            del os.environ["AGENTOS_MOCK_LLM"]
        if key_env:
            if old_key is not None:
                os.environ[key_env] = old_key
            elif key_env in os.environ:
                del os.environ[key_env]

