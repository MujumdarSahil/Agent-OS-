import os
import pytest

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

@pytest.fixture(autouse=True)
def setup_server_test_env():
    """Default test environment for agentos_server test suite.

    Part 0b (3.6b): AGENTOS_MOCK_LLM and LITELLM_LOCAL_MODEL_COST_MAP are set here (not in root conftest)
    so they apply only to tests that need LLM mocking.
    """
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    yield
