import os
import pytest

# Set at module import time so test collection of modules that import litellm does not trigger
# a remote cost-map fetch network timeout.
os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

@pytest.fixture(autouse=True)
def set_mock_llm():
    """Ensure AGENTOS_MOCK_LLM=1 and LITELLM_LOCAL_MODEL_COST_MAP=True are set for all tests in this suite.

    Part 0b (3.6b): these are set here (not in the root conftest) so only tests that use the LLM path
    get them, and their scope is explicit.
    """
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
