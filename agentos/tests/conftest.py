import os
import pytest

@pytest.fixture(autouse=True)
def set_mock_llm():
    """Ensure AGENTOS_MOCK_LLM=1 is set for all tests to run them offline."""
    os.environ["AGENTOS_MOCK_LLM"] = "1"
