import os
import pytest

@pytest.fixture(autouse=True)
def setup_server_test_env():
    """Default test environment for agentos_server test suite."""
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    yield
