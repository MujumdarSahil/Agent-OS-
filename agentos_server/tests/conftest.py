import os
import pytest

@pytest.fixture(autouse=True)
def setup_server_test_env():
    """Default test environment for agentos_server test suite."""
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    os.environ["AGENTOS_TEST_MODE"] = "1"
    old_no_auth = os.environ.get("AGENTOS_V1_NO_AUTH")
    if old_no_auth is None:
        os.environ["AGENTOS_V1_NO_AUTH"] = "1"
    yield
    if old_no_auth is None:
        os.environ.pop("AGENTOS_V1_NO_AUTH", None)
    else:
        os.environ["AGENTOS_V1_NO_AUTH"] = old_no_auth
