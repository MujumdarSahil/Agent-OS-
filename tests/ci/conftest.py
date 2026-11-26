"""
Conftest for tests/ci — sets AGENTOS_MOCK_LLM and LITELLM_LOCAL_MODEL_COST_MAP for CI use-case tests.

Part 0b (3.6b): these were previously set in the root conftest globally; now they are set only in the
sub-conftest of each test suite that needs them.  Some use-case test modules also set
AGENTOS_MOCK_LLM=1 at module level (before pytest imports them); that is fine and idempotent.
"""

import os
import pytest

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")


@pytest.fixture(autouse=True)
def ci_mock_llm_env():
    """Ensure mock-LLM env vars are set for every CI test in this suite."""
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    yield
