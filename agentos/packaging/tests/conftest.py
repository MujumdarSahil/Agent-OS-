import os
import pytest

os.environ.setdefault("AGENTOS_MOCK_LLM", "1")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

@pytest.fixture(autouse=True)
def setup_packaging_env():
    os.environ["AGENTOS_MOCK_LLM"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
