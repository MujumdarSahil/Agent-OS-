"""CI test for Use Case 16 (4.3): versions and environments: staging / production, promote with the test gate,
rollback keeps a started run on its version, re-check against the current policy (MOCK)."""

import asyncio
import importlib.util
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "16-environments"


def test_usecase_16_environments():
    spec = importlib.util.spec_from_file_location("usecase_16_run", USECASE_DIR / "run.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert asyncio.run(mod._run_usecase_async()) is True
