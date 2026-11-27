"""CI test for Use Case 15 (4.2): a flow test suite for the use case 07 support desk (MOCK)."""

import asyncio
import importlib.util
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "15-flow-tests"


def test_usecase_15_flow_tests():
    spec = importlib.util.spec_from_file_location("usecase_15_run", USECASE_DIR / "run.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert asyncio.run(mod._run_usecase_async()) is True
