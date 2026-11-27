"""CI test for Use Case 14 (4.1b): look-alike recipients on an approval card (MOCK)."""

import asyncio
import importlib.util
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "14-lookalike-recipients"


def test_usecase_14_lookalike_recipients():
    spec = importlib.util.spec_from_file_location("usecase_14_run", USECASE_DIR / "run.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert asyncio.run(mod._run_usecase_async()) is True
