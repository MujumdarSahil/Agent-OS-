"""CI test for Use Case 06: HTTP requests and branching (MOCK: fake DNS/HTTP, no real network)."""

import asyncio
import importlib.util
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "06-http-and-branching"


def test_usecase_06_http_and_branching():
    """Benign fetch->branch->internal email works; SSRF, injected URL and attacker predicate are blocked."""
    spec = importlib.util.spec_from_file_location("usecase_06_run", USECASE_DIR / "run.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert asyncio.run(mod._run_usecase_async()) is True
