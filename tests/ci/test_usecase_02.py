"""CI test for Use Case 02: Dynamic LLM Provider Fallback & Policy Editor."""

import os
from pathlib import Path

# Ensure mock LLM execution
os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "02-provider-fallback"


def test_usecase_02_benign_failover_and_disabled_invariants():
    """Verify that Use Case 02 passes all execution modes: benign, failover, and disabled check."""
    import importlib.util

    run_path = USECASE_DIR / "run.py"
    spec = importlib.util.spec_from_file_location("usecase_02_run", run_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    policy = mod.load_policy_from_file()
    assert len(policy) >= 3

    # 1. Benign execution
    assert mod.run_benign(policy) is True

    # 2. Failover execution
    assert mod.run_failover(policy) is True

    # 3. Disabled check execution
    assert mod.run_disabled_check(policy) is True
