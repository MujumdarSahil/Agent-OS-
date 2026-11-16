"""CI test for Use Case 03: Flow Lifecycle, Worker Leasing & Fencing, and Dead-Letter Recovery."""

import os
from pathlib import Path

# Ensure mock LLM execution
os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "03-flow-queue-worker"


def test_usecase_03_flow_queue_and_worker_fencing():
    """Verify that Use Case 03 passes all modes: benign, failover/fencing, and dead_letter."""
    import importlib.util

    run_path = USECASE_DIR / "run.py"
    spec = importlib.util.spec_from_file_location("usecase_03_run", run_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # 1. Benign execution
    assert mod.run_benign() is True

    # 2. Failover and fencing safety
    assert mod.run_failover() is True

    # 3. Poison-pill dead-letter isolation
    assert mod.run_dead_letter() is True
