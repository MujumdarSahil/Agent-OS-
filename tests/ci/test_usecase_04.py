"""CI test for Use Case 04: Webhook Ingress Trigger and Untrusted Payload Labeling."""

import asyncio
import os
from pathlib import Path

# Ensure mock LLM execution
os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "04-webhook-trigger"


def test_usecase_04_webhook_trigger_and_labeling():
    """Verify that Use Case 04 passes all scenarios (benign, unsigned, replay, injection)."""
    import importlib.util

    run_path = USECASE_DIR / "run.py"
    spec = importlib.util.spec_from_file_location("usecase_04_run", run_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    success = asyncio.run(mod._run_usecase_async())
    assert success is True
