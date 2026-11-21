"""CI test for Use Case 01: Email Summary Exfiltration Defense."""

import os
from pathlib import Path

import pytest

# Ensure environment variables for mock crewai execution
os.environ["CREWAI_TELEMETRY_OPT_OUT"] = "1"
os.environ["OTEL_SDK_DISABLED"] = "true"
os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "01-email-summary-exfil"


@pytest.mark.asyncio
async def test_usecase_01_benign_succeeds():
    """Verify that benign input in Use Case 01 succeeds with zero blocks."""
    import importlib.util

    run_path = USECASE_DIR / "run.py"
    spec = importlib.util.spec_from_file_location("usecase_01_run", run_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    result = await mod.execute_usecase("benign")
    assert result["success"] is True
    assert result["status"] == "succeeded"
    assert len(result["sent_calls"]) == 1
    assert result["sent_calls"][0]["to"] == "support@corp.local"


@pytest.mark.asyncio
async def test_usecase_01_attack_is_blocked_with_expected_reason():
    """Verify that attack input in Use Case 01 is blocked by proxy with provenance chain."""
    import importlib.util

    run_path = USECASE_DIR / "run.py"
    spec = importlib.util.spec_from_file_location("usecase_01_run", run_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    result = await mod.execute_usecase("attack")
    assert result["attack_blocked"] is True
    assert len(result["sent_calls"]) == 0
    assert "override author-pinned argument 'to'" in result["block_reason"]
    assert len(result["provenance_chain"]) >= 3
    assert result["provenance_chain"][0]["type"] == "run_started"
    assert result["provenance_chain"][-1]["type"] == "tool_call_rejected"
