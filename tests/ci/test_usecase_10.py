"""CI test for Use Case 10: alerts and notifications (MOCK: no model, local Slack stand-in, nothing leaves the machine)."""

import asyncio
import importlib.util
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "10-alerts-notifications"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, USECASE_DIR / file)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_usecase_10_alerts_and_notifications():
    """benign Slack note sent escaped; exfil blocked -> attack alert without the attacker's text; untrusted Slack
    text refused to a non-internal channel and escaped to an internal one; webhook host pinned; outbox retries and
    never re-sends after a restart."""
    assert asyncio.run(_load("usecase_10_run", "run.py")._run_usecase_async()) is True
