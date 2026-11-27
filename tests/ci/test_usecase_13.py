"""CI test for Use Case 13: "Describe it" natural-language builder (MOCK: in-process app, temp AgentOS home,
scripted builder model)."""

import asyncio
import importlib.util
import os
from pathlib import Path

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "13-describe-it"


def test_usecase_13_describe_it():
    """benign draft passes and publishes only when the owner publishes; injection never yields a publishable unsafe
    flow (pin fix then publishes); recipient-from-message refused; invented recipient -> question; key refused."""
    saved = dict(os.environ)  # run.py sets its own temp home and flags at import: keep them out of other tests
    try:
        spec = importlib.util.spec_from_file_location("usecase_13_run", USECASE_DIR / "run.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert asyncio.run(mod._run_usecase_async()) is True
    finally:
        os.environ.clear()
        os.environ.update(saved)
