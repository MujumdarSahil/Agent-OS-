"""CI test for Use Case 11: users, login and roles (MOCK: in-process app, temp AgentOS home, MockTransport)."""

import asyncio
import importlib.util
import os
from pathlib import Path

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "11-access-roles"


def test_usecase_11_access_roles():
    """setup needs the local token; builder publishes, approver approves (who is recorded); viewer approve, CSRF,
    enumeration, brute force, revoked token and separation of duties are refused."""
    saved = dict(os.environ)  # run.py sets its own temp home and flags at import: keep them out of other tests
    try:
        spec = importlib.util.spec_from_file_location("usecase_11_run", USECASE_DIR / "run.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert asyncio.run(mod._run_usecase_async()) is True
    finally:
        os.environ.clear()
        os.environ.update(saved)
