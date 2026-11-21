"""CI test for Use Case 08: MCP notes digest (MOCK: scripted LLM, local stdio MCP servers, recorded outbox)."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "08-mcp-notes"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, USECASE_DIR / file)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_usecase_08_mcp_notes():
    """benign -> one email to the pinned recipient; poisoned description -> override rejected, nothing to the
    attacker; rug pull -> call blocked and republish refused; shadowing -> look-alikes rejected."""
    assert asyncio.run(_load("usecase_08_run", "run.py")._run_usecase_async()) is True


def test_usecase_08_flow_uses_namespaced_mcp_tool_and_pinned_recipient():
    flow = json.loads((USECASE_DIR / "flows" / "mcp_notes.flow.json").read_text(encoding="utf-8"))
    agent = flow["nodes"]["drafter"]
    assert "mcp.notes.list_notes" in agent["config"]["tools"]
    assert agent["pinned_args"]["send_email.to"] == "team@corp.local"
