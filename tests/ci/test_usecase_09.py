"""CI test for Use Case 09: phishing triage with quarantined extraction (MOCK: scripted model, recorded outbox)."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path

os.environ["AGENTOS_MOCK_LLM"] = "1"

USECASE_DIR = Path(__file__).resolve().parent.parent.parent / "examples" / "usecases" / "09-phishing-triage"


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, USECASE_DIR / file)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_usecase_09_phishing_triage():
    """benign -> one alert to the pinned security address from extracted fields only; injection answers ->
    rejected, defaults, nothing sent; steering to legit -> approval needed, nothing to the attacker; an
    enum recipient and a destructive sink gated only by extraction -> publish refused."""
    assert asyncio.run(_load("usecase_09_run", "run.py")._run_usecase_async()) is True


def test_usecase_09_flow_has_no_free_text_extraction_and_pinned_recipients():
    flow = json.loads((USECASE_DIR / "flows" / "phishing_triage.flow.json").read_text(encoding="utf-8"))
    fields = flow["nodes"]["extract"]["config"]["fields"]
    assert {f["type"] for f in fields} <= {"enum", "bool", "int_range", "pattern", "allowlist"}
    assert flow["nodes"]["alert_security"]["pinned_args"]["to"] == "security@corp.local"
    assert flow["nodes"]["send_reply"]["pinned_args"]["to"] == "service-desk@corp.local"
