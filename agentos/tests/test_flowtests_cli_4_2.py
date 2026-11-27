"""4.2 `agentos test` CLI (MOCK): exit code 0 only if every case passes, 1 on a failing case, 2 on a setup error;
JUnit output; same storage resolution as the server (--project)."""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from agentos.flowtests import TestCase, flowtests_store_for
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord

UC07 = Path(__file__).resolve().parents[2] / "examples" / "usecases" / "07-support-desk-copilot"
FLOW = json.loads((UC07 / "flows" / "support_desk.flow.json").read_text(encoding="utf-8"))
TICKETS = json.loads((UC07 / "inputs" / "tickets.json").read_text(encoding="utf-8"))
FX = [{"kind": "http", "method": "GET", "url": "https://jsonplaceholder.typicode.com/users/1", "body": {"id": 1}}]


def normal(**kw) -> TestCase:
    return TestCase(flow_id=FLOW["id"], name="normal", input=TICKETS["normal"], fixtures=FX,
                    mock_responses={"triage": "NORMAL. Billing address question."}, **kw)


def _cli(args, project):
    from typer.testing import CliRunner

    from agentos.cli.main import app

    return CliRunner().invoke(app, ["test", *args, "--project", str(project)])


def _seed(project, cases):
    async def go():
        st = await open_storage(str(project), backend="file")
        try:
            await st.flows.put_draft(FlowRecord(**FLOW))
            store = flowtests_store_for(st)
            for c in cases:
                await store.put_case(c)
        finally:
            await st.close()
    asyncio.run(go())


@pytest.fixture
def cli_project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("CREWAI_TELEMETRY_OPT_OUT", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    project = tmp_path / "proj"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return project


@pytest.mark.parametrize("good,code", [(True, 0), (False, 1)])
def test_cli_exit_codes_and_junit(cli_project, tmp_path, good, code):
    exp = "succeeded" if good else "failed"
    _seed(cli_project, [normal(expectations=[{"kind": "status", "equals": exp}], tags=["smoke"])])
    out = tmp_path / "junit.xml"
    res = _cli([FLOW["id"], "--junit", str(out), "--tags", "smoke"], cli_project)
    assert res.exit_code == code, res.output
    root = ET.fromstring(out.read_text(encoding="utf-8"))
    assert root.find("testsuite").get("failures") == ("0" if good else "1")
    assert ("1/1 passed" if good else "0/1 passed") in res.output


def test_cli_setup_errors_exit_2(cli_project):
    assert _cli(["nope"], cli_project).exit_code == 2  # no cases
    _seed(cli_project, [normal()])
    assert _cli([FLOW["id"], "--version", "3"], cli_project).exit_code == 2  # version not found
    assert _cli([FLOW["id"], "--model", "gpt"], cli_project).exit_code == 2  # bad model spec
