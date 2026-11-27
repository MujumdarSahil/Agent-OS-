"""4.3 `agentos flows versions|diff|promote|rollback` (MOCK, file backend, same storage resolution as the server):
exit 0 ok, 1 refused (failed check, second person, lost race), 2 setup error; promotions are audited."""

from __future__ import annotations

import asyncio

import pytest

from agentos.flows.environments import ensure_new_flow_settings, policy_hash
from agentos.flows.policy import SecurityPolicy
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord

FID = "cli_env"


def flow(to: str) -> dict:
    return {"id": FID, "name": FID, "entrypoint": "trig",
            "nodes": {"trig": {"id": "trig", "type": "manual_trigger", "config": {}},
                      "send": {"id": "send", "type": "send_email", "config": {},
                               "pinned_args": {"to": to, "subject": "S"}}},
            "edges": [{"source": "trig", "target": "send", "arg_mapping": {"body": "payload"}}]}


def _cli(args, project):
    from typer.testing import CliRunner

    from agentos.cli.main import app

    return CliRunner().invoke(app, ["flows", *args, "--project", str(project)])


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "corp.local")
    p = tmp_path / "proj"
    p.mkdir()
    (p / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")

    async def seed():
        st = await open_storage(str(p), backend="file")
        try:
            await ensure_new_flow_settings(st, FID)
            ph = policy_hash(SecurityPolicy(internal_domains=["corp.local"]))
            for to in ("team@corp.local", "ops@corp.local"):
                await st.flows.put_draft(FlowRecord(**flow(to)))
                await st.flows.publish(FID, "sha", ph, published_by="alice", change_note=f"to {to}")
        finally:
            await st.close()
    asyncio.run(seed())
    return p


def test_cli_versions_diff_promote_rollback_exit_codes(project, monkeypatch):
    res = _cli(["versions", FID], project)
    assert res.exit_code == 0, res.output
    assert "v2" in res.output and "v1" in res.output  # (nothing deployed yet; rich may shorten the note column)
    d = _cli(["diff", FID, "--from", "1", "--to", "2"], project)
    assert d.exit_code == 0 and "recipient_changed" in d.output and "team@corp.local -> ops@corp.local" in d.output
    assert _cli(["promote", FID, "--version", "2", "--to", "production"], project).exit_code == 0
    # lost race: the caller expected production to be empty
    raced = _cli(["promote", FID, "--version", "1", "--to", "production", "--expected", "1"], project)
    assert raced.exit_code == 1 and "changed meanwhile" in raced.output
    assert _cli(["rollback", FID, "--to-version", "1", "--env", "production"], project).exit_code == 0
    # setup errors
    assert _cli(["promote", FID, "--version", "9", "--to", "production"], project).exit_code == 2
    assert _cli(["promote", FID, "--version", "1", "--to", "qa"], project).exit_code == 2
    assert _cli(["diff", FID, "--from", "x", "--to", "1"], project).exit_code == 2
    # refused: the current policy no longer treats corp.local as internal
    monkeypatch.setenv("AGENTOS_INTERNAL_DOMAINS", "")
    refused = _cli(["promote", FID, "--version", "2", "--to", "staging"], project)
    assert refused.exit_code == 1 and "fails the security check" in refused.output

    async def audit_actions():
        from agentos.audit import AuditLog, audit_store_for
        from agentos.security.vault import MasterKey

        st = await open_storage(str(project), backend="file")
        try:
            text = await AuditLog(audit_store_for(st), MasterKey.load(create=False).key).export_jsonl()
        finally:
            await st.close()
        return text
    text = asyncio.run(audit_actions())
    assert '"flow.promote"' in text and '"flow.rollback"' in text and '"refused"' in text
