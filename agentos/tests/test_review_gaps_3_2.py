"""3.2 Part 0 (MOCK): gaps from the 3.1 review.

0a. Deleting the audit log is "broken", not "empty": an independent anchor (seq, hash, MAC) lives in the main
    storage (.agentos/state), not the audit folder. Cases: delete log + head; delete the log only; replace with an
    older genuine copy (rollback); delete the anchor; a fresh install is still "empty".
0b. The server accepts as agent tools exactly what the picker offers (calculator, fetch_url, send_email,
    approved MCP tools): step types (approval, subflow, llm, agent, condition, ...) are refused at agent
    create/update, at flow save and at publish, and by the runtime proxy.
"""

from __future__ import annotations

import shutil

import pytest
from httpx import ASGITransport, AsyncClient

from agentos.audit import AuditLog, audit_anchor_for, audit_store_for
from agentos.flows.models import FlowDefinition, InvalidFlowConfigError
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.flows.tool_catalog import BUILTIN_CATALOG, ToolLookupError
from agentos.storage.file import open_file_storage

KEY = bytes(range(32))
STEP_TYPES = ["approval", "subflow", "llm", "agent", "condition", "validator", "quarantined_extraction",
              "webhook_trigger", "http_request", "merge", "wait", "error_handler"]


def _log(project) -> AuditLog:
    storage = open_file_storage(str(project))
    return AuditLog(audit_store_for(storage), KEY, anchor=audit_anchor_for(storage))


async def _filled(project, n=5) -> AuditLog:
    log = _log(project)
    for i in range(n):
        await log.record("flow.save", "flow", f"f{i}", details={"version": i})
    return log


# ------------------------------------------------------------------ 0a

@pytest.mark.asyncio
async def test_fresh_install_is_empty_and_anchor_lives_outside_the_audit_folder(tmp_path):
    assert (await _log(tmp_path).verify())["status"] == "empty"
    log = await _filled(tmp_path, 3)
    assert (await log.verify())["status"] == "ok"
    anchor = tmp_path / ".agentos" / "state" / "audit_anchor.json"
    assert anchor.exists() and anchor.parent != log.store.dir


@pytest.mark.asyncio
async def test_deleting_log_and_head_is_broken_not_empty(tmp_path):
    log = await _filled(tmp_path)
    log.store.path.unlink()
    log.store.head_path.unlink()
    res = await _log(tmp_path).verify()
    assert res["status"] == "broken" and res["reason"] == "audit log deleted or rolled back (anchor at seq 5)"
    assert res["first_broken_seq"] == 5


@pytest.mark.asyncio
async def test_deleting_the_log_only_is_broken(tmp_path):
    log = await _filled(tmp_path)
    log.store.path.unlink()
    res = await _log(tmp_path).verify()
    assert res["status"] == "broken" and "deleted or rolled back (anchor at seq 5)" in res["reason"]


@pytest.mark.asyncio
async def test_rollback_to_an_older_genuine_copy_is_broken(tmp_path):
    log = await _filled(tmp_path, 3)
    backup = tmp_path / "old-audit"
    shutil.copytree(log.store.dir, backup)  # genuine log + head at seq 3
    for i in range(3):
        await log.record("vault.secret.delete", "secret", f"s{i}")
    shutil.rmtree(log.store.dir)
    shutil.copytree(backup, log.store.dir)  # roll back: the old copy verifies on its own
    assert (await AuditLog(log.store, KEY).verify())["status"] == "ok"  # without the anchor: undetectable
    res = await _log(tmp_path).verify()
    assert res["status"] == "broken" and res["reason"] == "audit log deleted or rolled back (anchor at seq 6)"


@pytest.mark.asyncio
async def test_anchor_missing_or_forged_is_broken(tmp_path):
    log = await _filled(tmp_path, 2)
    anchor = tmp_path / ".agentos" / "state" / "audit_anchor.json"
    anchor.unlink()
    res = await _log(tmp_path).verify()
    assert res["status"] == "broken" and res["reason"] == "audit anchor missing"
    anchor.write_text('{"seq": 1, "hash": "%s", "mac": "%s"}' % ("0" * 64, "0" * 64), encoding="utf-8")
    assert (await _log(tmp_path).verify())["reason"] == "audit anchor is invalid"
    assert log is not None


@pytest.mark.asyncio
async def test_api_verify_reports_deletion(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-anchor")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    from agentos_server.app import create_app

    app = create_app(project_path=str(tmp_path))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": "Bearer test-token-anchor", "Host": "localhost"}) as c:
        await app.state.audit.record("flow.save", "flow", "x")
        await app.state.audit.record("flow.save", "flow", "y")
        shutil.rmtree(app.state.audit.store.dir)
        app.state.audit.store._loaded = False
        res = (await c.get("/api/v2/audit/verify")).json()
    assert res["status"] == "broken" and "anchor at seq 2" in res["reason"]


# ------------------------------------------------------------------ 0b

@pytest.mark.parametrize("name", STEP_TYPES)
def test_catalog_refuses_step_types_as_agent_tools(name):
    with pytest.raises(ToolLookupError) as err:
        BUILTIN_CATALOG.resolve(name)
    assert err.value.reason == "not_an_agent_tool" and "flow step, not an agent tool" in str(err.value)


@pytest.mark.parametrize("name", ["calculator", "fetch_url", "send_email"])
def test_catalog_accepts_the_picker_set(name):
    assert BUILTIN_CATALOG.resolve(name).name == name
    assert name in [e.name for e in BUILTIN_CATALOG.agent_tool_options()]


@pytest.mark.parametrize("name", ["approval", "subflow", "llm", "agent", "condition"])
def test_flow_save_and_publish_refuse_step_types_as_agent_tools(name):
    with pytest.raises((InvalidFlowConfigError, ValueError)) as err:
        FlowDefinition(id="agent_tools", entrypoint="trig",
                       nodes={"trig": {"id": "trig", "type": "manual_trigger"},
                              "agent": {"id": "agent", "type": "agent", "config": {"role": "r", "tools": [name]}}},
                       edges=[{"source": "trig", "target": "agent", "arg_mapping": {"task": "payload"}}])
    assert "not an agent tool" in str(err.value)
    # publish (the analyzer) refuses too, even for a flow that bypassed save validation
    from agentos.flows.models import NodeDefinition

    fd = FlowDefinition.model_construct(
        id="legacy", name="", version="2.0", entrypoint="trig", loops={},
        nodes={"trig": NodeDefinition(id="trig", type="manual_trigger"),
               "agent": NodeDefinition(id="agent", type="agent", config={"role": "r", "tools": [name]})},
        edges=[])
    res = StaticFlowAnalyzer(fd).verify()
    assert not res.is_valid and any("not an agent tool" in v.reason for v in res.violations)


@pytest.mark.asyncio
async def test_agent_api_refuses_step_types_and_accepts_picker_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTOS_API_TOKEN", "test-token-agent-tools")
    monkeypatch.delenv("AGENTOS_MONGO_URI", raising=False)
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    from agentos_server.app import create_app

    app = create_app(project_path=str(tmp_path))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost",
                           headers={"Authorization": "Bearer test-token-agent-tools", "Host": "localhost"}) as c:
        base = {"name": "a1", "role": "r", "goal": "g", "backstory": "b"}
        assert (await c.post("/api/v2/agents", json={**base, "tools": ["calculator"]})).status_code == 200
        for step in ("approval", "subflow", "llm", "agent", "condition"):
            r = await c.post("/api/v2/agents", json={**base, "tools": ["calculator", step]})  # update path
            assert r.status_code == 400 and "not an agent tool" in r.json()["detail"], step
        saved = (await c.get("/api/v2/agents/a1")).json()
        assert (saved.get("tools") or saved.get("tool_refs")) == ["calculator"]  # unchanged by the refused updates
        flow = {"id": "f_agent", "name": "f", "entrypoint": "trig",
                "nodes": {"trig": {"id": "trig", "type": "manual_trigger", "config": {}},
                          "ag": {"id": "ag", "type": "agent", "config": {"role": "r", "tools": ["approval"]}}},
                "edges": [{"source": "trig", "target": "ag", "arg_mapping": {"task": "payload"}}]}
        r = await c.post("/api/v2/flows", json=flow)
        assert r.status_code == 400 and "not an agent tool" in r.json()["detail"]


@pytest.mark.asyncio
async def test_runtime_proxy_refuses_step_types(tmp_path):
    from agentos.flows.policy import SecurityPolicy
    from agentos.flows.proxy import AgentOSToolProxy

    storage = open_file_storage(str(tmp_path))
    proxy = AgentOSToolProxy(run_id="r", agent_node_id="agent", storage=storage, policy=SecurityPolicy())
    with pytest.raises(ValueError):
        await proxy.invoke("agent", "approval", {})
