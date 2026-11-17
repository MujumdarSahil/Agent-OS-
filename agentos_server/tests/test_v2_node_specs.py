"""
2.4 backend contract tests (MOCK, FileStorage):
  - GET /api/v2/node-specs returns every BUILTIN_NODE_SPECS entry with the fields the
    visual builder depends on.
  - The publish-refusal payload format (node_id, target_arg, path, reason) stays stable,
    because the UI highlights violations from exactly these keys.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agentos.flows.specs import BUILTIN_NODE_SPECS
from agentos_server.app import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
UC01_FLOW = REPO_ROOT / "examples" / "usecases" / "01-email-summary-exfil" / "flow.json"

SPEC_KEYS = {
    "type",
    "side_effect",
    "idempotent",
    "timeout_seconds",
    "config_schema",
    "input_schema",
    "output_schema",
    "sink_rules",
    "constrained_fields",
}
VIOLATION_KEYS = {"node_id", "target_arg", "path", "reason"}


@pytest.fixture
def token():
    t = "test-token-node-specs"
    os.environ["AGENTOS_API_TOKEN"] = t
    yield t
    os.environ.pop("AGENTOS_API_TOKEN", None)


@pytest_asyncio.fixture
async def client(tmp_path, token):
    project = tmp_path / "project"
    project.mkdir()
    # Trusted internal domains are explicit admin config (no built-in default since the 2.0 cleanup).
    (project / "agentos.config.yaml").write_text(
        "preferred_tags: []\nsecurity:\n  internal_domains: [corp.local]\n", encoding="utf-8"
    )
    app = create_app(project_path=str(project))
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
        headers={"Authorization": f"Bearer {token}", "Host": "localhost"},
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_node_specs_lists_all_builtin_specs(client):
    r = await client.get("/api/v2/node-specs")
    assert r.status_code == 200
    body = r.json()
    assert [s["type"] for s in body] == sorted(BUILTIN_NODE_SPECS)
    for s in body:
        assert set(s) == SPEC_KEYS
        assert s["side_effect"] in {"none", "read", "write", "external_send", "destructive"}
    by_type = {s["type"]: s for s in body}
    # Sink rules are exposed so the UI can show which args need trusted values.
    assert by_type["send_email"]["side_effect"] == "external_send"
    assert by_type["send_email"]["sink_rules"], "send_email must expose its sink rules"
    for rule in by_type["send_email"]["sink_rules"].values():
        assert set(rule) == {"required_integrity", "allowlist_name", "condition"}


@pytest.mark.asyncio
async def test_model_choice_limited_to_enabled_providers(client, monkeypatch):
    """2.3 (MOCK): llm/agent 'model' must be served by an enabled provider; listed in /node-specs."""
    from agentos.llm.router_factory import set_fallback_policy_cache

    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    specs = {s["type"]: s for s in (await client.get("/api/v2/node-specs")).json()}
    assert "openai_gpt4o" in specs["agent"]["config_schema"]["properties"]["model"]["enum"]

    def flow(fid, model):
        return {"id": fid, "entrypoint": "t", "nodes": {
            "t": {"id": "t", "type": "manual_trigger", "config": {}},
            "l": {"id": "l", "type": "llm", "config": {"model": model}}},
            "edges": [{"source": "t", "target": "l"}]}

    assert (await client.post("/api/v2/flows", json=flow("m_ok", "openai_gpt4o"))).status_code == 201
    bad = await client.post("/api/v2/flows", json=flow("m_bad", "made-up-model"))
    assert bad.status_code == 400 and "enabled provider" in bad.text
    set_fallback_policy_cache([{"name": "openai_gpt4o", "enabled": False}])
    try:
        assert (await client.post("/api/v2/flows/m_ok/publish")).status_code == 400
    finally:
        set_fallback_policy_cache(None)
    assert (await client.post("/api/v2/flows/m_ok/publish")).status_code == 200


@pytest.mark.asyncio
async def test_subflow_cycle_and_unpublished_version_refused(client):
    """2.3 (MOCK): publish refuses subflow cycles across exact versions and unpublished versions."""
    def node(i, t, cfg=None):
        return {"id": i, "type": t, "config": cfg or {}}

    a1 = {"id": "fa", "entrypoint": "t", "nodes": {"t": node("t", "manual_trigger")}, "edges": []}
    assert (await client.post("/api/v2/flows", json=a1)).status_code == 201
    assert (await client.post("/api/v2/flows/fa/publish")).status_code == 200
    b1 = {"id": "fb", "entrypoint": "t", "nodes": {"t": node("t", "manual_trigger"),
                                                  "s": node("s", "subflow", {"flow_id": "fa", "version": 1})},
          "edges": [{"source": "t", "target": "s"}]}
    assert (await client.post("/api/v2/flows", json=b1)).status_code == 201
    published_b = await client.post("/api/v2/flows/fb/publish")
    assert published_b.status_code == 200 and published_b.json()["analysis"]["subflows"] == [["fa", 1]]
    a2 = {**a1, "nodes": {**a1["nodes"], "s": node("s", "subflow", {"flow_id": "fb", "version": 1})},
          "edges": [{"source": "t", "target": "s"}]}
    assert (await client.put("/api/v2/flows/fa", json=a2)).status_code == 200
    cyc = await client.post("/api/v2/flows/fa/publish")
    assert cyc.status_code == 400 and "cycle" in cyc.text
    missing = {"id": "fc", "entrypoint": "t", "nodes": {"t": node("t", "manual_trigger"),
                                                       "s": node("s", "subflow", {"flow_id": "fa", "version": 9})},
               "edges": [{"source": "t", "target": "s"}]}
    assert (await client.post("/api/v2/flows", json=missing)).status_code == 201
    assert "not published" in (await client.post("/api/v2/flows/fc/publish")).text


@pytest.mark.asyncio
async def test_node_specs_is_read_only(client):
    for method in ("POST", "PUT", "DELETE"):
        r = await client.request(method, "/api/v2/node-specs")
        assert r.status_code == 405, f"{method} should not be allowed"


def _uc01(flow_id: str) -> dict:
    flow = json.loads(UC01_FLOW.read_text(encoding="utf-8"))
    flow["id"] = flow_id
    flow["name"] = flow_id
    return flow


@pytest.mark.asyncio
async def test_publish_benign_uc01_ok(client):
    flow = _uc01("uc01_benign")
    assert (await client.post("/api/v2/flows", json=flow)).status_code == 201
    r = await client.post("/api/v2/flows/uc01_benign/publish")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "published"


@pytest.mark.asyncio
async def test_publish_refusal_violation_format_is_stable(client):
    attack = copy.deepcopy(_uc01("uc01_exfil"))
    # Exfiltration variant: recipient is no longer pinned, so the agent (fed by an
    # untrusted webhook) controls send_email.to.
    attack["nodes"]["agent_node"]["pinned_args"] = {}
    assert (await client.post("/api/v2/flows", json=attack)).status_code == 201
    r = await client.post("/api/v2/flows/uc01_exfil/publish")
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "Publish refused: security violations found"
    assert detail["violations"], "expected at least one violation"
    for v in detail["violations"]:
        assert set(v) == VIOLATION_KEYS
        assert isinstance(v["path"], list) and all(isinstance(p, str) for p in v["path"])
        assert isinstance(v["reason"], str) and v["reason"]
    assert any(v["node_id"] == "agent_node" for v in detail["violations"])
    # Unpinned recipient: the reason says so instead of "external recipient None".
    body = next(v for v in detail["violations"] if v["target_arg"] == "send_email.body")
    assert "recipient is not fixed (not pinned)" in body["reason"] and "None" not in body["reason"]
