"""4.3 environments (MOCK, file backend): migration keeps old behaviour, what runs where (resolved at run start),
promotion race (one wins), re-check against a changed policy, test gate, second-person rule, rollback refusal,
staging sends simulated in the worker, and the version diff flags every security-relevant change type."""

from __future__ import annotations

import asyncio
import threading

import pytest
import pytest_asyncio

from agentos.flows.environments import (
    DeploymentRaced,
    DeploymentRefused,
    DeploymentService,
    environment_version,
    ensure_new_flow_settings,
    migrate_all,
    policy_hash,
    resolve_run_target,
)
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.version_diff import version_diff
from agentos.flows.worker import FlowWorker
from agentos.queue.in_process import InProcessQueueBackend
from agentos.storage import open_storage
from agentos.storage.models import DeploymentRecord, FlowRecord, RunRecord
from agentos.storage.ports import DeploymentConflict

POLICY = SecurityPolicy(internal_domains=["corp.local"])
STRICT = SecurityPolicy(internal_domains=[])  # the admin removed corp.local: untrusted body to it now fails


def notify_flow(fid: str = "envf", to: str = "team@corp.local") -> dict:
    return {
        "id": fid, "name": fid, "entrypoint": "trig",
        "nodes": {"trig": {"id": "trig", "type": "manual_trigger", "config": {}},
                  "send": {"id": "send", "type": "send_email", "config": {},
                           "pinned_args": {"to": to, "subject": "S"}}},
        "edges": [{"source": "trig", "target": "send", "arg_mapping": {"body": "payload"}}],
    }


@pytest_asyncio.fixture
async def storage(tmp_path):
    s = await open_storage(str(tmp_path), backend="file")
    yield s
    await s.close()


async def publish(storage, flow: dict, by: str = "alice", policy=POLICY) -> int:
    await storage.flows.put_draft(FlowRecord(**flow))
    rec = await storage.flows.publish(flow["id"], "sha", policy_hash(policy), published_by=by, change_note="n")
    return rec.version


# ------------------------------------------------------------------------------------------------ migration (D2)


@pytest.mark.asyncio
async def test_migration_keeps_old_behaviour(storage):
    await publish(storage, notify_flow())
    await publish(storage, notify_flow(to="ops@corp.local"))
    await storage.flows.put_draft(FlowRecord(**notify_flow("draft_only")))
    assert await migrate_all(storage) == 2
    assert await migrate_all(storage) == 0  # idempotent
    assert (await storage.deployments.get("envf", "production")).version == 2  # = latest, as before 4.3
    assert await storage.deployments.get("envf", "staging") is None
    s = await storage.deployments.get_settings("envf")
    assert s.legacy and s.auto_deploy_production and s.auto_deploy_staging
    assert (await storage.deployments.get_settings("draft_only")).auto_deploy_production is True  # existed before


@pytest.mark.asyncio
async def test_new_flow_defaults_and_after_publish(storage):
    await ensure_new_flow_settings(storage, "envf", {"username": "bob"})
    v = await publish(storage, notify_flow())
    out = await DeploymentService(storage, POLICY).after_publish("envf", v, actor={"username": "bob"}, note="first")
    assert out["staging"] == {"deployed": True, "version": 1}
    assert out["production"]["deployed"] is False  # new flow: production does not move on publish
    assert await environment_version(storage, "envf", "production") is None


@pytest.mark.asyncio
async def test_legacy_flow_published_at_repository_level_runs_latest(storage):
    """A pre-4.3 flow whose webhook fired before any version existed keeps today's behaviour."""
    await storage.flows.put_draft(FlowRecord(**notify_flow()))
    assert await environment_version(storage, "envf", "production") is None  # migrated, nothing published yet
    await storage.flows.publish("envf", "sha", "p")
    assert await environment_version(storage, "envf", "production") == 1


@pytest.mark.asyncio
async def test_resolve_run_target(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    assert await resolve_run_target(storage, "envf") == (1, None)  # no production yet: latest (API compatibility)
    await storage.deployments.set(DeploymentRecord(flow_id="envf", environment="production", version=1), None)
    assert await resolve_run_target(storage, "envf") == (1, "production")
    assert await resolve_run_target(storage, "envf", "draft") == (None, "draft")
    with pytest.raises(ValueError):
        await resolve_run_target(storage, "envf", "staging")  # staging empty
    await storage.deployments.archive_version("envf", 1)
    with pytest.raises(DeploymentRefused):
        await resolve_run_target(storage, "envf", version=1)


# ------------------------------------------------------------------------------------------------ promote (D6)


@pytest.mark.asyncio
async def test_promotion_race_one_wins_async(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    await publish(storage, notify_flow(to="ops@corp.local"))
    svc = DeploymentService(storage, POLICY)
    res = await asyncio.gather(
        svc.deploy("envf", "production", 1, actor={"username": "a"}, expected_version=None),
        svc.deploy("envf", "production", 2, actor={"username": "b"}, expected_version=None),
        return_exceptions=True)
    assert sum(isinstance(r, dict) for r in res) == 1
    assert sum(isinstance(r, DeploymentRaced) for r in res) == 1


@pytest.mark.asyncio
async def test_promotion_race_one_wins_threads(storage, tmp_path):
    """Real concurrency: eight threads (own event loops, own storage objects) compare-and-set the same file."""
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    barrier = threading.Barrier(8)
    results: list = []

    def worker(i: int) -> None:
        async def go():
            st = await open_storage(str(tmp_path), backend="file")
            barrier.wait()
            try:
                await st.deployments.set(DeploymentRecord(flow_id="envf", environment="production", version=1,
                                                          deployed_by=f"t{i}"), None)
                results.append("won")
            except DeploymentConflict:
                results.append("lost")
            finally:
                await st.close()
        asyncio.run(go())

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("won") == 1 and results.count("lost") == 7
    assert len(await storage.deployments.history("envf")) == 1


@pytest.mark.asyncio
async def test_recheck_against_changed_policy_refuses(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    with pytest.raises(DeploymentRefused) as e:
        await DeploymentService(storage, STRICT).deploy("envf", "production", 1, actor={"username": "a"})
    assert "policy changed since it was published" in str(e.value)
    check = e.value.detail["checks"][0]
    assert check["name"] == "static_check" and not check["passed"] and check["policy_changed"]
    assert await storage.deployments.get("envf", "production") is None


@pytest.mark.asyncio
async def test_test_gate_block_and_warn(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    calls = []

    async def failing(flow_id, version, mode):
        calls.append(version)
        return {"passed": False, "message": "1 of 1 test cases failed", "suite_run_id": "s1"}

    s = await storage.deployments.get_settings("envf")
    await storage.deployments.put_settings(s.model_copy(update={"promote_test_gate": "block"}))
    svc = DeploymentService(storage, POLICY, test_gate_runner=failing)
    with pytest.raises(DeploymentRefused, match="tests did not pass"):
        await svc.deploy("envf", "production", 1, actor={"username": "a"})
    assert calls == [1]  # the exact version
    # staging promotions are not gated
    assert (await svc.deploy("envf", "staging", 1, actor={"username": "a"}))["to"] == 1
    await storage.deployments.put_settings(s.model_copy(update={"promote_test_gate": "warn"}))
    res = await svc.deploy("envf", "production", 1, actor={"username": "a"})
    assert res["warnings"] and "warn mode" in res["warnings"][0]


@pytest.mark.asyncio
async def test_second_person_rule(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow(), by="u_alice")
    s = await storage.deployments.get_settings("envf")
    await storage.deployments.put_settings(s.model_copy(update={"second_person": True}))
    svc = DeploymentService(storage, POLICY)
    with pytest.raises(DeploymentRefused, match="second-person"):
        await svc.deploy("envf", "production", 1, actor={"user_id": "u_alice", "username": "alice"})
    res = await svc.deploy("envf", "production", 1, actor={"user_id": "u_bob", "username": "bob"})
    assert res["record"]["deployed_by"] == "bob"
    # auto-deploy to production is skipped (not a failure) while the rule is on
    await storage.deployments.put_settings(s.model_copy(update={"second_person": True, "auto_deploy_production": True}))
    v2 = await publish(storage, notify_flow(to="ops@corp.local"), by="u_alice")
    out = await svc.after_publish("envf", v2, actor={"user_id": "u_alice"})
    assert out["production"]["deployed"] is False and "second-person" in out["production"]["reason"]


@pytest.mark.asyncio
async def test_rollback_refused_when_old_version_now_fails(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())  # v1: untrusted body to corp.local (fine while corp.local is internal)
    safe = notify_flow()
    safe["edges"] = [{"source": "trig", "target": "send", "arg_mapping": {}}]
    safe["nodes"]["send"]["pinned_args"]["body"] = "fixed text"
    await publish(storage, safe)  # v2: no untrusted data reaches the sink
    svc_then = DeploymentService(storage, POLICY)
    await svc_then.deploy("envf", "production", 2, actor={"username": "a"})
    with pytest.raises(DeploymentRefused, match="fails the security check"):
        await DeploymentService(storage, STRICT).deploy("envf", "production", 1, actor={"username": "a"},
                                                        action="rollback")
    assert (await storage.deployments.get("envf", "production")).version == 2  # unchanged
    res = await svc_then.deploy("envf", "production", 1, actor={"username": "a"}, action="rollback")
    assert res["from"] == 2 and res["to"] == 1 and res["record"]["action"] == "rollback"
    with pytest.raises(DeploymentRefused, match="earlier version"):
        await svc_then.deploy("envf", "production", 2, actor={"username": "a"}, action="rollback")


@pytest.mark.asyncio
async def test_archived_version_cannot_be_promoted(storage):
    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    await storage.deployments.archive_version("envf", 1)
    with pytest.raises(DeploymentRefused, match="archived"):
        await DeploymentService(storage, POLICY).deploy("envf", "staging", 1, actor=None)


# ------------------------------------------------------------------------------------------------ staging sends (D4)


async def _run(storage, env, version, transport: MockTransport, snapshot=None) -> list:
    queue = InProcessQueueBackend(storage=storage)
    run_id = f"run_{env}_{version}"
    await storage.runs.put(RunRecord(run_id=run_id, mission_name="envf", flow_id="envf", flow_version=version,
                                     status="queued", trigger="manual", environment=env, flow_snapshot=snapshot))
    await queue.enqueue(run_id=run_id, flow_id="envf", version=version or 0, inputs={"payload": "hello"})
    worker = FlowWorker(queue=queue, storage=storage, policy=POLICY,
                        transport_registry={"send_email": transport, "send_slack": MockTransport()})
    await worker.run_once()
    return [e for e in await storage.events.list(run_id) if e.type == "sink_committed"]


@pytest.mark.asyncio
async def test_staging_and_draft_sends_are_simulated_production_sends(storage):
    from agentos.flowtests.runner import flow_dict, snapshot

    await ensure_new_flow_settings(storage, "envf")
    await publish(storage, notify_flow())
    real = MockTransport()  # stands in for the production channel: counts real deliveries
    staged = await _run(storage, "staging", 1, real)
    assert real.sent_calls == [] and staged[0].data["result"]["status"] == "simulated"
    assert "staging" in staged[0].data["result"]["reason"]
    snap = snapshot(flow_dict(await storage.flows.get_draft("envf")), "draft", None)
    draft = await _run(storage, "draft", None, real, snap)
    assert real.sent_calls == [] and draft[0].data["result"]["status"] == "simulated"
    prod = await _run(storage, "production", 1, real)
    assert len(real.sent_calls) == 1 and prod[0].data["result"]["status"] == "sent"


# ------------------------------------------------------------------------------------------------ diff (D7)


def _base() -> dict:
    return {
        "id": "d", "name": "d", "entrypoint": "trig",
        "nodes": {
            "trig": {"id": "trig", "type": "manual_trigger", "config": {}},
            "check": {"id": "check", "type": "validator",
                      "config": {"field": "level", "field_type": "enum", "values": ["low", "high"]}},
            "gate": {"id": "gate", "type": "approval",
                     "config": {"prompt": "ok?", "approves": {"sink_node": "send", "args": ["body"]}}},
            "send": {"id": "send", "type": "send_email", "config": {},
                     "pinned_args": {"to": "team@corp.local", "subject": "S"}},
        },
        "edges": [{"source": "trig", "target": "gate", "arg_mapping": {"body": "payload"}},
                  {"source": "gate", "target": "send", "arg_mapping": {"body": "body"}}],
    }


def test_diff_flags_every_security_relevant_change_type():
    import copy

    old = _base()
    new = copy.deepcopy(old)
    new["nodes"]["send"]["pinned_args"]["to"] = "attacker@evil.example"          # recipient changed
    new["nodes"]["check"]["config"]["values"] = ["low", "high", "anything"]       # validator loosened
    del new["nodes"]["gate"]                                                      # approval removed
    new["edges"] = [{"source": "trig", "target": "send", "arg_mapping": {"body": "payload"}},
                    {"source": "trig", "target": "post", "arg_mapping": {"url": "payload"}}]
    new["nodes"]["post"] = {"id": "post", "type": "http_request", "config": {"method": "POST"}}  # sink added
    d = version_diff(old, new, POLICY)
    kinds = [x["kind"] for x in d["security"]]
    for k in ("sink_added", "recipient_changed", "approval_removed", "validator_loosened", "new_untrusted_path",
              "analysis_changed"):
        assert k in kinds, (k, kinds)
    assert kinds.index("sink_added") < kinds.index("analysis_changed")  # ordered by kind, security first
    rc = next(x for x in d["security"] if x["kind"] == "recipient_changed")
    assert rc["from"] == "team@corp.local" and rc["to"] == "attacker@evil.example"
    assert d["analysis"]["before"]["passed"] and not d["analysis"]["after"]["passed"]
    assert "post" in d["nodes_added"] and "gate" in d["nodes_removed"]
    changed = {r["id"]: r for r in d["nodes_changed_detail"]}
    assert changed["send"]["pinned_args"]["to"] == ["team@corp.local", "attacker@evil.example"]
    # the reverse direction: the sink is removed, nothing is loosened
    back = version_diff(new, old, POLICY)
    assert "sink_removed" in [x["kind"] for x in back["security"]]
    assert "validator_loosened" not in [x["kind"] for x in back["security"]]


def test_diff_flags_extraction_loosened_and_host_change():
    def flow(values, url):
        return {"id": "x", "name": "x", "entrypoint": "trig", "nodes": {
            "trig": {"id": "trig", "type": "manual_trigger", "config": {}},
            "ext": {"id": "ext", "type": "quarantined_extraction",
                    "config": {"fields": [{"name": "kind", "type": "enum", "values": values}]}},
            "post": {"id": "post", "type": "http_request", "config": {"method": "POST"}, "pinned_args": {"url": url}}},
            "edges": [{"source": "trig", "target": "ext", "arg_mapping": {"text": "payload"}},
                      {"source": "ext", "target": "post", "arg_mapping": {"body": "kind"}}]}
    d = version_diff(flow(["a", "b"], "https://api.corp.local/x"), flow(["a", "b", "c"], "https://evil.example/x"),
                     POLICY)
    kinds = {x["kind"]: x for x in d["security"]}
    assert "extraction_loosened" in kinds and "values added: c" in kinds["extraction_loosened"]["detail"]
    assert kinds["recipient_changed"]["detail"] == "host: api.corp.local -> evil.example"


def test_identical_versions_have_an_empty_diff():
    d = version_diff(_base(), _base(), POLICY)
    assert d["empty"] and d["security"] == []
