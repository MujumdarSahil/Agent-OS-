"""
2.3 node catalog - runtime and static behaviour (all MOCK: fake DNS resolver and HTTP sender,
MockTransport for email, FileStorage). No real network.
"""

from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest
import pytest_asyncio

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition, InvalidFlowConfigError
from agentos.flows.net_guard import HttpRequestTransport, RawResponse
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.specs import BUILTIN_NODE_SPECS, SideEffectClass, effective_side_effect
from agentos.flows.state import NodeState, RunStatus
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord, RunRecord

PUBLIC = {"example.com": ["93.184.216.34"], "api.example.com": ["93.184.216.35"],
          "attacker.example": ["203.0.113.66"], "internal.corp": ["10.20.0.5"]}
POLICY = SecurityPolicy(internal_domains={"corp.local"}, http_allowlist=["internal.corp"])


class FakeHttp:
    def __init__(self, routes=None, fail=None):
        self.routes = routes or {}
        self.fail = fail
        self.calls = []
        self.transport = HttpRequestTransport(allowlist=POLICY.http_allowlist,
                                              resolver=lambda h, p: PUBLIC[h], sender=self._send)

    def _send(self, method, target, path, headers, body, timeout_s, max_bytes):
        self.calls.append({"method": method, "host": target.host, "path": path, "headers": dict(headers), "body": body})
        if self.fail:
            raise self.fail
        return self.routes.get((target.host, path), RawResponse(200, {"content-type": "text/plain"}, b"public page text"))


@pytest_asyncio.fixture
async def storage(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(project), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


def flow(fid, entry, nodes, edges):
    return FlowDefinition(
        id=fid, entrypoint=entry,
        nodes={k: {"id": k, "type": v[0], "config": v[1] if len(v) > 1 else {}, "pinned_args": v[2] if len(v) > 2 else {}}
               for k, v in nodes.items()},
        edges=edges,
    )


def engine(fd, storage, http=None, email=None, **kw):
    reg = {"send_email": email or MockTransport()}
    if http is not None:
        reg["http_request"] = http.transport
    return FlowEngine(fd, storage, policy=POLICY, transport_registry=reg, **kw)


async def events(storage, run_id):
    return await storage.events.list(run_id, after_seq=0)


# ------------------------------------------------------------------ contract tests

NEW_TYPES = ["http_request", "condition", "merge", "wait", "error_handler", "subflow"]


@pytest.mark.parametrize("node_type", NEW_TYPES)
def test_contract_new_node_specs(node_type):
    spec = BUILTIN_NODE_SPECS[node_type]
    for schema in (spec.config_schema, spec.input_schema, spec.output_schema):
        jsonschema.Draft202012Validator.check_schema(schema)
    assert spec.type == node_type


def test_contract_http_request_side_effect_by_method_and_sink_rules():
    assert effective_side_effect("http_request", {"method": "GET"}) == SideEffectClass.READ
    assert effective_side_effect("http_request", {"method": "POST"}) == SideEffectClass.EXTERNAL_SEND
    assert effective_side_effect("http_request", {"method": "DELETE"}) == SideEffectClass.DESTRUCTIVE
    rules = BUILTIN_NODE_SPECS["http_request"].sink_rules
    assert rules["url"].required_integrity == "trusted"
    assert {rules[a].condition for a in ("body", "query", "headers")} == {"untrusted_only_to_allowlisted_hosts"}


# ------------------------------------------------------------------ condition + control dependency

def routing_flow():
    return flow("route", "trig", {
        "trig": ("manual_trigger",),
        "cond": ("condition", {"expression": "nodes.trig.payload.priority == 'high'"}),
        "notify": ("send_email", {}, {"to": "support@corp.local", "subject": "High priority", "body": "See ticket"}),
        "later": ("llm",),
    }, [
        {"source": "trig", "target": "cond"},
        {"source": "cond", "target": "notify", "branch": "true"},
        {"source": "cond", "target": "later", "branch": "false"},
    ])


@pytest.mark.asyncio
async def test_benign_routing_untrusted_predicate_to_pinned_internal_email(storage):
    fd = routing_flow()
    assert StaticFlowAnalyzer(fd, POLICY).verify().is_valid
    email = MockTransport()
    st = await engine(fd, storage, email=email).run(run_id="r_route", inputs={"priority": "high"})
    assert st.status == RunStatus.SUCCEEDED
    assert st.node_states["notify"] == NodeState.SUCCEEDED and st.node_states["later"] == NodeState.SKIPPED
    assert len(email.sent_calls) == 1
    started = next(e for e in await events(storage, "r_route") if e.type == "node_started" and e.data["node_id"] == "notify")
    assert started.data["control_label"]["integrity"] == "untrusted"  # shown in provenance
    assert "cond" in started.data["control_label"]["sources"]


def destructive_flow(expression):
    return flow("destroy", "hook", {
        "hook": ("webhook_trigger",),
        "cond": ("condition", {"expression": expression}),
        "wipe": ("http_request", {"method": "DELETE"}, {"url": "https://internal.corp/api/records/1"}),
    }, [
        {"source": "hook", "target": "cond"},
        {"source": "cond", "target": "wipe", "branch": "true"},
    ])


@pytest.mark.asyncio
async def test_attacker_predicate_cannot_trigger_destructive_sink(storage):
    fd = destructive_flow("nodes.hook.payload.action == 'delete'")
    res = StaticFlowAnalyzer(fd, POLICY).verify()
    assert not res.is_valid and any(v.node_id == "wipe" and v.target_arg == "(control)" for v in res.violations)
    http = FakeHttp()
    st = await engine(fd, storage, http=http).run(run_id="r_destroy", inputs={"action": "delete"})
    assert st.status == RunStatus.FAILED and "trusted control dependency" in (st.error or "")
    assert http.calls == []


@pytest.mark.asyncio
async def test_trusted_predicate_allows_destructive_sink(storage):
    fd = destructive_flow("1 == 1")
    assert StaticFlowAnalyzer(fd, POLICY).verify().is_valid
    http = FakeHttp()
    st = await engine(fd, storage, http=http).run(run_id="r_destroy_ok", inputs={})
    assert st.status == RunStatus.SUCCEEDED and http.calls[0]["method"] == "DELETE"


# ------------------------------------------------------------------ http_request rules

def http_flow(cfg, pinned=None, mapping=None):
    edges = [{"source": "hook", "target": "req", "arg_mapping": mapping or {}}]
    return flow("http", "hook", {"hook": ("webhook_trigger",), "req": ("http_request", cfg, pinned or {})}, edges)


@pytest.mark.asyncio
async def test_get_public_page_response_is_untrusted(storage):
    fd = http_flow({"method": "GET"}, {"url": "https://example.com/news"})
    assert StaticFlowAnalyzer(fd, POLICY).verify().is_valid
    st = await engine(fd, storage, http=FakeHttp()).run(run_id="r_get", inputs={})
    assert st.status == RunStatus.SUCCEEDED
    assert st.node_outputs["req"]["body"] == "public page text"
    assert st.node_output_labels["req"]["body"].integrity == "untrusted"


def test_untrusted_url_is_refused_statically():
    res = StaticFlowAnalyzer(http_flow({"method": "GET"}, mapping={"url": "payload"}), POLICY).verify()
    assert any(v.target_arg == "url" for v in res.violations)
    res2 = StaticFlowAnalyzer(http_flow({"method": "GET", "url": "{{ nodes.hook.payload.link }}"}), POLICY).verify()
    assert any(v.target_arg == "url" for v in res2.violations)


@pytest.mark.asyncio
async def test_post_untrusted_body_external_refused_internal_allowed(storage):
    ext = http_flow({"method": "POST", "body": "{{ nodes.hook.payload.text }}"}, {"url": "https://api.example.com/in"})
    res = StaticFlowAnalyzer(ext, POLICY).verify()
    assert any(v.target_arg == "body" for v in res.violations)
    http = FakeHttp()
    st = await engine(ext, storage, http=http).run(run_id="r_post_ext", inputs={"text": "secret plans"})
    assert st.status == RunStatus.FAILED and http.calls == []

    internal = http_flow({"method": "POST", "body": "{{ nodes.hook.payload.text }}"}, {"url": "https://internal.corp/in"})
    assert StaticFlowAnalyzer(internal, POLICY).verify().is_valid
    st2 = await engine(internal, storage, http=http).run(run_id="r_post_int", inputs={"text": "ok"})
    assert st2.status == RunStatus.SUCCEEDED and http.calls[-1]["body"] == b"ok"


def test_get_query_built_from_data_follows_host_rule():
    cfg = {"method": "GET", "query": {"q": "{{ nodes.hook.payload.term }}"}}
    assert any(v.target_arg == "query" for v in StaticFlowAnalyzer(http_flow(cfg, {"url": "https://example.com/s"}), POLICY).verify().violations)
    assert StaticFlowAnalyzer(http_flow(cfg, {"url": "https://internal.corp/s"}), POLICY).verify().is_valid
    static_q = {"method": "GET", "query": {"q": "weather"}}
    assert StaticFlowAnalyzer(http_flow(static_q, {"url": "https://example.com/s"}), POLICY).verify().is_valid


@pytest.mark.asyncio
async def test_ssrf_to_metadata_blocked_at_runtime(storage):
    fd = http_flow({"method": "GET"}, {"url": "http://169.254.169.254/latest/meta-data/"})
    http = FakeHttp()
    st = await engine(fd, storage, http=http).run(run_id="r_ssrf", inputs={})
    assert st.status == RunStatus.FAILED and "169.254.169.254" in (st.error or "") and http.calls == []


@pytest.mark.asyncio
async def test_vault_credential_header_sent_but_never_recorded(storage):
    fd = http_flow({"method": "GET", "headers": {"Authorization": {"vault": "api_token"}}}, {"url": "https://api.example.com/me"})
    http = FakeHttp()
    st = await engine(fd, storage, http=http, secret_resolver=lambda name: "Bearer sk-test-123").run(run_id="r_vault", inputs={})
    assert st.status == RunStatus.SUCCEEDED and http.calls[0]["headers"]["Authorization"] == "Bearer sk-test-123"
    assert all("sk-test-123" not in e.model_dump_json() for e in await events(storage, "r_vault"))


def test_vault_header_requires_pinned_url():
    with pytest.raises(ValueError, match="pinned URL"):  # pydantic wraps InvalidFlowConfigError
        http_flow({"method": "GET", "url": "{{ nodes.hook.payload.u }}", "headers": {"X-Key": {"vault": "k"}}})


# ------------------------------------------------------------------ merge

@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["all", "first"])
async def test_merge_joins_parallel_branches(storage, mode):
    fd = flow(f"merge_{mode}", "trig", {
        "trig": ("manual_trigger",),
        "a": ("llm",), "b": ("llm",),
        "m": ("merge", {"mode": mode}),
    }, [{"source": "trig", "target": "a", "arg_mapping": {"prompt": "payload"}},
        {"source": "trig", "target": "b"}, {"source": "a", "target": "m"}, {"source": "b", "target": "m"}])
    st = await engine(fd, storage).run(run_id=f"r_merge_{mode}", inputs={"x": 1})
    assert st.status == RunStatus.SUCCEEDED
    assert st.node_output_labels["m"]["*"].integrity == "untrusted"  # join includes the untrusted llm branch
    if mode == "all":
        assert set(st.node_outputs["m"]["inputs"]) == {"a", "b"}


# ------------------------------------------------------------------ error_handler

def handler_flow(with_handler=True):
    nodes = {"trig": ("manual_trigger",), "req": ("http_request", {"method": "GET"}, {"url": "https://example.com/x"})}
    edges = [{"source": "trig", "target": "req"}]
    if with_handler:
        nodes["oops"] = ("error_handler",)
        edges.append({"source": "req", "target": "oops", "branch": "on_error"})
    return flow("handled", "trig", nodes, edges)


@pytest.mark.asyncio
async def test_error_handler_receives_untrusted_error_info(storage):
    st = await engine(handler_flow(), storage, http=FakeHttp(fail=ConnectionError("upstream reset"))).run(run_id="r_err", inputs={})
    assert st.status == RunStatus.SUCCEEDED
    assert st.node_outputs["oops"]["error_type"] == "ConnectionError" and "upstream reset" in st.node_outputs["oops"]["message"]
    assert st.node_output_labels["oops"]["message"].integrity == "untrusted"


@pytest.mark.asyncio
async def test_unhandled_failure_fails_run_and_security_blocks_are_not_handled(storage):
    st = await engine(handler_flow(False), storage, http=FakeHttp(fail=ConnectionError("x"))).run(run_id="r_err2", inputs={})
    assert st.status == RunStatus.FAILED
    blocked = flow("blocked", "trig", {
        "trig": ("manual_trigger",), "req": ("http_request", {"method": "GET"}, {"url": "http://127.0.0.1/admin"}),
        "oops": ("error_handler",)}, [{"source": "trig", "target": "req"}, {"source": "req", "target": "oops", "branch": "on_error"}])
    st2 = await engine(blocked, storage, http=FakeHttp()).run(run_id="r_err3", inputs={})
    assert st2.status == RunStatus.FAILED and st2.node_states.get("oops") != NodeState.SUCCEEDED


# ------------------------------------------------------------------ wait

@pytest.mark.asyncio
async def test_wait_pauses_and_resumes_after_delay(storage):
    now = [1000.0]
    fd = flow("waiter", "trig", {"trig": ("manual_trigger",), "pause": ("wait", {"delay_seconds": 60}), "after": ("llm",)},
              [{"source": "trig", "target": "pause"}, {"source": "pause", "target": "after"}])
    eng = engine(fd, storage, clock=lambda: now[0])
    st = await eng.run(run_id="r_wait", inputs={})
    assert st.status == RunStatus.WAITING and (await storage.runs.get("r_wait")).resume_at == 1060.0
    assert (await eng.resume("r_wait")).status == RunStatus.WAITING  # not due yet
    now[0] = 1061.0
    st2 = await eng.resume("r_wait")
    assert st2.status == RunStatus.SUCCEEDED and st2.node_states["after"] == NodeState.SUCCEEDED
    assert (await storage.runs.get("r_wait")).resume_at is None


def test_wait_max_delay_enforced(monkeypatch):
    monkeypatch.setenv("AGENTOS_WAIT_MAX_SECONDS", "10")
    with pytest.raises(ValueError, match="maximum"):  # pydantic wraps InvalidFlowConfigError
        flow("w", "trig", {"trig": ("manual_trigger",), "p": ("wait", {"delay_seconds": 20})}, [{"source": "trig", "target": "p"}])


@pytest.mark.asyncio
async def test_wait_frees_worker_and_scheduler_requeues(storage):
    from agentos.flows.worker import FlowWorker
    from agentos.queue.in_process import InProcessQueueBackend
    from agentos.triggers.scheduler import FlowScheduler, InProcessLeaderLock

    fd = flow("waiter2", "trig", {"trig": ("manual_trigger",), "pause": ("wait", {"delay_seconds": 0}), "after": ("llm",)},
              [{"source": "trig", "target": "pause"}, {"source": "pause", "target": "after"}])
    await publish(storage, fd)
    queue = InProcessQueueBackend(storage=storage)
    await storage.runs.put(RunRecord(run_id="r_w2", mission_name="waiter2", flow_id="waiter2", flow_version=1, status="queued"))
    await queue.enqueue(run_id="r_w2", flow_id="waiter2", version=1, inputs={})
    worker = FlowWorker(queue=queue, storage=storage, policy=POLICY)
    await worker.run_once()
    job = await queue.get_job_by_run_id("r_w2")
    assert (await storage.runs.get("r_w2")).status == "waiting" and job.status == "waiting"  # worker freed
    sched = FlowScheduler(storage=storage, queue=queue, leader_lock=InProcessLeaderLock())
    assert await sched.resume_due_timers() == ["r_w2"]
    await worker.run_once()
    assert (await storage.runs.get("r_w2")).status == "succeeded"


# ------------------------------------------------------------------ subflow

async def publish(storage, fd, analysis=True):
    rec = FlowRecord(id=fd.id, entrypoint=fd.entrypoint, nodes={k: v.model_dump() for k, v in fd.nodes.items()},
                     edges=[e.model_dump() for e in fd.edges])
    await storage.flows.put_draft(rec)
    summary = StaticFlowAnalyzer(fd, POLICY).summary() if analysis else None
    return await storage.flows.publish(fd.id, "sha", "ph", analysis=summary)


@pytest.mark.asyncio
async def test_subflow_exact_version_keeps_labels(storage):
    child = flow("child", "trig", {"trig": ("manual_trigger",), "sum": ("llm",)},
                 [{"source": "trig", "target": "sum", "arg_mapping": {"prompt": "payload"}}])
    await publish(storage, child)
    parent = flow("parent", "hook", {"hook": ("webhook_trigger",), "sub": ("subflow", {"flow_id": "child", "version": 1})},
                  [{"source": "hook", "target": "sub", "arg_mapping": {"text": "payload"}}])
    st = await engine(parent, storage).run(run_id="r_parent", inputs={"text": "hello"})
    assert st.status == RunStatus.SUCCEEDED
    assert "sum" in st.node_outputs["sub"]["outputs"]
    assert st.node_output_labels["sub"]["outputs"].integrity == "untrusted"  # webhook data stays untrusted
    child_run = st.node_outputs["sub"]["child_run_id"]
    assert (await storage.runs.get(child_run)).status == "succeeded"


def test_subflow_unknown_summary_outputs_untrusted():
    parent = flow("p2", "trig", {"trig": ("manual_trigger",), "sub": ("subflow", {"flow_id": "x", "version": 3})},
                  [{"source": "trig", "target": "sub"}])
    labels, _, _ = StaticFlowAnalyzer(parent, POLICY, subflow_summaries={})._propagate_labels_fixpoint()
    assert labels["sub"]["outputs"].integrity == "untrusted"


def test_subflow_with_approval_refused():
    parent = flow("p3", "trig", {"trig": ("manual_trigger",), "sub": ("subflow", {"flow_id": "c", "version": 1})},
                  [{"source": "trig", "target": "sub"}])
    res = StaticFlowAnalyzer(parent, POLICY, subflow_summaries={("c", 1): {"has_waiting": True, "output_label": None}}).verify()
    assert any(v.target_arg == "(subflow)" for v in res.violations)


@pytest.mark.asyncio
async def test_subflow_runtime_depth_limit(storage):
    child = flow("leaf", "trig", {"trig": ("manual_trigger",)}, [])
    await publish(storage, child)
    parent = flow("deep", "trig", {"trig": ("manual_trigger",), "sub": ("subflow", {"flow_id": "leaf", "version": 1})},
                  [{"source": "trig", "target": "sub"}])
    st = await engine(parent, storage, subflow_depth=5).run(run_id="r_deep", inputs={})
    assert st.status == RunStatus.FAILED and "deeper than" in (st.error or "")
