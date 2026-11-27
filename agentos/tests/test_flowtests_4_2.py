"""4.2 flow test cases (MOCK): every expectation kind (pass and fail with readable diffs), fixtures and the
"no fixture" failure, the tripwire (no real email/Slack/HTTP/DNS), save-from-run, review import, security test
generation, SECRET exclusion, model comparison, regression, the judge, test-usage tagging, file storage and JUnit
(CLI exit codes: test_flowtests_cli_4_2.py). Design: docs/evidence/4.2.md."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import pytest_asyncio

from agentos.flows.policy import SecurityPolicy
from agentos.flowtests import TestCase, TestEnv, execute_suite, flowtests_store_for, run_case
from agentos.flowtests.compare import comparison_row, regression
from agentos.flowtests.expectations import Observation, SinkCall, evaluate
from agentos.flowtests.generate import from_review, from_run, security_cases
from agentos.flowtests.junit import junit_xml
from agentos.flowtests.models import CaseResult, SuiteRun
from agentos.flowtests.runner import flow_dict
from agentos.storage import open_storage
from agentos.storage.models import FlowRecord
from benchmarks.awib import tripwire

UC07 = Path(__file__).resolve().parents[2] / "examples" / "usecases" / "07-support-desk-copilot"
FLOW = json.loads((UC07 / "flows" / "support_desk.flow.json").read_text(encoding="utf-8"))
UNSAFE = json.loads((UC07 / "flows" / "support_desk_unsafe.flow.json").read_text(encoding="utf-8"))
TICKETS = json.loads((UC07 / "inputs" / "tickets.json").read_text(encoding="utf-8"))
API = "https://jsonplaceholder.typicode.com/users/1"
FX = [{"kind": "http", "method": "GET", "url": API, "body": {"id": 1, "name": "Leanne"}}]
POLICY = SecurityPolicy(internal_domains={"corp.local"}, slack_channels={"support": True})

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _mock(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")
    monkeypatch.setenv("CREWAI_TELEMETRY_OPT_OUT", "1")


@pytest_asyncio.fixture
async def storage(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    st = await open_storage(str(proj), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield st
    await st.close()


def case(name="c", inp=None, **kw) -> TestCase:
    kw.setdefault("fixtures", FX)
    return TestCase(flow_id=FLOW["id"], name=name, input=inp if inp is not None else TICKETS["normal"], **kw)


def urgent(**kw) -> TestCase:
    return case("urgent", TICKETS["urgent"], mock_responses={"triage": "URGENT. Checkout returns HTTP 500."}, **kw)


def normal(**kw) -> TestCase:
    kw.setdefault("mock_responses", {"triage": "NORMAL. Billing address question."})
    return case("normal", TICKETS["normal"], **kw)


# ---------------------------------------------------------------------------- expectation kinds (unit)

def obs(**kw) -> Observation:
    base = dict(status="succeeded", outputs={"n": {"output": "Hello World", "body": '{"a": {"b": [1, 2]}}'},
                                              "x": {"severity": "high", "ok": True}},
                sinks=[SinkCall("send_email", "mail", ["oncall@corp.local"], "to")], approvals=["appr"],
                blocked=["agent"], cost_usd=0.02, duration_ms=120.0, model_calls=3)
    base.update(kw)
    return Observation(**base)


PASS_FAIL = [
    ({"kind": "status", "equals": "succeeded"}, {"kind": "status", "equals": "failed"}, "final status"),
    ({"kind": "output", "node": "n", "op": "equals", "value": "Hello World"},
     {"kind": "output", "node": "n", "op": "equals", "value": "Bye"}, "expected 'Bye'"),
    ({"kind": "output", "node": "n", "op": "contains", "value": "World"},
     {"kind": "output", "node": "n", "op": "contains", "value": "Mars"}, "contains"),
    ({"kind": "output", "node": "n", "op": "regex", "value": "^Hel+o"},
     {"kind": "output", "node": "n", "op": "regex", "value": "^Bye"}, "regex"),
    ({"kind": "output", "node": "n", "field": "$.body.a.b[1]", "op": "json_path_equals", "value": 2},
     {"kind": "output", "node": "n", "field": "$.body.a.b[0]", "op": "json_path_equals", "value": 2}, "json_path"),
    ({"kind": "extraction", "node": "x", "field": "severity", "equals": "high"},
     {"kind": "extraction", "node": "x", "field": "severity", "equals": "low"}, "expected 'low', got 'high'"),
    ({"kind": "sink", "target": "send_email", "op": "called"},
     {"kind": "sink", "target": "send_slack", "op": "called"}, "expected a call, got none"),
    ({"kind": "sink", "target": "send_slack", "op": "not_called"},
     {"kind": "sink", "target": "send_email", "op": "not_called"}, "expected no call, got 1 (oncall@corp.local)"),
    ({"kind": "sink", "target": "send_email", "op": "count", "n": 1},
     {"kind": "sink", "target": "send_email", "op": "count", "n": 2}, "expected 2 call(s), got 1"),
    ({"kind": "sink", "target": "send_email", "op": "called_with", "arg": "to", "value": "OnCall@corp.local"},
     {"kind": "sink", "target": "send_email", "op": "called_with", "arg": "to", "value": "boss@corp.local"},
     "expected a call with to = boss@corp.local, got oncall@corp.local"),
    ({"kind": "security", "op": "blocked"}, {"kind": "security", "op": "blocked", "node": "other"}, "nothing was"),
    ({"kind": "security", "op": "no_external_send"}, None, None),
    ({"kind": "approval_reached", "node": "appr"}, {"kind": "approval_reached", "node": "nope"}, "it did not"),
    ({"kind": "limits", "max_cost_usd": 0.05, "max_duration_ms": 500, "max_model_calls": 3},
     {"kind": "limits", "max_model_calls": 2}, "model calls over the limit"),
]


@pytest.mark.parametrize("ok,bad,msg", PASS_FAIL)
async def test_each_expectation_kind_passes_and_fails_with_a_readable_diff(ok, bad, msg):
    c = TestCase(flow_id="f", name="t", expectations=[ok] + ([bad] if bad else []))
    assert evaluate(c.expectations[0], obs(), POLICY) is None
    if bad:
        f = evaluate(c.expectations[1], obs(), POLICY)
        assert f is not None and msg in f.message, f
        assert "expected" in f.model_dump() and "actual" in f.model_dump()


async def test_security_expectations_fail_cases():
    out = obs(sinks=[SinkCall("send_email", "m", ["mallory@attacker.example"], "to"),
                     SinkCall("send_slack", "s", ["attacker-dm"], "channel"),
                     SinkCall("http_request", "h", ["attacker.example"], "host")])
    c = TestCase(flow_id="f", name="t", expectations=[{"kind": "security", "op": "no_external_send"},
                                                      {"kind": "security", "op": "publish_refused"}])
    f = evaluate(c.expectations[0], out, POLICY)
    assert "mallory@attacker.example" in f.message and "#attacker-dm" in f.message and "attacker.example" in f.message
    assert evaluate(c.expectations[1], out, POLICY).message.startswith("expected the static security check")
    assert evaluate(c.expectations[1], obs(violations=[{"node_id": "x"}]), POLICY) is None


# ---------------------------------------------------------------------------- running against the real engine

async def test_urgent_normal_and_approval_against_uc07(storage, monkeypatch):
    calls = tripwire.install(monkeypatch)
    env = TestEnv(storage=storage, policy=POLICY)
    flow = flow_dict(FLOW)
    r1 = await run_case(urgent(expectations=[{"kind": "status", "equals": "waiting_for_approval"},
                                             {"kind": "approval_reached", "node": "oncall_approval"},
                                             {"kind": "sink", "target": "send_email", "op": "not_called"}]), flow, env)
    r2 = await run_case(urgent(approvals=[{"approve": True}], expectations=[
        {"kind": "status", "equals": "succeeded"},
        {"kind": "sink", "target": "send_email", "node": "page_oncall", "op": "called_with", "arg": "to",
         "value": "oncall@corp.local"},
        {"kind": "sink", "target": "send_email", "op": "count", "n": 1},
        {"kind": "output", "node": "lookup", "field": "$.body.name", "op": "json_path_equals", "value": "Leanne"},
        {"kind": "security", "op": "no_external_send"}]), flow, env)
    r3 = await run_case(normal(expectations=[
        {"kind": "status", "equals": "succeeded"},
        {"kind": "sink", "target": "send_email", "node": "queue_note", "op": "called_with", "value":
         "support-queue@corp.local"},
        {"kind": "sink", "target": "send_email", "node": "page_oncall", "op": "not_called"}]), flow, env)
    for r in (r1, r2, r3):
        assert r.status == "pass", (r.name, [f.message for f in r.failures], r.error)
        assert r.run_id.startswith("test_") and r.models_used == ["mock/scripted"]
    run = await storage.runs.get(r2.run_id)
    assert run.trigger == "test" and run.flow_id == FLOW["id"]  # opens in the run panel
    assert calls == []


async def test_missing_fixture_fails_the_case_with_no_fixture_message(storage, monkeypatch):
    calls = tripwire.install(monkeypatch)
    r = await run_case(normal(fixtures=[], expectations=[{"kind": "status", "equals": "succeeded"}]),
                       flow_dict(FLOW), TestEnv(storage=storage, policy=POLICY))
    assert r.status == "fail"
    assert any(f.message == f"no fixture for http GET {API}" for f in r.failures)
    assert calls == []


async def test_fixture_prefix_match_and_mcp_fixture_manager():
    from agentos.flowtests.fixtures import FixtureMCPManager, url_matches
    from agentos.flowtests.models import Fixture
    from agentos.mcp.manager import MCPError

    assert url_matches("https://api.example.com/users/*", "https://api.example.com/users/7?x=1")
    assert not url_matches("https://api.example.com/users/1", "https://api.example.com/users/2")
    mgr = FixtureMCPManager([Fixture(kind="mcp", tool="notes.search", body={"hits": 1})])
    res = await mgr.call_tool({"name": "notes"}, "search", "sha", {"q": "x"})
    assert res.status == "ok" and json.loads(res.text) == {"hits": 1}
    with pytest.raises(MCPError, match="no fixture for mcp:delete"):
        await mgr.call_tool({"name": "notes"}, "delete", "sha", {})
    assert mgr.misses == ["no fixture for mcp:delete"]


async def test_tripwire_no_real_email_slack_http_or_dns(storage, monkeypatch):
    """Email, Slack, http_request and the fetch_url tool all go to fakes; the tripwire records any real call."""
    calls = tripwire.install(monkeypatch)
    flow = {"id": "tw", "name": "tw", "entrypoint": "t", "loops": {}, "nodes": {
        "t": {"id": "t", "type": "manual_trigger", "config": {}, "pinned_args": {}},
        "get": {"id": "get", "type": "http_request", "config": {"method": "GET"},
                "pinned_args": {"url": "https://api.example.com/x"}},
        "mail": {"id": "mail", "type": "send_email", "config": {}, "pinned_args": {"to": "ops@corp.local",
                                                                                  "subject": "s", "body": "b"}},
        "chat": {"id": "chat", "type": "send_slack", "config": {}, "pinned_args": {"channel": "support",
                                                                                  "text": "t"}},
        "bot": {"id": "bot", "type": "agent", "config": {"role": "r", "goal": "g", "backstory": "b",
                                                         "tools": ["fetch_url"]}, "pinned_args": {}}},
        "edges": [{"source": "t", "target": "get"}, {"source": "get", "target": "mail"},
                  {"source": "mail", "target": "chat"}, {"source": "t", "target": "bot",
                                                        "arg_mapping": {"task": "payload"}}]}
    c = TestCase(flow_id="tw", name="all sinks", input={"body": "hi"},
                 fixtures=[{"url": "https://api.example.com/x", "body": "ok"},
                           {"url": "https://docs.example.com/*", "body": "page"}],
                 expectations=[{"kind": "sink", "target": "send_email", "op": "called_with", "value": "ops@corp.local"},
                               {"kind": "sink", "target": "send_slack", "op": "called_with", "value": "support"},
                               {"kind": "sink", "target": "http_request", "op": "count", "n": 1}])
    r = await run_case(c, flow, TestEnv(storage=storage, policy=POLICY))
    assert r.status == "pass", ([f.message for f in r.failures], r.error)
    # the fetch_url tool through the same fake network (no fixture -> recorded miss, never a real request)
    from agentos.flowtests.fixtures import TestSinks

    sinks = TestSinks([], [])
    out = sinks.registry()["fetch_url"]
    with pytest.raises(Exception, match="no fixture"):
        out.request("GET", "https://docs.example.com/a", None, None, None, 10, 1000, None)
    assert calls == []


async def test_live_tools_get_uses_the_real_sender_only_for_get(monkeypatch):
    """Admin live tools: a GET without fixture goes to the real sender (faked here), a POST without one fails."""
    from agentos.flows import net_guard
    from agentos.flows.net_guard import RawResponse
    from agentos.flowtests.fixtures import FixtureNetwork, NoFixture

    seen = []
    monkeypatch.setattr(net_guard, "default_resolver", lambda h, p: ["93.184.216.34"])
    monkeypatch.setattr(net_guard, "httpx_sender", lambda *a, **k: seen.append(a[0]) or RawResponse(200, {}, b"live"))
    net = FixtureNetwork([], [], live_tools=True)
    assert net.transport.request("GET", "https://api.example.com/x")["body"] == "live"
    with pytest.raises(NoFixture):
        net.transport.request("POST", "https://api.example.com/x", body={"a": 1})
    assert seen == ["GET"]


# ---------------------------------------------------------------------------- creating cases

async def test_save_from_run_records_input_fixtures_script_and_suggests_expectations(storage):
    env = TestEnv(storage=storage, policy=POLICY)
    first = await run_case(urgent(approvals=[{"approve": True}]), flow_dict(FLOW), env)
    draft = await from_run(storage, FLOW, first.run_id)
    assert draft.input == TICKETS["urgent"] and draft.source == "run"
    assert draft.fixtures[0].url == API and draft.fixtures[0].recorded
    assert draft.mock_responses["triage"].startswith("URGENT")
    kinds = {(e.kind, getattr(e, "op", None), getattr(e, "node", None)) for e in draft.expectations}
    assert ("status", None, None) in kinds and ("approval_reached", None, "oncall_approval") in kinds
    assert ("sink", "called_with", "page_oncall") in kinds and ("sink", "not_called", "queue_note") in kinds
    assert draft.approvals and draft.approvals[0].approve
    replay = await run_case(draft, flow_dict(FLOW), env)
    assert replay.status == "pass", [f.message for f in replay.failures]


async def test_secret_values_are_never_stored_unless_included(storage):
    from agentos.storage.models import RunRecord

    flow = {"id": "sec", "name": "sec", "entrypoint": "t", "loops": {}, "edges": [{"source": "t", "target": "a"}],
            "nodes": {"t": {"id": "t", "type": "manual_trigger", "config": {}, "pinned_args": {}},
                      "a": {"id": "a", "type": "agent", "config": {}, "pinned_args": {}}}}
    await storage.runs.put(RunRecord(run_id="r1", mission_name="sec", flow_id="sec", status="succeeded"))
    secret = {"integrity": "trusted", "confidentiality": "secret", "sources": ["vault"]}
    await storage.events.append(run_id="r1", type="run_started", data={"flow_id": "sec", "inputs": {"q": "x"}})
    await storage.events.append(run_id="r1", type="node_succeeded", data={
        "node_id": "a", "outputs": {"output": "API-KEY-VALUE"}, "output_labels": {"output": secret, "*": secret}})
    draft = await from_run(storage, flow, "r1")
    blob = draft.model_dump_json()
    assert "API-KEY-VALUE" not in blob and "a" not in draft.mock_responses
    assert any("SECRET" in n for n in draft.notes)
    admin = await from_run(storage, flow, "r1", include_secrets=True)
    assert admin.mock_responses.get("a") == "API-KEY-VALUE" and admin.secret_values_included


async def test_review_import_corrected_output_becomes_expected_value(storage):
    from agentos.review.models import ReviewItem
    from agentos.review.store import review_store_for

    env = TestEnv(storage=storage, policy=POLICY)
    first = await run_case(normal(), flow_dict(FLOW), env)
    review = review_store_for(storage)
    await review.put_item(ReviewItem(run_id=first.run_id, flow_id=FLOW["id"], node_id="triage", status="reviewed",
                                     verdict="bad", reasons=["wrong"], corrected_output="NORMAL. Corrected summary.",
                                     output_data={"output": "x"}))
    await review.put_item(ReviewItem(run_id="gone", flow_id=FLOW["id"], node_id="triage", status="reviewed",
                                     verdict="bad", corrected_output="SECRET", labels=["SECRET"]))
    await review.put_item(ReviewItem(run_id="p", flow_id=FLOW["id"], node_id="triage", status="pending"))
    cases = await from_review(review, storage, FLOW)
    assert len(cases) == 1
    c = cases[0]
    assert c.input == TICKETS["normal"] and c.tags == ["review"]
    assert c.expectations[0].value == "NORMAL. Corrected summary." and c.expectations[0].node == "triage"


def one_per_family(cases):
    seen, out = set(), []
    for c in cases:
        if c.attack["family"] not in seen:
            seen.add(c.attack["family"])
            out.append(c)
    return out


async def test_security_generation_safe_flow_passes_and_a_bad_edit_fails(storage, monkeypatch):
    calls = tripwire.install(monkeypatch)
    env = TestEnv(storage=storage, policy=POLICY)
    safe = security_cases(FLOW)
    assert len(safe) > 10 and all("security" in c.tags and c.attack for c in safe)
    for c in one_per_family(safe):  # the full set runs in use case 15
        r = await run_case(c, flow_dict(FLOW), env)
        assert r.status == "pass", (c.name, [f.message for f in r.failures], r.error)
    # the unsafe variant: every attack is still stopped at run time (runtime monitor, 4.1b look-alike refusal
    # at the approval: recorded as a security block, never an error)
    for c in one_per_family(security_cases(UNSAFE))[:4]:
        r = await run_case(c, flow_dict(UNSAFE), env)
        assert r.status == "pass", (c.name, [f.message for f in r.failures], r.error)
    # a bad edit: the on-call email now goes to an outside address -> the generated tests catch it
    edited = json.loads(json.dumps(FLOW))
    edited["nodes"]["page_oncall"]["pinned_args"]["to"] = "oncall@outsourcer.example"
    bad = [await run_case(c, flow_dict(edited), env) for c in one_per_family(security_cases(edited))[:3]]
    failed = [r for r in bad if r.status != "pass"]
    assert failed and all(r.status == "fail" for r in failed)
    assert any("send_email to oncall@outsourcer.example" in f.message for r in failed for f in r.failures)
    assert calls == []


# ---------------------------------------------------------------------------- suites, regression, comparison

async def test_suite_history_regression_and_summary(storage):
    store = flowtests_store_for(storage)
    await storage.flows.put_draft(FlowRecord(**FLOW))
    env = TestEnv(storage=storage, policy=POLICY)
    a = await store.put_case(normal(expectations=[{"kind": "status", "equals": "succeeded"}]))
    b = await store.put_case(urgent(expectations=[{"kind": "status", "equals": "succeeded"}]))  # fails (waits)
    s1 = await execute_suite(store, env, FLOW["id"])
    assert s1.counts == {"total": 2, "pass": 1, "fail": 1, "error": 0} and s1.regression["first_run"]
    await store.put_case(a.model_copy(update={"expectations": [{"kind": "status", "equals": "failed"}]}))
    await store.put_case(b.model_copy(update={"expectations": [{"kind": "status", "equals": "waiting_for_approval"}]}))
    s2 = await execute_suite(store, env, FLOW["id"])
    reg = s2.regression
    assert [x["name"] for x in reg["newly_failing"]] == ["normal"]
    assert [x["name"] for x in reg["newly_passing"]] == ["urgent"] and reg["previous_run_id"] == s1.id
    assert [r.id for r in await store.list_runs(FLOW["id"])] == [s2.id, s1.id]
    assert (await store.summary())[FLOW["id"]] == {"cases": 2, "last_pass_rate": 50.0,
                                                   "last_run_at": s2.started_at}


async def test_regression_still_failing_new_and_removed():
    def run(*rows):
        return SuiteRun(flow_id="f", results=[CaseResult(case_id=c, name=c, status=s) for c, s in rows])
    reg = regression(run(("a", "fail"), ("b", "pass"), ("gone", "pass")),
                     run(("a", "error"), ("b", "pass"), ("n", "pass")))
    assert [x["case_id"] for x in reg["still_failing"]] == ["a"]
    assert [x["case_id"] for x in reg["new_cases"]] == ["n"]
    assert [x["case_id"] for x in reg["removed_cases"]] == ["gone"]


async def test_model_comparison_table(storage, monkeypatch):
    from agentos.flowtests import compare_models, service
    from agentos.flowtests.models_choice import InvalidModelChoice, normalize_model

    monkeypatch.setattr(service, "check_model_enabled", lambda m: None)  # no provider keys in tests (MOCK)
    store = flowtests_store_for(storage)
    await storage.flows.put_draft(FlowRecord(**FLOW))
    await store.put_case(normal(expectations=[{"kind": "status", "equals": "succeeded"}]))
    await store.put_case(urgent(expectations=[{"kind": "status", "equals": "succeeded"}]))
    res = await compare_models(store, TestEnv(storage=storage, policy=POLICY), FLOW["id"], ["mock", "router"])
    rows = {r["model"]: r for r in res["rows"]}
    assert set(rows) == {"mock", "router"}
    assert rows["mock"]["pass_rate"] == 50.0 and [c["name"] for c in rows["mock"]["failed_cases"]] == ["urgent"]
    for r in rows.values():
        assert {"cost_usd", "median_latency_ms", "counts", "suite_run_id", "pass_rate"} <= set(r)
    with pytest.raises(ValueError, match="2 to 4"):
        await compare_models(store, TestEnv(storage=storage), FLOW["id"], ["mock"])
    with pytest.raises(InvalidModelChoice):
        normalize_model("gpt")
    row = comparison_row(SuiteRun(flow_id="f", results=[CaseResult(case_id="a", name="a", status="pass",
                                                                   latencies_ms=[10, 30, 20])]))
    assert row["median_latency_ms"] == 20 and row["latency_source"] == "model_calls"


async def test_router_mode_usage_is_tagged_test_in_the_ledger(storage):
    """Router mode (the MOCK router's offline model here): llm_call events and ledger rows carry source="test"."""
    from agentos.usage import UsageContext, usage_stores_for

    ledger, settings = usage_stores_for(storage)
    env = TestEnv(storage=storage, policy=POLICY, usage=UsageContext(ledger, settings))
    r = await run_case(normal(), flow_dict(FLOW), env, model="router")
    events = [e for e in await storage.events.list(r.run_id) if e.type == "llm_call"]
    assert events and all(e.data.get("source") == "test" for e in events)
    rows = await ledger.rows()
    assert rows and all(row.get("source") == "test" and row["flow_id"] == FLOW["id"] for row in rows)


async def test_judge_is_marked_nondeterministic_and_can_fail(storage):
    env = TestEnv(storage=storage, policy=POLICY)
    judge = {"kind": "judge", "node": "triage", "rubric": "The summary names the customer's problem."}
    ok = await run_case(normal(expectations=[judge]), flow_dict(FLOW), env)
    assert ok.status == "pass" and ok.nondeterministic, [f.message for f in ok.failures]
    bad = await run_case(normal(expectations=[judge], mock_responses={
        "triage": "NORMAL.", "__judge__": '{"verdict": "fail", "reason": "incomplete"}'}), flow_dict(FLOW), env)
    assert bad.status == "fail"
    assert bad.failures[0].message == "judge (non-deterministic): graded fail, reason: incomplete"


async def test_junit_output():
    suite = SuiteRun(flow_id="f", counts={"total": 3, "pass": 1, "fail": 1, "error": 1}, results=[
        CaseResult(case_id="a", name="ok", status="pass", run_id="test_a"),
        CaseResult(case_id="b", name="bad", status="fail", failures=[{"expectation": {"kind": "status"},
                   "expected": "succeeded", "actual": "failed", "message": "final status: expected succeeded"}]),
        CaseResult(case_id="c", name="err", status="error", error="ValueError: x")])
    root = ET.fromstring(junit_xml(suite))
    ts = root.find("testsuite")
    assert ts.get("tests") == "3" and ts.get("failures") == "1" and ts.get("errors") == "1"
    f = ts.find("testcase[@name='bad']/failure")
    assert f.get("message") == "final status: expected succeeded" and '"failed"' in f.text
