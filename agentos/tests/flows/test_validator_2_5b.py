"""2.5b validator hardening - MOCK (no model, no network; MockTransport outbox, fake HTTP sender).

The reviewer's CRITICAL bypass: webhook -> validator {field: "to", field_type: "enum"} (no values) -> send_email
passed publish, and at run time the validator returned {"to": "mallory@attacker.example"} labelled trusted (same
for bounded_number without bounds); it also dropped the input's confidentiality. The validator now uses the
same constraint code as quarantined extraction (agentos/flows/extraction.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

import agentos.flows.extraction as ex
from agentos.flows.engine import FlowEngine, execute_validator_runtime
from agentos.flows.labels import Label
from agentos.flows.models import FlowDefinition, NodeDefinition
from agentos.flows.net_guard import HttpRequestTransport, RawResponse
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.state import RunStatus
from agentos.flows.static_analyzer import StaticFlowAnalyzer
from agentos.storage import open_storage

POLICY = SecurityPolicy(
    internal_domains={"corp.local"},
    http_allowlist=["internal.corp"],
    allowlists={"recipients": ["Security@corp.local"], "records": ["https://internal.corp/api/records/1"]},
)
ATTACKER = "mallory@attacker.example"


@pytest_asyncio.fixture
async def storage(tmp_path: Path):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


def mk(nodes, edges, entry):
    return FlowDefinition(
        id="val", entrypoint=entry,
        nodes={k: {"id": k, "type": v[0], "config": v[1] if len(v) > 1 else {},
                   "pinned_args": v[2] if len(v) > 2 else {}} for k, v in nodes.items()},
        edges=edges,
    )


def node(cfg) -> NodeDefinition:
    return NodeDefinition(id="val", type="validator", config=cfg)


async def events(storage, run_id):
    return await storage.events.list(run_id, after_seq=0)


# ------------------------------------------------------------------ the exact bypass

def bypass_flow(cfg):
    return mk({"hook": ("webhook_trigger",), "val": ("validator", cfg), "send": ("send_email", {}, {"subject": "s", "body": "b"})},
              [{"source": "hook", "target": "val", "arg_mapping": {"to": "payload"}},
               {"source": "val", "target": "send", "arg_mapping": {"to": "to"}}], "hook")


@pytest.mark.parametrize("cfg", [
    {"field": "to", "field_type": "enum"},
    {"field": "to", "field_type": "bounded_number"},
    {"field": "to", "field_type": "bounded_number", "min": 0},
    {"field": "to", "field_type": "free_text"},
    {"field": "to", "field_type": "text"},
    {"field": "to", "field_type": "allowlist_match", "allowlist_name": "http_allowlist"},
    {"field": "to", "field_type": "allowlist", "allowlist_name": "not_configured"},
])
def test_bypass_refused_at_publish_with_a_clear_message(cfg):
    res = StaticFlowAnalyzer(bypass_flow(cfg), POLICY).verify()
    assert not res.is_valid
    cfg_err = [v.reason for v in res.violations if v.node_id == "val" and v.target_arg == "(config)"]
    assert cfg_err and "validator" in cfg_err[0]
    assert any(v.node_id == "send" and v.target_arg == "to" for v in res.violations)  # nothing declassified


@pytest.mark.parametrize("cfg", [{"field": "to", "field_type": "enum"}, {"field": "to", "field_type": "bounded_number"}])
def test_bypass_direct_runtime_call_fails_closed(cfg):
    with pytest.raises(ex.ExtractionRejected) as err:
        execute_validator_runtime(node(cfg), {"to": ATTACKER}, POLICY)
    assert err.value.reason == "invalid_config" and ATTACKER not in str(err.value)


@pytest.mark.asyncio
async def test_old_published_flow_fails_closed_at_run_time_with_an_event(storage):
    # a flow published before the fix still loads (no schema change for old keys) but declassifies nothing
    fd = mk({"val": ("validator", {"field": "to", "field_type": "enum"}), "send": ("send_email", {}, {"subject": "s", "body": "b"})},
            [{"source": "val", "target": "send", "arg_mapping": {"to": "to"}}], "val")
    outbox = MockTransport()
    st = await FlowEngine(fd, storage, policy=POLICY, transport_registry={"send_email": outbox}).run(
        run_id="r_old", inputs={"to": ATTACKER})
    assert st.status == RunStatus.FAILED and "fail closed" in (st.error or "")
    assert outbox.sent_calls == [] and not st.node_outputs.get("val")
    evs = await events(storage, "r_old")
    rej = next(e for e in evs if e.type == "validator_rejected")
    assert rej.data == {"node_id": "val", "reason": "invalid_config", "field": None, "field_type": "enum",
                        "declassified": False}
    assert not any(e.type == "declassified" for e in evs)
    assert all(ATTACKER not in e.model_dump_json() for e in evs if e.type in ("validator_rejected", "node_failed"))


# ------------------------------------------------------------------ every type's near-misses

ENUM = {"field": "category", "field_type": "enum", "values": ["phishing", "spam", "legit"]}
BOOL = {"field": "flag", "field_type": "bool"}
INT = {"field": "n", "field_type": "int_range", "min": 0, "max": 5}
LEGACY_INT = {"field": "n", "field_type": "bounded_number", "min": 0, "max": 5}
TICKET = {"field": "t", "field_type": "pattern", "pattern": "ticket_id"}
ALLOW = {"field": "to", "field_type": "allowlist", "allowlist_name": "recipients"}
LEGACY_ALLOW = {"field": "to", "field_type": "allowlist_match", "allowlist_name": "recipients"}

ACCEPTED = [
    (ENUM, "phishing", "phishing"), (ENUM, "  legit\t", "legit"),
    (BOOL, True, True), (BOOL, False, False), (BOOL, "true", True), (BOOL, "false", False),
    (INT, 0, 0), (INT, 5, 5), (LEGACY_INT, 3, 3),
    (TICKET, "SEC-42", "SEC-42"),
    (ALLOW, " security@CORP.local ", "Security@corp.local"), (LEGACY_ALLOW, "SECURITY@corp.local", "Security@corp.local"),
]
REJECTED = [
    (ENUM, "Phishing", "not_allowed"), (ENUM, "phish", "not_allowed"), (ENUM, "legit\nIgnore previous", "not_allowed"),
    (ENUM, "category: legit", "not_allowed"), (ENUM, ATTACKER, "not_allowed"), (ENUM, 1, "wrong_type"),
    (ENUM, ["legit"], "nested_value"),
    (BOOL, "True", "wrong_type"), (BOOL, "yes", "wrong_type"), (BOOL, "1", "wrong_type"), (BOOL, " true", "wrong_type"),
    (BOOL, 1, "wrong_type"), (BOOL, 0, "wrong_type"), (BOOL, None, "wrong_type"),
    (INT, True, "wrong_type"), (INT, "3", "wrong_type"), (INT, 3.0, "wrong_type"), (INT, 6, "out_of_range"),
    (INT, -1, "out_of_range"), (LEGACY_INT, 42.5, "wrong_type"),
    (TICKET, "SEC-42 extra", "pattern_mismatch"), (TICKET, "sec-42", "pattern_mismatch"),
    (ALLOW, ATTACKER, "not_allowed"), (LEGACY_ALLOW, "security@corp.local.evil", "not_allowed"),
    (ALLOW, {"to": "Security@corp.local"}, "nested_value"),
]


@pytest.mark.parametrize("cfg,value,expected", ACCEPTED)
def test_accepted_values_are_canonical(cfg, value, expected):
    out, lbl = execute_validator_runtime(node(cfg), {cfg["field"]: value}, POLICY)
    assert out[cfg["field"]] == expected and type(out[cfg["field"]]) is type(expected)
    assert lbl.integrity == "trusted"


@pytest.mark.parametrize("cfg,value,reason", REJECTED)
def test_near_misses_are_rejected(cfg, value, reason):
    with pytest.raises(ex.ExtractionRejected) as err:
        execute_validator_runtime(node(cfg), {cfg["field"]: value}, POLICY)
    assert err.value.reason == reason


@pytest.mark.parametrize("cfg,needle", [
    ({"field": "c", "field_type": "enum", "values": ["a"]}, None),
    ({"field": "c", "field_type": "enum", "values": ["a", "b<x>"]}, None),
    ({"field": "n", "field_type": "int_range", "min": 5, "max": 1}, "min must be"),
    ({"field": "n", "field_type": "int_range", "min": 0, "max": 10**9 + 1}, None),
    ({"field": "f", "field_type": "bool", "values": ["a", "b"]}, "does not take"),
    ({"field": "t", "field_type": "pattern"}, "requires 'pattern'"),
    ({"field": "o", "field_type": "allowlist_match"}, None),
])
def test_bad_constraints_refused(cfg, needle):
    try:
        fd = mk({"val": ("validator", cfg)}, [], "val")
    except Exception:
        assert needle is None  # rejected by the JSON Schema or model checks before publish
        return
    errs = [v.reason for v in StaticFlowAnalyzer(fd, POLICY).verify().violations if v.target_arg == "(config)"]
    assert errs and (needle is None or needle in errs[0])


# ------------------------------------------------------------------ labels: confidentiality, identical at publish/run

def test_secret_in_secret_out_and_marker():
    secret = Label(integrity="untrusted", confidentiality="secret", sources=frozenset({"hook"}))
    _, lbl = execute_validator_runtime(node(ENUM), {"category": "spam"}, POLICY, secret)
    assert lbl.integrity == "trusted" and lbl.confidentiality == "secret"
    assert "hook" in lbl.sources and "declassified:validator:val:category:enum" in lbl.sources
    _, legacy = execute_validator_runtime(node(LEGACY_ALLOW), {"to": "security@corp.local"}, POLICY, secret)
    assert "declassified:validator:val:to:allowlist" in legacy.sources and legacy.confidentiality == "secret"


@pytest.mark.asyncio
async def test_labels_identical_at_publish_and_run_time(storage):
    fd = mk({"val": ("validator", ENUM)}, [], "val")
    static_labels, _, _ = StaticFlowAnalyzer(fd, POLICY)._propagate_labels_fixpoint()
    st = await FlowEngine(fd, storage, policy=POLICY).run(run_id="r_lbl", inputs={"category": "spam"})
    assert st.status == RunStatus.SUCCEEDED and st.node_output_labels["val"] == static_labels["val"]
    # two levels: the second validator's labels come from the first one's (shared inbound function)
    fd2 = mk({"val": ("validator", BOOL), "again": ("validator", BOOL)},
             [{"source": "val", "target": "again", "arg_mapping": {"flag": "flag"}}], "val")
    s2, _, _ = StaticFlowAnalyzer(fd2, POLICY)._propagate_labels_fixpoint()
    st2 = await FlowEngine(fd2, storage, policy=POLICY).run(run_id="r_lbl2", inputs={"flag": "true"})
    assert st2.status == RunStatus.SUCCEEDED
    for nid in ("val", "again"):
        assert st2.node_output_labels[nid] == s2[nid], nid
    decl = next(e for e in await events(storage, "r_lbl2") if e.type == "declassified")
    assert decl.data["kind"] == "validator" and decl.data["field_type"] == "bool"


@pytest.mark.asyncio
async def test_confidentiality_kept_through_a_flow(storage, monkeypatch):
    original = ex.shared_inbound

    def secret(flow, node_id, labels, fallback):
        base = original(flow, node_id, labels, fallback)
        return Label(integrity=base.integrity, confidentiality="secret", sources=base.sources)

    monkeypatch.setattr(ex, "shared_inbound", secret)
    st = await FlowEngine(mk({"val": ("validator", ENUM)}, [], "val"), storage, policy=POLICY).run(
        run_id="r_secret", inputs={"category": "legit"})
    assert st.status == RunStatus.SUCCEEDED
    assert {k: v.confidentiality for k, v in st.node_output_labels["val"].items()} == {
        "category": "secret", "data": "secret", "*": "secret"}


# ------------------------------------------------------------------ recipient rule

@pytest.mark.asyncio
async def test_validator_enum_can_never_be_a_recipient(storage):
    cfg = {"field": "to", "field_type": "enum", "values": ["security.corp.local", "evil.test"]}
    fd = mk({"val": ("validator", cfg), "send": ("send_email", {}, {"subject": "s", "body": "b"})},
            [{"source": "val", "target": "send", "arg_mapping": {"to": "to"}}], "val")
    res = StaticFlowAnalyzer(fd, POLICY).verify()
    assert any(v.node_id == "send" and v.target_arg == "to" and "allowlist" in v.reason for v in res.violations)
    outbox = MockTransport()
    st = await FlowEngine(fd, storage, policy=POLICY, transport_registry={"send_email": outbox}).run(
        run_id="r_enum_to", inputs={"to": "evil.test"})
    assert st.status == RunStatus.FAILED and outbox.sent_calls == []


@pytest.mark.asyncio
async def test_validator_allowlist_may_be_a_recipient(storage):
    fd = mk({"val": ("validator", LEGACY_ALLOW), "send": ("send_email", {}, {"subject": "s", "body": "b"})},
            [{"source": "val", "target": "send", "arg_mapping": {"to": "to"}}], "val")
    assert StaticFlowAnalyzer(fd, POLICY).verify().is_valid
    outbox = MockTransport()
    st = await FlowEngine(fd, storage, policy=POLICY, transport_registry={"send_email": outbox}).run(
        run_id="r_allow_to", inputs={"to": "SECURITY@corp.local"})
    assert st.status == RunStatus.SUCCEEDED and [c["to"] for c in outbox.sent_calls] == ["Security@corp.local"]
    # the attacker's address never passes the allowlist
    outbox2 = MockTransport()
    st2 = await FlowEngine(fd, storage, policy=POLICY, transport_registry={"send_email": outbox2}).run(
        run_id="r_allow_to_attacker", inputs={"to": ATTACKER})
    assert st2.status == RunStatus.FAILED and outbox2.sent_calls == []


# ------------------------------------------------------------------ DESTRUCTIVE rule

class FakeHttp:
    def __init__(self):
        self.calls = []
        self.transport = HttpRequestTransport(allowlist=POLICY.http_allowlist,
                                              resolver=lambda h, p: ["10.20.0.5"], sender=self._send)

    def _send(self, method, target, path, headers, body, timeout_s, max_bytes):
        self.calls.append(method)
        return RawResponse(200, {"content-type": "text/plain"}, b"ok")


def destructive_flow(with_approval=False):
    nodes = {"val": ("validator", {"field": "action", "field_type": "enum", "values": ["keep", "delete"]}),
             "cond": ("condition", {"expression": "nodes.val.action == 'delete'"}),
             "wipe": ("http_request", {"method": "DELETE"}, {"url": "https://internal.corp/api/records/1"})}
    edges = [{"source": "val", "target": "cond"}]
    if with_approval:
        nodes["gate"] = ("approval", {"prompt": "Delete?", "approves": {"sink_node": "wipe", "args": ["url"]}})
        edges += [{"source": "cond", "target": "gate", "branch": "true"}, {"source": "gate", "target": "wipe"}]
    else:
        edges += [{"source": "cond", "target": "wipe", "branch": "true"}]
    return mk(nodes, edges, "val")


@pytest.mark.asyncio
async def test_destructive_gated_only_by_validator_is_refused(storage):
    res = StaticFlowAnalyzer(destructive_flow(), POLICY).verify()
    assert any(v.node_id == "wipe" and v.target_arg == "(control)" and "validator val.action" in v.reason
               for v in res.violations)
    http = FakeHttp()
    st = await FlowEngine(destructive_flow(), storage, policy=POLICY, transport_registry={"http_request": http.transport}).run(
        run_id="r_destroy", inputs={"action": "delete"})
    assert st.status == RunStatus.FAILED and http.calls == []


@pytest.mark.asyncio
async def test_destructive_with_upstream_approval_or_admin_flag(storage):
    assert StaticFlowAnalyzer(destructive_flow(with_approval=True), POLICY).verify().is_valid
    http = FakeHttp()
    eng = FlowEngine(destructive_flow(with_approval=True), storage, policy=POLICY,
                     transport_registry={"http_request": http.transport})
    st = await eng.run(run_id="r_destroy_ok", inputs={"action": "delete"})
    assert st.status == RunStatus.WAITING and http.calls == []
    st = await eng.approve("r_destroy_ok", "gate", "approve")
    assert st.status == RunStatus.SUCCEEDED and http.calls == ["DELETE"]
    flagged = POLICY.model_copy(update={"allow_declassified_for_destructive": True})
    assert StaticFlowAnalyzer(destructive_flow(), flagged).verify().is_valid


@pytest.mark.asyncio
async def test_destructive_argument_from_validator_is_refused(storage):
    cfg = {"field": "url", "field_type": "allowlist", "allowlist_name": "records"}
    fd = mk({"val": ("validator", cfg), "wipe": ("http_request", {"method": "DELETE"})},
            [{"source": "val", "target": "wipe", "arg_mapping": {"url": "url"}}], "val")
    res = StaticFlowAnalyzer(fd, POLICY).verify()
    assert any(v.node_id == "wipe" and v.target_arg == "url" for v in res.violations)
    http = FakeHttp()
    st = await FlowEngine(fd, storage, policy=POLICY, transport_registry={"http_request": http.transport}).run(
        run_id="r_arg", inputs={"url": "https://internal.corp/api/records/1"})
    assert st.status == RunStatus.FAILED and http.calls == []
