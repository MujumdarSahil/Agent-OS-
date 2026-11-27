"""4.1b Part 0: look-alike (homoglyph) destinations. MOCK only (MockTransport sinks, no network, no model).

AWIB 4.1 found `support@corp.lоcal` (Cyrillic "о") passing an attentive approver. One shared check
(agentos/flows/destinations.py) now backs every recipient / host / allowlist decision.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agentos.flows.destinations import analyze, domain_matches, email_domain_internal, lookalike_warning
from agentos.flows.labels import Label
from agentos.flows.models import FlowDefinition
from agentos.flows.net_guard import host_matches_allowlist
from agentos.flows.policy import SecurityPolicy
from agentos.flows.rules import evaluate_sink_argument_rule
from agentos.flows.specs import SEND_EMAIL_SINK_SPEC
from agentos.flows.static_analyzer import StaticFlowAnalyzer

CYR_O, GREEK_O = "о", "ο"
LOOK_DOMAIN = f"support@corp.l{CYR_O}cal"
LOOK_LOCAL = f"supp{CYR_O}rt@corp.local"
GREEK = f"support@c{GREEK_O}rp.local"
FULLWIDTH = "support@ｃorp.local"
NON_ENGLISH = ["josé@ejemplo.es", "用户@例子.中国",
               "иван@пример.рф"]
POLICY = SecurityPolicy(internal_domains={"corp.local"}, slack_channels={"ops": True},
                        allowlists={"recipients": ["support@corp.local"]})


# --------------------------------------------------------------------------- the shared analysis

@pytest.mark.parametrize("addr", [LOOK_DOMAIN, LOOK_LOCAL, GREEK, FULLWIDTH, "admin@аре.com"])
def test_lookalikes_are_confusable_and_flagged(addr):
    info = analyze(addr)
    assert info.confusable and info.flagged and info.reasons
    assert info.ascii_form.isascii()


def test_mixed_script_in_local_part_and_domain_named_in_reasons():
    assert any("local part" in r for r in analyze(LOOK_LOCAL).reasons)
    assert any("domain" in r for r in analyze(LOOK_DOMAIN).reasons)
    assert analyze(LOOK_DOMAIN).ascii_form == "support@corp.xn--lcal-55d"


def test_idn_punycode_input_is_decoded_and_still_confusable():
    puny = "support@corp.xn--lcal-55d"
    info = analyze(puny)
    assert info.normalized == LOOK_DOMAIN and info.confusable
    assert not email_domain_internal(puny, {"corp.local"})


def test_fullwidth_normalises_but_is_never_internal():
    info = analyze(FULLWIDTH)
    assert info.normalized == "support@corp.local" and info.nfkc_changed and info.confusable
    assert not email_domain_internal(FULLWIDTH, {"corp.local"})


@pytest.mark.parametrize("addr", NON_ENGLISH)
def test_legitimate_non_english_addresses_are_not_confusable_but_flagged(addr):
    info = analyze(addr)
    assert not info.confusable and info.non_ascii and info.flagged
    w = lookalike_warning(addr)
    assert w and w["confusable"] is False and w["ascii_form"].isascii()


def test_plain_ascii_address_has_no_warning():
    assert lookalike_warning("support@corp.local") is None
    assert not analyze("support@corp.local").flagged


def test_internal_domain_requires_exact_match():
    assert email_domain_internal("support@corp.local", {"corp.local"})
    assert email_domain_internal("Support@CORP.LOCAL", {"@corp.local"})
    assert not email_domain_internal("support@evilcorp.local", {"corp.local"})
    assert not email_domain_internal("support@sub.corp.local", {"corp.local"})
    for bad in (LOOK_DOMAIN, LOOK_LOCAL, GREEK, FULLWIDTH):
        assert not email_domain_internal(bad, {"corp.local"})
    # a non-English internal domain configured by the admin (punycode) still matches exactly
    assert domain_matches("пример.рф", {"xn--e1afmkfd.xn--p1ai"})


# --------------------------------------------------------------------------- every policy check uses it

def test_policy_checks_refuse_lookalikes():
    assert POLICY.is_internal_email("support@corp.local")
    assert not POLICY.is_internal_email(LOOK_DOMAIN)
    assert POLICY.is_internal_slack_channel("ops")
    assert not POLICY.is_internal_slack_channel(f"{CYR_O}ps")
    assert POLICY.is_in_allowlist("recipients", "support@corp.local")
    assert not POLICY.is_in_allowlist("recipients", LOOK_DOMAIN)


def test_http_allowlist_refuses_lookalike_hosts():
    allow = ["internal.corp", "*.corp.local"]
    assert host_matches_allowlist("internal.corp", [], allow)
    assert host_matches_allowlist("mail.corp.local", [], allow)
    assert not host_matches_allowlist(f"internal.c{CYR_O}rp", [], allow)
    assert not host_matches_allowlist(f"mail.corp.l{CYR_O}cal", [], allow)
    assert not host_matches_allowlist("internal.xn--crp-tdd", [], allow)
    assert not host_matches_allowlist("ｉnternal.corp", [], allow)  # full-width i


# --------------------------------------------------------------------------- shared sink rule (static + runtime)

def _rule(to, approved=False, confirmed=False):
    return evaluate_sink_argument_rule(
        node_id="send", spec=SEND_EMAIL_SINK_SPEC, arg_name="to", rule=SEND_EMAIL_SINK_SPEC.sink_rules["to"],
        arriving_label=Label.trusted(), effective_inbound_label=Label.trusted(), is_pinned=not approved,
        is_approved=approved, pinned_to_val=to, policy=POLICY, path=["send"], lookalike_confirmed=confirmed)


def test_sink_rule_treats_lookalike_recipient_as_untrusted_unless_confirmed():
    assert _rule("support@corp.local") == []
    assert any("look-alike" in v.reason for v in _rule(LOOK_DOMAIN))
    assert any("look-alike" in v.reason for v in _rule(LOOK_DOMAIN, approved=True))  # approved, not confirmed
    assert _rule(LOOK_DOMAIN, approved=True, confirmed=True) == []
    assert _rule(NON_ENGLISH[0]) == []  # legitimate non-English: deliverable
    assert any("look-alike" in v.reason for v in _rule({"payload": LOOK_DOMAIN}))  # nested payload


def _flow(to_pinned):
    nodes = {"trig": {"id": "trig", "type": "manual_trigger"},
             "send": {"id": "send", "type": "send_email", "config": {},
                      "pinned_args": {"to": to_pinned, "subject": "S", "body": "fixed"}}}
    return FlowDefinition(id="f", name="f", entrypoint="trig", nodes=nodes,
                          edges=[{"source": "trig", "target": "send", "arg_mapping": {}}])


def test_static_check_refuses_pinned_lookalike_and_keeps_legit_non_english():
    bad = StaticFlowAnalyzer(_flow(LOOK_DOMAIN), policy=POLICY).verify().violations
    assert any("look-alike" in v.reason for v in bad)
    ok = StaticFlowAnalyzer(_flow(NON_ENGLISH[0]), policy=POLICY).verify().violations
    assert not any("look-alike" in v.reason for v in ok)


# --------------------------------------------------------------------------- proxy and approvals (real engine)

async def _storage(td: Path):
    from agentos.storage import open_storage

    proj = td / "p"
    proj.mkdir()
    (proj / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    return await open_storage(str(proj), backend="file", vault_path=str(td / "v.json"))


@pytest.mark.asyncio
async def test_proxy_blocks_agent_call_to_lookalike(tmp_path):
    from agentos.flows.proxy import AgentOSToolProxy, MockTransport
    from agentos.flows.rules import SinkRuleViolationError

    storage = await _storage(tmp_path)
    mt = MockTransport()
    try:
        proxy = AgentOSToolProxy("r1", "agent", storage, POLICY, transport_registry={"send_email": mt})
        with pytest.raises(SinkRuleViolationError, match="look-alike"):
            await proxy.invoke("agent", "send_email", {"to": LOOK_DOMAIN, "subject": "s", "body": "b"})
        await proxy.invoke("agent", "send_email", {"to": "support@corp.local", "subject": "s", "body": "b"})
    finally:
        await storage.close()
    assert [c["to"] for c in mt.sent_calls] == ["support@corp.local"]


APPROVAL_FLOW = json.loads((Path(__file__).resolve().parents[2] / "examples" / "usecases" / "05-visual-builder"
                            / "flows" / "approval.flow.json").read_text(encoding="utf-8"))


async def _run_to_approval(payload):
    from agentos.flows.engine import FlowEngine
    from agentos.flows.proxy import MockTransport
    from agentos.flows.state import RunStatus

    storage = await _storage(Path(tempfile.mkdtemp(prefix="agentos-4-1b-")))
    mt = MockTransport()
    engine = FlowEngine(FlowDefinition(**APPROVAL_FLOW), storage, policy=POLICY,
                        transport_registry={"send_email": mt})
    state = await engine.run("run1", inputs=payload, raise_on_error=False)
    assert state.status == RunStatus.WAITING
    card = [e for e in await storage.events.list("run1") if e.type == "node_waiting"][-1].data
    return engine, storage, mt, card


@pytest.mark.asyncio
async def test_lookalike_approval_needs_extra_confirmation():
    engine, storage, mt, card = await _run_to_approval(LOOK_DOMAIN)
    try:
        warns = card["destination_warnings"]
        assert warns and warns[0]["arg"] == "to" and warns[0]["ascii_form"] == "support@corp.xn--lcal-55d"
        with pytest.raises(ValueError, match="look-alike confirmation"):
            await engine.approve(run_id="run1", node_id="gate", decision=True)
        assert mt.sent_calls == []
        state = await engine.approve(run_id="run1", node_id="gate", decision=True, confirm_lookalike=True)
        assert state.status.value == "succeeded"
        dec = [e for e in await storage.events.list("run1") if e.type == "approval_decision"][-1].data
        assert dec["confirm_lookalike"] is True
    finally:
        await storage.close()
    assert len(mt.sent_calls) == 1  # a human explicitly confirmed the exact address


@pytest.mark.asyncio
async def test_lookalike_reject_needs_no_confirmation_and_sends_nothing():
    engine, storage, mt, _ = await _run_to_approval(LOOK_DOMAIN)
    try:
        await engine.approve(run_id="run1", node_id="gate", decision="reject")
    finally:
        await storage.close()
    assert mt.sent_calls == []


@pytest.mark.asyncio
async def test_plain_address_unchanged_and_non_english_flagged_but_deliverable():
    engine, storage, mt, card = await _run_to_approval("support@corp.local")
    try:
        assert card["destination_warnings"] == []
        await engine.approve(run_id="run1", node_id="gate", decision=True)
    finally:
        await storage.close()
    assert len(mt.sent_calls) == 1
    engine, storage, mt, card = await _run_to_approval(NON_ENGLISH[0])
    try:
        assert card["destination_warnings"] and card["destination_warnings"][0]["confusable"] is False
        await engine.approve(run_id="run1", node_id="gate", decision=True, confirm_lookalike=True)
    finally:
        await storage.close()
    assert len(mt.sent_calls) == 1
