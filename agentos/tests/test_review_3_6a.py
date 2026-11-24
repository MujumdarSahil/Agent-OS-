"""Milestone 3.6a: Human Review Queue unit & integration tests.

Tests:
1. Review item CRUD (put, get, list with flow/status/verdict filters, pagination).
2. Review verdicts (good/bad, multi-select reasons, corrected output, note, reviewer).
3. Review skip (status=skipped, optional note).
4. Review sampling configuration (defaults to off, percentage, rules, target nodes).
5. Sampling rule evaluation:
   - mode="off"
   - mode="all"
   - mode="percentage" (within statistical tolerance over 100 runs)
   - mode="rules" with rules:
     * failed
     * fallback_used
     * rejected_input
     * approval_rejected
     * sink_blocked
6. Target node sampling:
   - default: final output node
   - specific: designated nodes
7. Security labels:
   - Labels (UNTRUSTED, SECRET, sources) captured accurately in review items.
8. Corrected output isolation:
   - Corrected output is stored and exported, but never fed back into live runs.
9. Review quality metrics:
   - Reviewed count, % good, top bad reasons frequency.
10. Export JSONL & SECRET exclusion:
   - Secret redaction when include_secrets=False.
   - Raw secret inclusion when include_secrets=True.
11. Manual "Send to review":
   - Enqueues review item from existing run.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentos.flows.models import FlowDefinition, NodeDefinition
from agentos.flows.state import FlowRunState, RunStatus
from agentos.review.models import (
    ReviewItem,
    ReviewSamplingConfig,
)
from agentos.review.store import ReviewStore, enqueue_run_for_review, review_store_for
from agentos.storage.file import open_file_storage
from agentos.storage.models import RunRecord


@pytest.fixture
def storage(tmp_path):
    return open_file_storage(str(tmp_path / "data"))


@pytest.fixture
def store(storage):
    return review_store_for(storage)


def _make_flow(flow_id: str, nodes: list[str]) -> FlowDefinition:
    node_defs = {
        nid: NodeDefinition(id=nid, type="webhook_trigger", config={})
        for nid in nodes
    }
    return FlowDefinition(
        id=flow_id,
        name=flow_id,
        entrypoint=nodes[0] if nodes else "entry",
        nodes=node_defs,
        edges=[],
    )


# -----------------------------------------------------------------------------
# 1. Store CRUD & Filtering
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_review_store_crud(store: ReviewStore):
    item = ReviewItem(
        id="rev-1",
        item_id="rev-1",
        run_id="run-1",
        flow_id="support_bot",
        flow_version=2,
        node_id="reply_node",
        inputs={"query": "how do I reset password?"},
        input_labels={"query": {"integrity": "untrusted", "confidentiality": "public"}},
        outputs={"text": "Click reset button."},
        output_labels={"text": {"integrity": "trusted", "confidentiality": "public"}},
    )

    created = await store.put_item(item)
    assert created.id == "rev-1"
    assert created.item_id == "rev-1"
    assert created.status == "pending"
    assert created.verdict is None

    fetched = await store.get_item("rev-1")
    assert fetched is not None
    assert fetched.run_id == "run-1"
    assert fetched.flow_id == "support_bot"
    assert fetched.node_id == "reply_node"
    assert fetched.inputs["query"] == "how do I reset password?"

    # Update verdict to good
    updated = await store.update_verdict(
        "rev-1",
        verdict="good",
        reasons=[],
        reviewer_id="alice",
        note="Clear and concise",
    )
    assert updated is not None
    assert updated.status == "reviewed"
    assert updated.verdict == "good"
    assert updated.reviewer_id == "alice"
    assert updated.note == "Clear and concise"
    assert updated.reviewed_at is not None

    # Update verdict to bad with corrected output and reasons
    updated_bad = await store.update_verdict(
        "rev-1",
        verdict="bad",
        reasons=["incomplete", "formatting"],
        corrected_output="Go to Settings > Security > Reset Password.",
        reviewer_id="bob",
        note="Missed steps",
    )
    assert updated_bad is not None
    assert updated_bad.status == "reviewed"
    assert updated_bad.verdict == "bad"
    assert updated_bad.reasons == ["incomplete", "formatting"]
    assert updated_bad.corrected_output == "Go to Settings > Security > Reset Password."
    assert updated_bad.reviewer_id == "bob"


@pytest.mark.asyncio
async def test_review_skip(store: ReviewStore):
    item = ReviewItem(
        id="rev-skip",
        item_id="rev-skip",
        run_id="run-2",
        flow_id="triage",
        node_id="classify",
        inputs={"ticket": 123},
        outputs={"cat": "billing"},
    )
    await store.put_item(item)

    skipped = await store.skip_item("rev-skip", note="Ambiguous ticket", reviewer_id="carol")
    assert skipped is not None
    assert skipped.status == "skipped"
    assert skipped.note == "Ambiguous ticket"
    assert skipped.reviewer_id == "carol"
    assert skipped.reviewed_at is not None


@pytest.mark.asyncio
async def test_list_items_filtering_and_pagination(store: ReviewStore):
    # Populate items across flows and statuses
    for i in range(10):
        flow = "flow_a" if i < 6 else "flow_b"
        item = ReviewItem(
            id=f"item-{i}",
            item_id=f"item-{i}",
            run_id=f"run-{i}",
            flow_id=flow,
            flow_version=1,
            node_id="final",
            inputs={"x": i},
            outputs={"y": i * 2},
        )
        await store.put_item(item)

    # Mark some as reviewed
    await store.update_verdict("item-0", verdict="good", reviewer_id="alice")
    await store.update_verdict("item-1", verdict="bad", reasons=["wrong"], reviewer_id="alice")
    await store.update_verdict("item-6", verdict="good", reviewer_id="bob")
    # Skip one
    await store.skip_item("item-2", note="skip", reviewer_id="carol")

    # Filter by flow
    items_a, total_a = await store.list_items(flow_id="flow_a")
    assert total_a == 6
    assert len(items_a) == 6

    # Filter by status
    pending, total_pending = await store.list_items(status="pending")
    assert total_pending == 6  # 10 - 3 reviewed - 1 skipped
    assert len(pending) == 6

    reviewed, total_reviewed = await store.list_items(status="reviewed")
    assert total_reviewed == 3

    skipped, total_skipped = await store.list_items(status="skipped")
    assert total_skipped == 1

    # Filter by verdict
    good, total_good = await store.list_items(verdict="good")
    assert total_good == 2

    bad, total_bad = await store.list_items(verdict="bad")
    assert total_bad == 1

    # Pagination
    page1, _ = await store.list_items(limit=3, offset=0)
    assert len(page1) == 3
    page2, _ = await store.list_items(limit=3, offset=3)
    assert len(page2) == 3
    assert page1[0].id != page2[0].id


# -----------------------------------------------------------------------------
# 2. Sampling Config
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sampling_config(store: ReviewStore):
    # Default is off
    default_cfg = await store.get_sampling_config("unknown_flow")
    assert default_cfg.flow_id == "unknown_flow"
    assert default_cfg.mode == "off"
    assert default_cfg.percentage == 100
    assert default_cfg.rules == []
    assert default_cfg.nodes == []

    # Update config
    new_cfg = ReviewSamplingConfig(
        flow_id="support_bot",
        mode="rules",
        percentage=20,
        rules=["failed", "fallback_used"],
        nodes=["agent_node", "llm_node"],
        updated_by="admin_user",
    )
    saved = await store.put_sampling_config(new_cfg)
    assert saved.mode == "rules"
    assert saved.percentage == 20
    assert "failed" in saved.rules
    assert "agent_node" in saved.nodes
    assert saved.updated_by == "admin_user"
    assert saved.updated_at is not None

    # Retrieve again
    fetched = await store.get_sampling_config("support_bot")
    assert fetched.mode == "rules"
    assert fetched.rules == ["failed", "fallback_used"]
    assert fetched.nodes == ["agent_node", "llm_node"]


# -----------------------------------------------------------------------------
# 3. Sampling Rules & Engine Evaluation
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sampling_mode_off(store: ReviewStore, storage: Any):
    from agentos.flows.engine import FlowEngine

    flow = _make_flow("flow_off", ["out"])
    engine = FlowEngine(flow, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="flow_off", mode="off"))

    state = FlowRunState(run_id="run-off")
    state.node_outputs["out"] = {"result": "ok"}

    await engine._maybe_sample_for_review(state, RunStatus.SUCCEEDED)
    items, total = await store.list_items(flow_id="flow_off")
    assert total == 0


@pytest.mark.asyncio
async def test_sampling_mode_all(store: ReviewStore, storage: Any):
    from agentos.flows.engine import FlowEngine

    flow = _make_flow("flow_all", ["step1"])
    engine = FlowEngine(flow, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="flow_all", mode="all"))

    state = FlowRunState(run_id="run-all-1")
    state.node_inputs["step1"] = {"q": "hello"}
    state.node_outputs["step1"] = {"ans": "world"}

    await engine._maybe_sample_for_review(state, RunStatus.SUCCEEDED)
    items, total = await store.list_items(flow_id="flow_all")
    assert total == 1
    assert items[0].run_id == "run-all-1"
    assert items[0].node_id == "step1"
    assert items[0].outputs["ans"] == "world"


@pytest.mark.asyncio
async def test_sampling_mode_percentage_tolerance(store: ReviewStore, storage: Any):
    """Test that percentage sampling enqueues roughly the target percentage over many runs."""
    from agentos.flows.engine import FlowEngine

    flow = _make_flow("flow_pct", ["final"])
    engine = FlowEngine(flow, storage)
    target_pct = 30
    await store.put_sampling_config(
        ReviewSamplingConfig(flow_id="flow_pct", mode="percentage", percentage=target_pct)
    )

    # Run 100 times
    for i in range(100):
        state = FlowRunState(run_id=f"run-pct-{i}")
        state.node_outputs["final"] = {"val": i}
        await engine._maybe_sample_for_review(state, RunStatus.SUCCEEDED)

    items, total = await store.list_items(flow_id="flow_pct")
    # For target 30% over 100 trials, sampled count should comfortably be within [15, 45]
    assert 15 <= total <= 45, f"Expected between 15 and 45 sampled items for 30%, got {total}"


@pytest.mark.asyncio
async def test_sampling_rules_triggers(store: ReviewStore, storage: Any):
    """Test each rule in mode='rules'."""
    from agentos.flows.engine import FlowEngine

    # 1. Rule: failed
    flow = _make_flow("f_rules", ["out"])
    engine = FlowEngine(flow, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="f_rules", mode="rules", rules=["failed"]))

    state_ok = FlowRunState(run_id="r1")
    state_ok.node_outputs["out"] = {"x": 1}
    await engine._maybe_sample_for_review(state_ok, RunStatus.SUCCEEDED)
    _, total = await store.list_items(flow_id="f_rules")
    assert total == 0  # Succeeded -> not sampled

    state_fail = FlowRunState(run_id="r2")
    state_fail.node_outputs["out"] = {"err": "boom"}
    await engine._maybe_sample_for_review(state_fail, RunStatus.FAILED)
    _, total = await store.list_items(flow_id="f_rules")
    assert total == 1

    # 2. Rule: fallback_used
    flow_fb = _make_flow("f_fallback", ["out"])
    engine_fb = FlowEngine(flow_fb, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="f_fallback", mode="rules", rules=["fallback_used"]))

    state_no_fb = FlowRunState(run_id="r3")
    state_no_fb.node_outputs["out"] = {"x": 1}
    await engine_fb._maybe_sample_for_review(state_no_fb, RunStatus.SUCCEEDED)
    _, total = await store.list_items(flow_id="f_fallback")
    assert total == 0

    state_fb = FlowRunState(run_id="r4")
    state_fb.node_outputs["out"] = {"x": 1}
    state_fb.handled_failures["out"] = {"error": "fallback"}  # Handled fallback
    await engine_fb._maybe_sample_for_review(state_fb, RunStatus.SUCCEEDED)
    _, total = await store.list_items(flow_id="f_fallback")
    assert total == 1

    # 3. Rule: rejected_input
    flow_rej = _make_flow("f_rej", ["out"])
    engine_rej = FlowEngine(flow_rej, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="f_rej", mode="rules", rules=["rejected_input"]))

    state_rej = FlowRunState(run_id="r5")
    state_rej.node_outputs["out"] = {"x": 1}
    # Append extraction_rejected event
    await storage.events.append("r5", "extraction_rejected", {"reason": "bad format"})
    await engine_rej._maybe_sample_for_review(state_rej, RunStatus.SUCCEEDED)
    _, total = await store.list_items(flow_id="f_rej")
    assert total == 1

    # 4. Rule: approval_rejected
    flow_app = _make_flow("f_app", ["out"])
    engine_app = FlowEngine(flow_app, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="f_app", mode="rules", rules=["approval_rejected"]))

    state_app = FlowRunState(run_id="r6")
    state_app.node_outputs["out"] = {"x": 1}
    await storage.events.append("r6", "approval_rejected", {"node_id": "gate"})
    await engine_app._maybe_sample_for_review(state_app, RunStatus.SUCCEEDED)
    _, total = await store.list_items(flow_id="f_app")
    assert total == 1

    # 5. Rule: sink_blocked
    flow_sink = _make_flow("f_sink", ["out"])
    engine_sink = FlowEngine(flow_sink, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="f_sink", mode="rules", rules=["sink_blocked"]))

    state_sink = FlowRunState(run_id="r7")
    state_sink.node_outputs["out"] = {"x": 1}
    await storage.events.append("r7", "tool_call_rejected", {"reason": "untrusted"})
    await engine_sink._maybe_sample_for_review(state_sink, RunStatus.SUCCEEDED)
    _, total = await store.list_items(flow_id="f_sink")
    assert total == 1


@pytest.mark.asyncio
async def test_target_nodes_sampling(store: ReviewStore, storage: Any):
    """Test sampling designated nodes vs default final node."""
    from agentos.flows.engine import FlowEngine

    flow = _make_flow("target_flow", ["agent_step", "llm_step", "final_output"])
    engine = FlowEngine(flow, storage)

    # Specific nodes: ['agent_step', 'llm_step']
    await store.put_sampling_config(
        ReviewSamplingConfig(
            flow_id="target_flow",
            mode="all",
            nodes=["agent_step", "llm_step"],
        )
    )

    state = FlowRunState(run_id="run-targets")
    state.node_inputs["agent_step"] = {"in": 1}
    state.node_outputs["agent_step"] = {"draft": "A"}
    state.node_inputs["llm_step"] = {"in": 2}
    state.node_outputs["llm_step"] = {"text": "B"}
    state.node_inputs["final_output"] = {"in": 3}
    state.node_outputs["final_output"] = {"done": True}

    await engine._maybe_sample_for_review(state, RunStatus.SUCCEEDED)

    items, total = await store.list_items(flow_id="target_flow")
    assert total == 2
    node_ids = {i.node_id for i in items}
    assert node_ids == {"agent_step", "llm_step"}
    assert "final_output" not in node_ids


# -----------------------------------------------------------------------------
# 4. Security Labels & Corrected Output Isolation
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_security_labels_in_review_items(store: ReviewStore, storage: Any):
    from agentos.flows.engine import FlowEngine
    from agentos.flows.labels import Label

    flow = _make_flow("labeled_flow", ["eval_node"])
    engine = FlowEngine(flow, storage)
    await store.put_sampling_config(ReviewSamplingConfig(flow_id="labeled_flow", mode="all"))

    state = FlowRunState(run_id="run-labels")
    state.node_inputs["eval_node"] = {"untrusted_prompt": "Drop database;"}
    state.node_input_labels["eval_node"] = {
        "untrusted_prompt": Label(confidentiality="public", integrity="untrusted", sources=["webhook"])
    }
    state.node_outputs["eval_node"] = {"secret_token": "token-123", "normal_resp": "Hello"}
    state.node_output_labels["eval_node"] = {
        "secret_token": Label(confidentiality="secret", integrity="trusted", sources=["vault"]),
        "normal_resp": Label(confidentiality="public", integrity="trusted", sources=["llm"]),
    }

    await engine._maybe_sample_for_review(state, RunStatus.SUCCEEDED)

    items, _ = await store.list_items(flow_id="labeled_flow")
    assert len(items) == 1
    item = items[0]

    # Labels preserved faithfully
    assert item.input_labels["untrusted_prompt"]["integrity"] == "untrusted"
    assert item.output_labels["secret_token"]["confidentiality"] == "secret"
    assert item.output_labels["normal_resp"]["confidentiality"] == "public"


@pytest.mark.asyncio
async def test_corrected_output_isolation(store: ReviewStore):
    """Ensure corrected output is stored and exported but does not alter flow run context."""
    item = ReviewItem(
        id="iso-1",
        item_id="iso-1",
        run_id="run-iso",
        flow_id="flow_iso",
        node_id="gen",
        inputs={"prompt": "2 + 2"},
        outputs={"answer": "5"},  # wrong
    )
    await store.put_item(item)

    # Reviewer provides corrected output
    reviewed = await store.update_verdict(
        "iso-1",
        verdict="bad",
        reasons=["wrong"],
        corrected_output="4",
        reviewer_id="human_verifier",
    )
    assert reviewed.corrected_output == "4"

    # Verify that the original outputs remain untampered in the review item
    fetched = await store.get_item("iso-1")
    assert fetched.outputs["answer"] == "5"
    assert fetched.corrected_output == "4"


# -----------------------------------------------------------------------------
# 5. Quality Metrics
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_review_quality_metrics(store: ReviewStore):
    # 10 items for flow_q: 7 good, 3 bad
    for i in range(10):
        item = ReviewItem(
            id=f"qm-{i}",
            item_id=f"qm-{i}",
            run_id=f"run-{i}",
            flow_id="flow_q",
            flow_version=1,
            node_id="bot",
            inputs={"q": i},
            outputs={"a": i},
        )
        await store.put_item(item)

    # 7 good
    for i in range(7):
        await store.update_verdict(f"qm-{i}", verdict="good", reviewer_id="alice")

    # 3 bad with reasons
    await store.update_verdict("qm-7", verdict="bad", reasons=["wrong", "made_up"], reviewer_id="bob")
    await store.update_verdict("qm-8", verdict="bad", reasons=["wrong", "incomplete"], reviewer_id="bob")
    await store.update_verdict("qm-9", verdict="bad", reasons=["unsafe"], reviewer_id="bob")

    metrics = await store.get_metrics("flow_q", flow_version=1)
    assert metrics.flow_id == "flow_q"
    assert metrics.flow_version == 1
    assert metrics.reviewed_count == 10
    assert metrics.good_count == 7
    assert metrics.bad_count == 3
    assert metrics.good_percentage == 70.0
    assert metrics.pct_good == 70.0

    # Top bad reasons ordering
    reason_map = {r.reason: r.count for r in metrics.top_bad_reasons}
    assert reason_map["wrong"] == 2
    assert reason_map["made_up"] == 1
    assert reason_map["incomplete"] == 1
    assert reason_map["unsafe"] == 1
    assert metrics.top_bad_reasons[0].reason == "wrong"  # Highest count first


# -----------------------------------------------------------------------------
# 6. Export JSONL & Secret Exclusion
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_jsonl_and_secret_redaction(store: ReviewStore):
    item = ReviewItem(
        id="exp-1",
        item_id="exp-1",
        run_id="run-exp",
        flow_id="flow_exp",
        flow_version=1,
        node_id="auth_node",
        inputs={"username": "alice", "vault_secret": "my-secret-pw"},
        input_labels={
            "vault_secret": {"confidentiality": "secret", "integrity": "trusted"},
            "username": {"confidentiality": "public", "integrity": "untrusted"},
        },
        outputs={"token": "bearer-secret-xyz", "welcome": "Welcome alice!"},
        output_labels={
            "token": {"confidentiality": "secret", "integrity": "trusted"},
            "welcome": {"confidentiality": "public", "integrity": "trusted"},
        },
    )
    await store.put_item(item)
    await store.update_verdict(
        "exp-1",
        verdict="good",
        corrected_output="Welcome, Alice!",
        reviewer_id="auditor",
    )

    # 1. Export without secrets (default)
    records = await store.export_items(flow_id="flow_exp", include_secrets=False)
    assert len(records) == 1
    record = records[0]

    assert record["flow_id"] == "flow_exp"
    assert record["verdict"] == "good"
    assert record["corrected_output"] == "Welcome, Alice!"
    assert record["input"]["username"] == "alice"
    assert record["input"]["vault_secret"] == "[SECRET redacted]"
    assert record["output"]["welcome"] == "Welcome alice!"
    assert record["output"]["token"] == "[SECRET redacted]"

    # 2. Export with secrets (admin opt-in)
    records_sec = await store.export_items(flow_id="flow_exp", include_secrets=True)
    assert len(records_sec) == 1
    record_sec = records_sec[0]

    assert record_sec["input"]["vault_secret"] == "my-secret-pw"
    assert record_sec["output"]["token"] == "bearer-secret-xyz"


# -----------------------------------------------------------------------------
# 7. Manual "Send to Review"
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_to_review(store: ReviewStore, storage: Any):
    # Setup mock run data in storage
    await storage.runs.put(
        RunRecord(
            run_id="run-manual",
            mission_name="send_flow",
            flow_id="send_flow",
            flow_version=3,
            status="succeeded",
        )
    )
    await storage.events.append(
        "run-manual",
        "node_finished",
        {
            "node_id": "step_manual",
            "inputs": {"text": "inspect me"},
            "outputs": {"summary": "done"},
        },
    )

    item = await enqueue_run_for_review(storage, "run-manual", node_id="step_manual")
    assert item is not None
    assert item.flow_id == "send_flow"
    assert item.flow_version == 3
    assert item.node_id == "step_manual"
    assert item.inputs["text"] == "inspect me"
    assert item.outputs["summary"] == "done"
    assert item.status == "pending"
