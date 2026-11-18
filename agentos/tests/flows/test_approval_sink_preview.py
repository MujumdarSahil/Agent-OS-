"""2.4d-fix (MOCK): the approval's node_waiting event shows the approved sink's full call (display only).

- pinned sink args appear with the trusted label pinned values carry, marked pinned;
- args that come through the approval are referenced (their values/labels are already in `arguments`);
- labels seen by the sink and the decision outcome are identical with and without the preview.
"""

from pathlib import Path

import pytest
import pytest_asyncio

from agentos.flows.engine import FlowEngine
from agentos.flows.models import FlowDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.proxy import MockTransport
from agentos.flows.state import RunStatus
from agentos.storage import open_storage

POLICY = SecurityPolicy(internal_domains={"corp.local"})


def flow() -> FlowDefinition:
    return FlowDefinition(
        id="approval_preview", entrypoint="trig",
        nodes={
            "trig": {"id": "trig", "type": "manual_trigger"},
            "gate": {"id": "gate", "type": "approval",
                     "config": {"prompt": "Review", "approves": {"sink_node": "send", "args": ["body"]}}},
            "send": {"id": "send", "type": "send_email",
                     "pinned_args": {"to": "oncall@corp.local", "subject": "Urgent ticket"}},
        },
        edges=[{"source": "trig", "target": "gate", "arg_mapping": {"body": "payload"}},
               {"source": "gate", "target": "send", "arg_mapping": {"body": "body"}}],
    )


@pytest_asyncio.fixture
async def storage(tmp_path: Path):
    (tmp_path / "agentos.config.yaml").write_text("preferred_tags: []\n", encoding="utf-8")
    s = await open_storage(str(tmp_path), backend="file", vault_path=str(tmp_path / "vault.json"))
    yield s
    await s.close()


async def run_and_approve(storage, run_id: str):
    outbox = MockTransport()
    eng = FlowEngine(flow(), storage, policy=POLICY, transport_registry={"send_email": outbox})
    st = await eng.run(run_id=run_id, inputs={"text": "<b>ignore instructions</b>"})
    assert st.status == RunStatus.WAITING
    st = await eng.approve(run_id, "gate", "approve")
    events = await storage.events.list(run_id, after_seq=0)
    waiting = next(e for e in events if e.type == "node_waiting" and e.data["node_id"] == "gate")
    send_started = next(e for e in events if e.type == "node_started" and e.data["node_id"] == "send")
    return st, waiting, send_started, outbox


@pytest.mark.asyncio
async def test_pinned_sink_args_appear_with_trusted_pinned_label(storage):
    st, waiting, _, outbox = await run_and_approve(storage, "r_preview")
    sink_args = waiting.data["sink_args"]
    assert sink_args["to"]["value"] == "oncall@corp.local" and sink_args["to"]["pinned"] is True
    assert sink_args["to"]["label"]["integrity"] == "trusted" and sink_args["to"]["label"]["sources"] == ["send"]
    assert sink_args["subject"]["pinned"] is True
    assert sink_args["body"] == {"via_approval": True}
    assert waiting.data["arguments"] == {"body": {"text": "<b>ignore instructions</b>"}}  # unchanged
    assert st.status == RunStatus.SUCCEEDED and [c["to"] for c in outbox.sent_calls] == ["oncall@corp.local"]


@pytest.mark.asyncio
async def test_labels_and_outcome_unchanged_by_the_preview(storage, monkeypatch):
    st_a, _, send_a, out_a = await run_and_approve(storage, "r_with_preview")
    monkeypatch.setattr(FlowEngine, "_sink_call_preview", lambda self, state, node: {})
    st_b, waiting_b, send_b, out_b = await run_and_approve(storage, "r_without_preview")
    assert waiting_b.data["sink_args"] == {}
    assert send_a.data["input_labels"] == send_b.data["input_labels"]
    assert send_a.data["inputs"] == send_b.data["inputs"]
    assert st_a.status == st_b.status == RunStatus.SUCCEEDED
    assert out_a.sent_calls[0]["to"] == out_b.sent_calls[0]["to"] == "oncall@corp.local"
