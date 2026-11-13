"""Tests for publish-time StaticFlowAnalyzer and Information Flow Control verification."""

from agentos.flows.models import (
    EdgeDefinition,
    FlowDefinition,
    NodeDefinition,
)
from agentos.flows.policy import SecurityPolicy
from agentos.flows.static_analyzer import StaticFlowAnalyzer


def test_test_b_static_reject_unmediated_untrusted_to_sink():
    """Test B (Negative): Webhook -> Agent -> send_email Sink is rejected at publish time."""
    flow = FlowDefinition(
        id="unmediated_injection_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(id="agent_node", type="agent", config={"role": "Assistant"}),
            "email_sink": NodeDefinition(id="email_sink", type="send_email"),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
            EdgeDefinition(source="agent_node", target="email_sink", arg_mapping={"to": "output", "body": "output"}),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow)
    result = analyzer.verify()

    assert not result.is_valid
    assert len(result.violations) > 0
    violation = result.violations[0]
    assert violation.node_id == "email_sink"
    assert violation.target_arg == "to"
    assert "webhook_in" in violation.path or "agent_node" in violation.path
    assert "requires trusted argument 'to'" in violation.reason


def test_test_b_static_pass_with_allowlist_validator():
    """Test B (Passing Variant 1): Inserting an allowlist validator on `to` passes static verification."""
    flow = FlowDefinition(
        id="validated_injection_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(id="agent_node", type="agent", config={"role": "Assistant"}),
            "validator_node": NodeDefinition(
                id="validator_node",
                type="validator",
                config={"field": "to", "field_type": "allowlist_match", "allowlist": ["secops@corp.local"]},
            ),
            "email_sink": NodeDefinition(id="email_sink", type="send_email"),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
            EdgeDefinition(source="agent_node", target="validator_node", arg_mapping={"to": "output"}),
            EdgeDefinition(source="validator_node", target="email_sink", arg_mapping={"to": "to"}),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow)
    result = analyzer.verify()
    assert result.is_valid
    assert len(result.violations) == 0


def test_test_b_static_pass_with_human_approval():
    """Test B (Passing Variant 2): Inserting a human approval node before the sink passes static check."""
    policy = SecurityPolicy(internal_domains={"corp.local"})
    flow = FlowDefinition(
        id="approval_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(id="agent_node", type="agent", config={"role": "Assistant"}),
            "approval_node": NodeDefinition(
                id="approval_node",
                type="approval",
                config={
                    "prompt": "Approve email",
                    "approves": {"sink_node": "email_sink", "args": ["to", "body"]},
                },
            ),
            "email_sink": NodeDefinition(
                id="email_sink",
                type="send_email",
                pinned_args={"to": "secops@corp.local"},
            ),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
            EdgeDefinition(source="agent_node", target="approval_node", arg_mapping={"data": "output"}),
            EdgeDefinition(source="approval_node", target="email_sink", arg_mapping={"body": "data"}),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow, policy=policy)
    result = analyzer.verify()
    assert result.is_valid
    assert len(result.violations) == 0


def test_validator_soundness_free_text_stays_untrusted():
    """Soundness test: Free-text fields stay untrusted even after passing a validator."""
    flow = FlowDefinition(
        id="free_text_validator_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "validator_node": NodeDefinition(
                id="validator_node",
                type="validator",
                # Unconstrained field_type="text" (free-text string) must NOT upgrade integrity!
                config={"field": "to", "field_type": "text"},
            ),
            "email_sink": NodeDefinition(id="email_sink", type="send_email"),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="validator_node", arg_mapping={"data": "payload"}),
            EdgeDefinition(source="validator_node", target="email_sink", arg_mapping={"to": "to"}),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow)
    result = analyzer.verify()
    # Must fail because free-text field cannot be upgraded to trusted
    assert not result.is_valid
    assert any(v.target_arg == "to" for v in result.violations)


def test_instruction_4_agent_attached_sink_tool_unpinned_rejected_pinned_passes():
    """Instruction 4:

    Webhook -> agent(send_email tool, `to` unpinned) is rejected.
    With `to` pinned in author config, it passes.
    """
    policy = SecurityPolicy(internal_domains={"corp.local"})

    # 1. Unpinned variant: agent has send_email tool attached, but `to` is not pinned
    unpinned_flow = FlowDefinition(
        id="unpinned_agent_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(
                id="agent_node",
                type="agent",
                config={"role": "Support", "tools": ["send_email"]},
            ),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
        ],
    )

    analyzer_unpinned = StaticFlowAnalyzer(unpinned_flow, policy=policy)
    res_unpinned = analyzer_unpinned.verify()
    assert not res_unpinned.is_valid
    assert len(res_unpinned.violations) > 0
    violation = res_unpinned.violations[0]
    assert violation.node_id == "agent_node"
    assert violation.target_arg == "send_email.to"
    assert "send_email" in violation.path

    # 2. Pinned variant: `to` is pinned by the author on agent_node
    pinned_flow = FlowDefinition(
        id="pinned_agent_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(
                id="agent_node",
                type="agent",
                config={"role": "Support", "tools": ["send_email"]},
                pinned_args={"send_email.to": "secops@corp.local"},
            ),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
        ],
    )

    analyzer_pinned = StaticFlowAnalyzer(pinned_flow, policy=policy)
    res_pinned = analyzer_pinned.verify()
    assert res_pinned.is_valid
    assert len(res_pinned.violations) == 0


def test_test_f_static_benign_flow_passes():
    """Static part of Test F: Benign flow with pinned recipient passes verification."""
    policy = SecurityPolicy(internal_domains={"corp.local"})
    flow = FlowDefinition(
        id="test_f_static_benign",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(
                id="agent_node",
                type="agent",
                config={"role": "Summarizer", "tools": ["send_email"]},
                pinned_args={"send_email.to": "team@corp.local"},
            ),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={"task": "payload"}),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow, policy=policy)
    result = analyzer.verify()
    assert result.is_valid
    assert len(result.violations) == 0
