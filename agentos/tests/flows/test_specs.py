"""Unit tests for NodeSpecs, agent hardening, and flow graph topology validation."""

import pytest

from pydantic import ValidationError

from agentos.flows.models import (
    CyclicFlowError,
    EdgeDefinition,
    FlowDefinition,
    InvalidFlowConfigError,
    NodeDefinition,
)


def test_agent_node_hardening_rules():
    # Cache=True must be rejected by schema
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="bad_cache",
            entrypoint="agent_1",
            nodes={"agent_1": NodeDefinition(id="agent_1", type="agent", config={"cache": True})},
        )

    # allow_delegation=True must be rejected
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="bad_delegation",
            entrypoint="agent_1",
            nodes={"agent_1": NodeDefinition(id="agent_1", type="agent", config={"allow_delegation": True})},
        )

    # allow_code_execution=True must be rejected
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="bad_code_exec",
            entrypoint="agent_1",
            nodes={"agent_1": NodeDefinition(id="agent_1", type="agent", config={"allow_code_execution": True})},
        )

    # Direct raw MCP servers or raw tools must be rejected (additionalProperties: False)
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="bad_mcp",
            entrypoint="agent_1",
            nodes={"agent_1": NodeDefinition(id="agent_1", type="agent", config={"mcp_servers": ["http://evil.com"]})},
        )


def test_flow_dag_validation_clean_dag_passes():
    flow = FlowDefinition(
        id="clean_dag",
        entrypoint="node_a",
        nodes={
            "node_a": NodeDefinition(id="node_a", type="webhook_trigger"),
            "node_b": NodeDefinition(id="node_b", type="llm"),
            "node_c": NodeDefinition(id="node_c", type="send_email"),
        },
        edges=[
            EdgeDefinition(source="node_a", target="node_b", arg_mapping={"prompt": "payload"}),
            EdgeDefinition(source="node_b", target="node_c", arg_mapping={"body": "completion"}),
        ],
    )
    assert flow.id == "clean_dag"


def test_flow_dag_validation_rejects_general_cycle():
    with pytest.raises((ValidationError, CyclicFlowError), match="illegal general cycle"):
        FlowDefinition(
            id="cyclic_flow",
            entrypoint="node_a",
            nodes={
                "node_a": NodeDefinition(id="node_a", type="webhook_trigger"),
                "node_b": NodeDefinition(id="node_b", type="llm"),
                "node_c": NodeDefinition(id="node_c", type="llm"),
            },
            edges=[
                EdgeDefinition(source="node_a", target="node_b"),
                EdgeDefinition(source="node_b", target="node_c"),
                EdgeDefinition(source="node_c", target="node_a"),  # Cycle!
            ],
        )


def test_flow_dag_validation_allows_explicit_bounded_loop():
    flow = FlowDefinition(
        id="bounded_loop_flow",
        entrypoint="node_a",
        nodes={
            "node_a": NodeDefinition(id="node_a", type="webhook_trigger"),
            "loop_node": NodeDefinition(id="loop_node", type="loop", config={"max_iterations": 3}),
            "worker_node": NodeDefinition(id="worker_node", type="llm"),
        },
        edges=[
            EdgeDefinition(source="node_a", target="loop_node"),
            EdgeDefinition(source="loop_node", target="worker_node"),
            EdgeDefinition(source="worker_node", target="loop_node"),  # Back-edge declared in loop
        ],
        loops={
            "loop_node": {
                "max_iterations": 3,
                "back_edge": ["worker_node", "loop_node"],
            }
        },
    )
    assert flow.id == "bounded_loop_flow"
