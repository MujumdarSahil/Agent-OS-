"""Regression tests for 7 static-analyzer bypasses and 5 design fixes.

Every test verifies that insecure patterns, bypass attempts, or invalid configs
are strictly REJECTED (either by the static analyzer or at publish time via schema/model validation).
"""

import pytest
from pydantic import ValidationError

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.models import (
    EdgeDefinition,
    FlowDefinition,
    InvalidFlowConfigError,
    NodeDefinition,
)
from agentos.flows.policy import SecurityPolicy
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass
from agentos.flows.static_analyzer import StaticFlowAnalyzer


# ---------------------------------------------------------------------------
# Bypass 1: Unmapped Edge Carries Source Label Join
# ---------------------------------------------------------------------------

def test_bypass_1_unmapped_edge_propagates_untrusted_labels():
    """Bypass 1: webhook -> agent(tools=[send_email], `to` unpinned) via an edge with NO arg_mapping.

    Fix: every edge carries the join of all the source's output labels, mapped or not.
    """
    flow = FlowDefinition(
        id="bypass_1_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "agent_node": NodeDefinition(
                id="agent_node",
                type="agent",
                config={"role": "Emailer", "tools": ["send_email"]},
            ),
        },
        # Empty arg_mapping: must STILL carry the source's untrusted label join!
        edges=[
            EdgeDefinition(source="webhook_in", target="agent_node", arg_mapping={}),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow)
    result = analyzer.verify()

    assert not result.is_valid
    assert len(result.violations) > 0
    assert any(
        v.node_id == "agent_node" and v.target_arg == "send_email.to"
        for v in result.violations
    )


# ---------------------------------------------------------------------------
# Bypass 2: Validator Soundness
# ---------------------------------------------------------------------------

def test_bypass_2_validator_soundness():
    """Bypass 2: validator with no field_type, or unconstrained free text, or empty allowlist.

    Fix: field_type is required; unknown or missing -> untrusted.
    allowlist_match requires a non-empty allowlist.
    """
    # 2a: Missing field_type -> rejected at publish
    with pytest.raises((ValidationError, InvalidFlowConfigError)):
        FlowDefinition(
            id="bad_validator_no_field_type",
            entrypoint="webhook_in",
            nodes={
                "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
                "val": NodeDefinition(id="val", type="validator", config={"field": "to"}),
            },
        )

    # 2b: Unconstrained / free-text field_type ("free_text") -> stays untrusted, rejected at sink
    flow_free_text = FlowDefinition(
        id="free_text_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "val": NodeDefinition(
                id="val",
                type="validator",
                config={"field": "to", "field_type": "free_text"},
            ),
            "email_sink": NodeDefinition(id="email_sink", type="send_email"),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="val", arg_mapping={"data": "payload"}),
            EdgeDefinition(source="val", target="email_sink", arg_mapping={"to": "to"}),
        ],
    )
    res_free = StaticFlowAnalyzer(flow_free_text).verify()
    assert not res_free.is_valid
    assert any(v.target_arg == "to" for v in res_free.violations)

    # 2c: allowlist_match with missing allowlist_name -> rejected at publish
    with pytest.raises((ValidationError, InvalidFlowConfigError)):
        FlowDefinition(
            id="bad_validator_missing_allowlist_name",
            entrypoint="webhook_in",
            nodes={
                "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
                "val": NodeDefinition(
                    id="val",
                    type="validator",
                    config={"field": "to", "field_type": "allowlist_match"},
                ),
            },
        )

    # Part 0.b: Inline allowlist in node config is rejected by schema (must use admin allowlist_name)
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="inline_allowlist_rejected",
            entrypoint="webhook_in",
            nodes={
                "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
                "val": NodeDefinition(
                    id="val",
                    type="validator",
                    config={
                        "field": "to",
                        "field_type": "allowlist_match",
                        "allowlist": ["attacker@evil.com"],
                    },
                ),
            },
        )


# ---------------------------------------------------------------------------
# Bypass 3: Tool, HTTP, and MCP Outputs are Untrusted Sources
# ---------------------------------------------------------------------------

def test_bypass_3_agent_tool_untrusted_source_taints_context():
    """Bypass 3: agent(tools=[fetch_url, send_email], `to` unpinned) with trusted inputs.

    Fix: tool, HTTP and MCP outputs are untrusted sources. If an agent has any tool
    whose output is untrusted, its context label for sink checks is untrusted.
    Tool nodes output untrusted explicitly, not by a missing-field accident.
    """
    flow = FlowDefinition(
        id="bypass_3_flow",
        entrypoint="llm_trusted",
        nodes={
            "llm_trusted": NodeDefinition(
                id="llm_trusted",
                type="llm",
                config={"model": "gpt-4"},
            ),
            "agent_node": NodeDefinition(
                id="agent_node",
                type="agent",
                config={"role": "Researcher", "tools": ["fetch_url", "send_email"]},
            ),
        },
        edges=[
            EdgeDefinition(
                source="llm_trusted",
                target="agent_node",
                arg_mapping={"task": "completion"},
            ),
        ],
    )

    analyzer = StaticFlowAnalyzer(flow)
    result = analyzer.verify()

    # Agent input was trusted, but fetch_url is an untrusted source -> context untrusted -> sink rejected
    assert not result.is_valid
    assert any(
        v.node_id == "agent_node" and v.target_arg == "send_email.to"
        for v in result.violations
    )


# ---------------------------------------------------------------------------
# Bypass 4: Unknown Tools Fail Closed at Publish
# ---------------------------------------------------------------------------

def test_bypass_4_unknown_tool_rejected_at_publish():
    """Bypass 4: webhook -> agent(tools=[delete_all_files]) where the tool has no spec.

    Fix: unknown tools are rejected at publish (fail closed).
    """
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="unknown tool"):
        FlowDefinition(
            id="unknown_tool_flow",
            entrypoint="webhook_in",
            nodes={
                "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
                "agent_node": NodeDefinition(
                    id="agent_node",
                    type="agent",
                    config={"role": "Attacker", "tools": ["delete_all_files"]},
                ),
            },
        )


# ---------------------------------------------------------------------------
# Bypass 5: Disallowed Agent Config Fields (additionalProperties: False)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("forbidden_field", ["mcps", "apps", "knowledge_sources", "memory"])
def test_bypass_5_agent_config_forbidden_fields_rejected(forbidden_field: str):
    """Bypass 5: agent config with mcps / apps / knowledge_sources / memory set.

    Fix: validate every node config against its config_schema with jsonschema;
    the agent schema uses additionalProperties: false.
    """
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id=f"forbidden_{forbidden_field}",
            entrypoint="agent_1",
            nodes={
                "agent_1": NodeDefinition(
                    id="agent_1",
                    type="agent",
                    config={"role": "Assistant", forbidden_field: ["something"]},
                )
            },
        )


# ---------------------------------------------------------------------------
# Bypass 6: String Booleans in Agent Config Rejected
# ---------------------------------------------------------------------------

def test_bypass_6_agent_config_string_booleans_rejected():
    """Bypass 6: agent config cache: "true" (a string, not a bool) or unvalidated fields.

    Fix: use the schema; test that strings don't slip through boolean fields.
    """
    # String "true" instead of bool
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="str_bool_flow",
            entrypoint="agent_1",
            nodes={
                "agent_1": NodeDefinition(
                    id="agent_1",
                    type="agent",
                    config={"role": "Assistant", "cache": "true"},
                )
            },
        )

    # String "false" instead of bool
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="str_false_flow",
            entrypoint="agent_1",
            nodes={
                "agent_1": NodeDefinition(
                    id="agent_1",
                    type="agent",
                    config={"role": "Assistant", "cache": "false"},
                )
            },
        )


# ---------------------------------------------------------------------------
# Bypass 7: Exfiltration Sink and Secret Leaks Rejected
# ---------------------------------------------------------------------------

def test_bypass_7_send_email_external_exfiltration_and_secret_leak_rejected():
    """Bypass 7: send_email with `to` pinned to an external address and untrusted body.

    Fix: if `to` is not in the internal recipient allowlist, `body` requires trusted
    integrity. Also: secret-labelled data routed to an EXTERNAL_SEND sink is rejected.
    """
    policy = SecurityPolicy(internal_domains={"corp.local"})

    # 7a: Untrusted body sent to an external recipient is rejected (exfiltration sink)
    flow_external = FlowDefinition(
        id="exfil_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "email_sink": NodeDefinition(
                id="email_sink",
                type="send_email",
                pinned_args={"to": "attacker@evil.com"},
            ),
        },
        edges=[
            EdgeDefinition(
                source="webhook_in",
                target="email_sink",
                arg_mapping={"body": "payload"},
            ),
        ],
    )
    res_exfil = StaticFlowAnalyzer(flow_external, policy=policy).verify()
    assert not res_exfil.is_valid
    assert any("Untrusted body cannot be sent to external recipient" in v.reason for v in res_exfil.violations)

    # 7b: Secret-labeled data routed to EXTERNAL_SEND sink is rejected
    # Author a mock secret node to inject secret-labeled data
    secret_spec = NodeSpec(
        type="secret_store",
        side_effect=SideEffectClass.READ,
        output_schema={"type": "object", "properties": {"api_key": {"type": "string"}}},
    )
    BUILTIN_NODE_SPECS["secret_store"] = secret_spec

    try:
        flow_secret = FlowDefinition(
            id="secret_leak_flow",
            entrypoint="secret_store",
            nodes={
                "secret_store": NodeDefinition(id="secret_store", type="secret_store"),
                "email_sink": NodeDefinition(
                    id="email_sink",
                    type="send_email",
                    pinned_args={"to": "admin@corp.local"},
                ),
            },
            edges=[
                EdgeDefinition(
                    source="secret_store",
                    target="email_sink",
                    arg_mapping={"body": "api_key"},
                ),
            ],
        )

        analyzer_secret = StaticFlowAnalyzer(flow_secret, policy=policy)
        # Force secret label on secret_store output
        node_out, node_in, paths = analyzer_secret._propagate_labels_fixpoint()
        node_out["secret_store"]["api_key"] = Label(
            confidentiality=Confidentiality.SECRET.value,
            sources={"secret_store"},
        )

        # Directly verify sink check
        violations = []
        analyzer_secret._check_node_sinks(
            "email_sink",
            flow_secret.nodes["email_sink"],
            BUILTIN_NODE_SPECS["send_email"],
            {"body": node_out["secret_store"]["api_key"]},
            node_out["secret_store"]["api_key"],
            ["secret_store", "email_sink"],
            violations,
        )
        assert len(violations) > 0
        assert any("Confidentiality violation: secret-labeled data" in v.reason for v in violations)
    finally:
        BUILTIN_NODE_SPECS.pop("secret_store", None)


# ---------------------------------------------------------------------------
# Design Fix 8: Approval Node Targeting & Non-Declassification of Agent Context
# ---------------------------------------------------------------------------

def test_design_fix_8_approval_node_targeting_rules():
    """Design Fix 8: Approval node must declare WHICH sink and WHICH args it approves.

    It declassifies ONLY those arguments for that specific downstream sink.
    Placing approval before an agent does NOT make the agent context trusted.
    """
    policy = SecurityPolicy(internal_domains={"corp.local"})

    # 8a: Approval node placed before an agent does NOT make the agent context trusted
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="targets an agent node"):
        FlowDefinition(
            id="approval_agent_flow",
            entrypoint="webhook_in",
            nodes={
                "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
                "app": NodeDefinition(
                    id="app",
                    type="approval",
                    config={"prompt": "Approve", "approves": {"sink_node": "agent_node", "args": ["task"]}},
                ),
                "agent_node": NodeDefinition(
                    id="agent_node",
                    type="agent",
                    config={"role": "Worker", "tools": ["send_email"]},
                ),
            },
            edges=[
                EdgeDefinition(source="webhook_in", target="app", arg_mapping={"data": "payload"}),
                EdgeDefinition(source="app", target="agent_node", arg_mapping={"task": "data"}),
            ],
        )

    # 8b: Approval declaring sink_a does NOT declassify sink_b
    flow_two_sinks = FlowDefinition(
        id="approval_targeting_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "app": NodeDefinition(
                id="app",
                type="approval",
                config={"prompt": "Approve", "approves": {"sink_node": "sink_a", "args": ["to"]}},
            ),
            "sink_a": NodeDefinition(id="sink_a", type="send_email", pinned_args={"body": "hello"}),
            "sink_b": NodeDefinition(id="sink_b", type="send_email", pinned_args={"body": "hello"}),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="app", arg_mapping={"data": "payload"}),
            EdgeDefinition(source="app", target="sink_a", arg_mapping={"to": "data"}),
            EdgeDefinition(source="app", target="sink_b", arg_mapping={"to": "data"}),
        ],
    )
    res = StaticFlowAnalyzer(flow_two_sinks, policy=policy).verify()
    assert not res.is_valid
    # sink_a passed because it was approved; sink_b failed because approval only targeted sink_a!
    sink_b_violations = [v for v in res.violations if v.node_id == "sink_b"]
    assert len(sink_b_violations) > 0
    assert any(v.target_arg == "to" for v in sink_b_violations)
    assert not any(v.node_id == "sink_a" for v in res.violations)


def test_part0_a_approval_binding_unmapped_arg_rejected():
    """Part 0.a: Approval binding: an argument counts as approved only if that

    argument's value is mapped from the approval node's output on the edge into the sink.
    Regression test: approval approves `to`, but `to` comes straight from the webhook -> REJECTED.
    """
    policy = SecurityPolicy(internal_domains={"corp.local"})
    flow = FlowDefinition(
        id="unmapped_approval_flow",
        entrypoint="webhook_in",
        nodes={
            "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
            "app": NodeDefinition(
                id="app",
                type="approval",
                config={"prompt": "Approve", "approves": {"sink_node": "email_sink", "args": ["to"]}},
            ),
            "email_sink": NodeDefinition(id="email_sink", type="send_email", pinned_args={"body": "hello"}),
        },
        edges=[
            EdgeDefinition(source="webhook_in", target="app", arg_mapping={"data": "payload"}),
            # app -> email_sink has edge, but does NOT map 'to'
            EdgeDefinition(source="app", target="email_sink", arg_mapping={}),
            # 'to' comes STRAIGHT from webhook_in!
            EdgeDefinition(source="webhook_in", target="email_sink", arg_mapping={"to": "payload"}),
        ],
    )

    result = StaticFlowAnalyzer(flow, policy=policy).verify()
    assert not result.is_valid
    assert any(v.node_id == "email_sink" and v.target_arg == "to" for v in result.violations)


# ---------------------------------------------------------------------------
# Design Fix 9: SecurityPolicy Domain Configuration
# ---------------------------------------------------------------------------

def test_design_fix_9_security_policy_domain_allowlist():
    """Design Fix 9: Do not hardcode @corp.local in the engine.

    Default policy has internal_domains: set().
    """
    default_policy = SecurityPolicy()
    assert len(default_policy.internal_domains) == 0
    assert not default_policy.is_internal_email("alice@corp.local")

    configured_policy = SecurityPolicy(internal_domains={"corp.local"})
    assert configured_policy.is_internal_email("alice@corp.local")
    assert not configured_policy.is_internal_email("alice@external.com")


# ---------------------------------------------------------------------------
# Design Fix 10: Loop Fixpoint Iteration Over Back-Edges
# ---------------------------------------------------------------------------

def test_design_fix_10_loop_back_edge_propagates_untrusted_fixpoint():
    """Design Fix 10: Untrusted data entering only via loop back-edge taints downstream sink.

    Static analyzer iterates to a fixpoint over back-edges, not just a single DAG pass.
    """
    policy = SecurityPolicy(internal_domains={"corp.local"})
    # Entrypoint is trusted LLM.
    # LLM -> loop_head -> untrusted tool -> (back-edge back to loop_head) -> send_email sink.
    flow_loop = FlowDefinition(
        id="loop_back_edge_flow",
        entrypoint="trusted_init",
        nodes={
            "trusted_init": NodeDefinition(
                id="trusted_init",
                type="llm",
                config={"model": "gpt-4"},
            ),
            "loop_head": NodeDefinition(
                id="loop_head",
                type="loop",
                config={"max_iterations": 3},
            ),
            "fetch_step": NodeDefinition(
                id="fetch_step",
                type="fetch_url",
            ),
            "email_sink": NodeDefinition(
                id="email_sink",
                type="send_email",
            ),
        },
        edges=[
            EdgeDefinition(source="trusted_init", target="loop_head"),
            EdgeDefinition(source="loop_head", target="fetch_step", arg_mapping={"url": "data"}),
            # Back-edge from untrusted fetch_step back to loop_head!
            EdgeDefinition(source="fetch_step", target="loop_head", arg_mapping={"data": "content"}),
            # Downstream sink connected from loop_head
            EdgeDefinition(source="loop_head", target="email_sink", arg_mapping={"to": "data"}),
        ],
        loops={
            "loop_head": {
                "max_iterations": 3,
                "back_edge": ["fetch_step", "loop_head"],
            }
        },
    )

    result = StaticFlowAnalyzer(flow_loop, policy=policy).verify()
    # Due to fixpoint iteration over back-edge, email_sink receives untrusted data and is rejected!
    assert not result.is_valid
    assert any(v.node_id == "email_sink" and v.target_arg == "to" for v in result.violations)


# ---------------------------------------------------------------------------
# Design Fix 11: Canonical Pinned Args Syntax
# ---------------------------------------------------------------------------

def test_design_fix_11_canonical_pinned_args_syntax():
    """Design Fix 11: One canonical syntax node.pinned_args.

    Passing pinned_args in node.config is rejected by schema.
    """
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="config schema validation failed"):
        FlowDefinition(
            id="bad_pinned_args_in_config",
            entrypoint="agent_1",
            nodes={
                "agent_1": NodeDefinition(
                    id="agent_1",
                    type="agent",
                    config={"role": "Assistant", "pinned_args": {"send_email.to": "admin@corp.local"}},
                )
            },
        )


# ---------------------------------------------------------------------------
# Design Fix 12: Edge Referencing Unknown Source Output Field Rejected
# ---------------------------------------------------------------------------

def test_design_fix_12_edge_unknown_source_output_field_rejected():
    """Design Fix 12: If an edge's arg_mapping references an output field not in

    the source node's spec, reject at publish (fail closed).
    """
    with pytest.raises((ValidationError, InvalidFlowConfigError), match="references unknown source output field"):
        FlowDefinition(
            id="bad_edge_source_field",
            entrypoint="webhook_in",
            nodes={
                "webhook_in": NodeDefinition(id="webhook_in", type="webhook_trigger"),
                "llm_node": NodeDefinition(id="llm_node", type="llm", config={"model": "gpt-4"}),
            },
            edges=[
                # webhook_trigger only outputs 'payload' and 'headers', NOT 'non_existent_output'
                EdgeDefinition(
                    source="webhook_in",
                    target="llm_node",
                    arg_mapping={"prompt": "non_existent_output"},
                ),
            ],
        )
