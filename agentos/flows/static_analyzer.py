"""Static flow graph analyzer and Information Flow Control verification.

The StaticFlowAnalyzer inspects declarative flow definitions before execution,
over-approximates security labels from sources through joins and declassification
nodes, iterates over loop back-edges to a fixpoint, and rejects any flow where
untrusted data reaches sensitive sink arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.models import FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from agentos.flows.rules import RuleViolation, evaluate_sink_argument_rule
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass

# Backwards compatibility alias
Violation = RuleViolation


@dataclass
class PublishVerificationResult:
    """Outcome of publish-time static flow verification."""

    is_valid: bool
    violations: list[RuleViolation] = field(default_factory=list)

    @property
    def error_message(self) -> str:
        if self.is_valid:
            return ""
        lines = ["Flow verification failed with security violations:"]
        for v in self.violations:
            path_str = " -> ".join(v.path)
            lines.append(f"  - [{v.node_id}:{v.target_arg}] {v.reason} (Path: {path_str})")
        return "\n".join(lines)


class StaticFlowAnalyzer:
    """Analyzes flow graphs for Information Flow Control (IFC) and sink policy compliance."""

    def __init__(self, flow: FlowDefinition, policy: SecurityPolicy | None = None) -> None:
        self.flow = flow
        self.policy = policy or SecurityPolicy()

    def verify(self) -> PublishVerificationResult:
        """Statically inspect flow graph and verify that sink arguments satisfy security policies."""
        violations: list[RuleViolation] = []

        # 1. Propagate labels across graph edges (including back-edges) to a fixpoint
        node_output_labels, node_effective_inbound, node_paths = self._propagate_labels_fixpoint()

        # 2. Verify all sink policies on the stabilized label environment
        for node_id, node in self.flow.nodes.items():
            spec = BUILTIN_NODE_SPECS.get(node.type) or NodeSpec(type=node.type)
            current_path = node_paths.get(node_id, [node_id])
            effective_inbound = node_effective_inbound.get(node_id, Label.trusted())

            # Collect arriving argument labels
            inbound_edges = [e for e in self.flow.edges if e.target == node_id]
            arg_labels: dict[str, Label] = {}
            for edge in inbound_edges:
                src_labels = node_output_labels.get(edge.source, {})
                for target_arg, src_field in edge.arg_mapping.items():
                    if src_field in src_labels:
                        arg_labels[target_arg] = src_labels[src_field]

            # Direct sink nodes check
            if spec.side_effect in (
                SideEffectClass.EXTERNAL_SEND,
                SideEffectClass.DESTRUCTIVE,
                SideEffectClass.WRITE,
            ):
                self._check_node_sinks(
                    node_id, node, spec, arg_labels, effective_inbound, current_path, violations
                )

            # Agent nodes with attached tools check
            if node.type == "agent":
                self._check_agent_tool_sinks(
                    node_id, node, effective_inbound, current_path, violations
                )

        return PublishVerificationResult(
            is_valid=len(violations) == 0,
            violations=violations,
        )

    def _propagate_labels_fixpoint(
        self,
    ) -> tuple[dict[str, dict[str, Label]], dict[str, Label], dict[str, list[str]]]:
        """Iteratively propagate security labels across all edges to a fixpoint.

        Handles loops and back-edges correctly: if untrusted data enters only
        through a back-edge, it will degrade downstream labels to untrusted.
        """
        node_output_labels: dict[str, dict[str, Label]] = {}
        node_effective_inbound: dict[str, Label] = {}
        node_paths: dict[str, list[str]] = {self.flow.entrypoint: [self.flow.entrypoint]}

        # Initialize entrypoint
        entry_node = self.flow.nodes[self.flow.entrypoint]
        entry_spec = BUILTIN_NODE_SPECS.get(entry_node.type) or NodeSpec(type=entry_node.type)
        if entry_node.type == "webhook_trigger":
            init_inbound = Label.untrusted(sources={self.flow.entrypoint})
        else:
            init_inbound = Label.trusted(sources={self.flow.entrypoint})

        node_effective_inbound[self.flow.entrypoint] = init_inbound
        node_output_labels[self.flow.entrypoint] = self._compute_output_labels(
            self.flow.entrypoint, entry_node, entry_spec, init_inbound, {}
        )

        max_iterations = (len(self.flow.nodes) + 1) * 4
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            changed = False

            for node_id, node in self.flow.nodes.items():
                spec = BUILTIN_NODE_SPECS.get(node.type) or NodeSpec(type=node.type)
                inbound_edges = [e for e in self.flow.edges if e.target == node_id]

                inbound_labels: list[Label] = []
                arg_labels: dict[str, Label] = {}

                for edge in inbound_edges:
                    src_labels = node_output_labels.get(edge.source, {})
                    if not src_labels:
                        continue

                    # Every edge carries the join of all source output labels, mapped or not
                    src_join_all = Label.join_all(list(src_labels.values()), default=Label.trusted())
                    inbound_labels.append(src_join_all)

                    # Update path
                    src_path = node_paths.get(edge.source, [edge.source])
                    if node_id not in node_paths:
                        node_paths[node_id] = src_path + [node_id]

                    # Map individual arguments
                    for target_arg, src_field in edge.arg_mapping.items():
                        if src_field in src_labels:
                            arg_labels[target_arg] = src_labels[src_field]

                if not inbound_labels and node_id == self.flow.entrypoint:
                    effective_inbound = node_effective_inbound.get(
                        node_id,
                        Label.untrusted(sources={node_id})
                        if node.type == "webhook_trigger"
                        else Label.trusted(sources={node_id}),
                    )
                elif inbound_labels:
                    effective_inbound = Label.join_all(inbound_labels, default=Label.trusted())
                else:
                    effective_inbound = Label.trusted(sources={node_id})

                # Check if inbound changed
                prev_inbound = node_effective_inbound.get(node_id)
                if prev_inbound != effective_inbound:
                    node_effective_inbound[node_id] = effective_inbound
                    changed = True

                # Compute output labels
                new_outputs = self._compute_output_labels(
                    node_id, node, spec, effective_inbound, arg_labels
                )
                prev_outputs = node_output_labels.get(node_id, {})
                if prev_outputs != new_outputs:
                    node_output_labels[node_id] = new_outputs
                    changed = True

            if not changed:
                break

        return node_output_labels, node_effective_inbound, node_paths

    def _check_node_sinks(
        self,
        node_id: str,
        node: NodeDefinition,
        spec: NodeSpec,
        arg_labels: dict[str, Label],
        effective_inbound: Label,
        current_path: list[str],
        violations: list[RuleViolation],
    ) -> None:
        """Verify sink arguments on direct sink nodes using the shared rule engine."""
        pinned_args = node.pinned_args

        # Confidentiality check for unmapped wildcard inputs
        if spec.side_effect == SideEffectClass.EXTERNAL_SEND:
            if effective_inbound.confidentiality == Confidentiality.SECRET.value:
                violations.append(
                    RuleViolation(
                        node_id=node_id,
                        target_arg="*",
                        path=current_path,
                        reason=(
                            f"Confidentiality violation: secret-labeled data cannot be passed "
                            f"to EXTERNAL_SEND sink {node_id!r}."
                        ),
                    )
                )

        # Evaluate rules using shared engine
        for arg_name, rule in spec.sink_rules.items():
            is_pinned = arg_name in pinned_args
            arriving_label = (
                Label.trusted(sources={node_id})
                if is_pinned
                else arg_labels.get(arg_name, effective_inbound)
            )

            # Part 0.a: Argument is approved only if mapped on edge from approval node
            is_approved = False
            for edge in self.flow.edges:
                if edge.target == node_id and arg_name in edge.arg_mapping:
                    src_node = self.flow.nodes.get(edge.source)
                    if src_node and src_node.type == "approval":
                        approves_cfg = src_node.config.get("approves", {})
                        if (
                            approves_cfg.get("sink_node") == node_id
                            and arg_name in approves_cfg.get("args", [])
                        ):
                            is_approved = True
                            break

            arg_violations = evaluate_sink_argument_rule(
                node_id=node_id,
                spec=spec,
                arg_name=arg_name,
                rule=rule,
                arriving_label=arriving_label,
                effective_inbound_label=effective_inbound,
                is_pinned=is_pinned,
                is_approved=is_approved,
                pinned_to_val=pinned_args.get("to"),
                policy=self.policy,
                path=current_path,
            )
            violations.extend(arg_violations)

    def _check_agent_tool_sinks(
        self,
        node_id: str,
        node: NodeDefinition,
        agent_input_label: Label,
        current_path: list[str],
        violations: list[RuleViolation],
    ) -> None:
        """Verify sink tools attached to agent nodes using the shared rule engine."""
        tools = node.config.get("tools", [])
        pinned_args = node.pinned_args

        # Accumulate agent context: tools producing untrusted output degrade context to untrusted
        agent_context_label = agent_input_label
        for tool_name in tools:
            tool_spec = BUILTIN_NODE_SPECS.get(tool_name)
            if tool_spec and (
                tool_spec.type in ("fetch_url", "tool")
                or tool_spec.side_effect == SideEffectClass.READ
            ):
                agent_context_label = agent_context_label.join(Label.untrusted(sources={tool_name}))

        for tool_name in tools:
            tool_spec = BUILTIN_NODE_SPECS.get(tool_name)
            if not tool_spec:
                continue

            # Confidentiality check for agent sink tools
            if tool_spec.side_effect == SideEffectClass.EXTERNAL_SEND:
                if agent_context_label.confidentiality == Confidentiality.SECRET.value:
                    violations.append(
                        RuleViolation(
                            node_id=node_id,
                            target_arg=tool_name,
                            path=current_path + [tool_name],
                            reason=(
                                f"Confidentiality violation: secret-labeled data cannot be passed "
                                f"to EXTERNAL_SEND tool {tool_name!r} attached to agent {node_id!r}."
                            ),
                        )
                    )

            if not tool_spec.sink_rules:
                continue

            for arg_name, rule in tool_spec.sink_rules.items():
                canonical_pinned_key = f"{tool_name}.{arg_name}"
                is_pinned = canonical_pinned_key in pinned_args or arg_name in pinned_args
                arriving_label = (
                    Label.trusted(sources={node_id})
                    if is_pinned
                    else agent_context_label
                )
                to_val = (
                    pinned_args.get(f"{tool_name}.to")
                    or pinned_args.get("to")
                )

                arg_violations = evaluate_sink_argument_rule(
                    node_id=node_id,
                    spec=tool_spec,
                    arg_name=canonical_pinned_key,
                    rule=rule,
                    arriving_label=arriving_label,
                    effective_inbound_label=agent_context_label,
                    is_pinned=is_pinned,
                    is_approved=False,  # Approval cannot declassify agent context in general
                    pinned_to_val=to_val,
                    policy=self.policy,
                    path=current_path + [tool_name],
                )
                violations.extend(arg_violations)

    def _compute_output_labels(
        self,
        node_id: str,
        node: NodeDefinition,
        spec: NodeSpec,
        effective_inbound: Label,
        arg_labels: dict[str, Label],
    ) -> dict[str, Label]:
        """Compute output labels for a node based on its type and declassification semantics."""
        # 1. Webhook trigger produces untrusted output explicitly
        if node.type == "webhook_trigger":
            lbl = Label.untrusted(sources={node_id})
            return {"payload": lbl, "headers": lbl, "*": lbl}

        # 2. Tool nodes produce untrusted output explicitly
        if node.type in ("tool", "fetch_url"):
            lbl = Label.untrusted(sources={node_id})
            return {"result": lbl, "content": lbl, "*": lbl}

        # 3. Approval node: human approval declassifies only approved args on approved sink node directly
        if node.type == "approval":
            approved_flag = Label.trusted(
                confidentiality=effective_inbound.confidentiality,
                sources=effective_inbound.sources | {node_id},
            )
            return {
                "approved": approved_flag,
                "data": effective_inbound,
                "*": effective_inbound,
            }

        # 4. Validator node: field_type is required, unknown/missing -> untrusted;
        # allowlist_match requires admin allowlist_name (inline allowlist is forbidden).
        if node.type == "validator":
            field_name = node.config.get("field", "data")
            field_type = node.config.get("field_type")

            # Check validity of declassification
            is_sound = False
            if field_type in ("enum", "bool", "bounded_number"):
                is_sound = True
            elif field_type == "allowlist_match":
                allowlist_name = node.config.get("allowlist_name")
                if allowlist_name and len(self.policy.allowlists.get(allowlist_name, [])) > 0:
                    is_sound = True

            if is_sound:
                declassified = Label.trusted(
                    confidentiality=effective_inbound.confidentiality,
                    sources=effective_inbound.sources | {node_id},
                )
            else:
                # Untrusted for free-text or unconstrained configuration
                declassified = Label.untrusted(
                    confidentiality=effective_inbound.confidentiality,
                    sources=effective_inbound.sources | {node_id},
                )
            return {field_name: declassified, "*": declassified, "data": declassified, "to": declassified}

        # 5. Agent node inherits inbound label and joins with tools producing untrusted output
        if node.type == "agent":
            agent_ctx = effective_inbound
            for tool_name in node.config.get("tools", []):
                tool_spec = BUILTIN_NODE_SPECS.get(tool_name)
                if tool_spec and (
                    tool_spec.type in ("fetch_url", "tool")
                    or tool_spec.side_effect == SideEffectClass.READ
                ):
                    agent_ctx = agent_ctx.join(Label.untrusted(sources={tool_name}))
            out_lbl = Label(
                integrity=agent_ctx.integrity,
                confidentiality=agent_ctx.confidentiality,
                sources=agent_ctx.sources | {node_id},
            )
            return {"output": out_lbl, "*": out_lbl}

        # 6. LLM node inherits input label join
        if node.type == "llm":
            out_lbl = Label(
                integrity=effective_inbound.integrity,
                confidentiality=effective_inbound.confidentiality,
                sources=effective_inbound.sources | {node_id},
            )
            return {"completion": out_lbl, "*": out_lbl}

        # Default fallback: inherit effective inbound label
        out_lbl = Label(
            integrity=effective_inbound.integrity,
            confidentiality=effective_inbound.confidentiality,
            sources=effective_inbound.sources | {node_id},
        )
        return {"*": out_lbl}
