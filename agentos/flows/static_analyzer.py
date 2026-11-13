"""Static flow graph analyzer and Information Flow Control verification.

The StaticFlowAnalyzer inspects declarative flow definitions before execution,
over-approximates security labels from sources through joins and declassification
nodes, and rejects any flow where untrusted data reaches sensitive sink arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentos.flows.labels import Integrity, Label
from agentos.flows.models import FlowDefinition
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass


@dataclass
class Violation:
    """Represents a security policy violation discovered during static analysis."""

    node_id: str
    target_arg: str
    path: list[str]
    reason: str


@dataclass
class PublishVerificationResult:
    """Outcome of publish-time static flow verification."""

    is_valid: bool
    violations: list[Violation] = field(default_factory=list)

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

    def __init__(self, flow: FlowDefinition) -> None:
        self.flow = flow

    def verify(self) -> PublishVerificationResult:
        """Statically inspect flow graph and verify that sink arguments satisfy security policies."""
        violations: list[Violation] = []

        # 1. Compute topological order of execution
        topo_order = self._topological_sort()

        # 2. Track simulated label environments per node:
        # node_output_labels: { node_id: { field_name: Label } }
        node_output_labels: dict[str, dict[str, Label]] = {}
        # node_effective_inbound_labels: { node_id: Label }
        node_effective_inbound: dict[str, Label] = {}
        # paths: { node_id: list[str] }
        node_paths: dict[str, list[str]] = {}

        for node_id in topo_order:
            node = self.flow.nodes[node_id]
            spec = BUILTIN_NODE_SPECS.get(node.type) or NodeSpec(type=node.type)

            # Determine path to this node
            current_path = node_paths.get(node_id, [node_id])

            # Aggregate incoming labels from all inbound edges
            inbound_edges = [e for e in self.flow.edges if e.target == node_id]
            inbound_labels: list[Label] = []
            arg_labels: dict[str, Label] = {}

            for edge in inbound_edges:
                src_labels = node_output_labels.get(edge.source, {})
                for target_arg, src_field in edge.arg_mapping.items():
                    src_lbl = src_labels.get(
                        src_field,
                        Label.untrusted(sources={edge.source}),
                    )
                    arg_labels[target_arg] = src_lbl
                    inbound_labels.append(src_lbl)

            # Node effective input label is join of all arriving inputs
            effective_input_label = (
                Label.join_all(inbound_labels, default=Label.trusted())
                if inbound_labels
                else (
                    Label.untrusted(sources={node_id})
                    if node.type == "webhook_trigger"
                    else Label.trusted(sources={node_id})
                )
            )
            node_effective_inbound[node_id] = effective_input_label

            # --- SINK CHECK 1: Direct Sink Nodes ---
            if spec.side_effect in (SideEffectClass.EXTERNAL_SEND, SideEffectClass.DESTRUCTIVE, SideEffectClass.WRITE):
                self._check_node_sinks(node_id, node, spec, arg_labels, current_path, violations)

            # --- SINK CHECK 2: Tools attached to Agent Nodes ---
            if node.type == "agent":
                self._check_agent_tool_sinks(node_id, node, effective_input_label, current_path, violations)

            # Compute output labels for current node
            node_output_labels[node_id] = self._compute_output_labels(
                node_id, node, spec, effective_input_label, arg_labels
            )

            # Propagate paths to downstream neighbors
            for edge in [e for e in self.flow.edges if e.source == node_id]:
                if edge.target not in node_paths:
                    node_paths[edge.target] = current_path + [edge.target]

        return PublishVerificationResult(
            is_valid=len(violations) == 0,
            violations=violations,
        )

    def _check_node_sinks(
        self,
        node_id: str,
        node: Any,
        spec: NodeSpec,
        arg_labels: dict[str, Label],
        current_path: list[str],
        violations: list[Violation],
    ) -> None:
        """Verify sink arguments on direct sink nodes."""
        pinned_args = {**node.config.get("pinned_args", {}), **node.pinned_args}

        for arg_name, rule in spec.sink_rules.items():
            if rule.required_integrity != Integrity.TRUSTED.value:
                continue

            # If the argument is pinned in author config, it carries trusted integrity
            if arg_name in pinned_args:
                continue

            # Otherwise, evaluate the arriving argument's label
            arriving_label = arg_labels.get(arg_name, Label.untrusted(sources={node_id}))
            if arriving_label.integrity == Integrity.UNTRUSTED.value:
                violations.append(
                    Violation(
                        node_id=node_id,
                        target_arg=arg_name,
                        path=current_path,
                        reason=(
                            f"Sink node {node_id!r} requires trusted argument {arg_name!r}, "
                            f"but received untrusted data from source(s) {sorted(arriving_label.sources)}."
                        ),
                    )
                )

    def _check_agent_tool_sinks(
        self,
        node_id: str,
        node: Any,
        agent_input_label: Label,
        current_path: list[str],
        violations: list[Violation],
    ) -> None:
        """Verify sink tools attached to agent nodes.

        Sink tools attached to an agent are sinks reached by the agent's input label join.
        Unpinned sink arguments on such tools fail static check unless declassified.
        """
        tools = node.config.get("tools", [])
        pinned_args = {**node.config.get("pinned_args", {}), **node.pinned_args}

        for tool_name in tools:
            tool_spec = BUILTIN_NODE_SPECS.get(tool_name)
            if not tool_spec or not tool_spec.sink_rules:
                continue

            # Check each sink rule on the attached tool
            for arg_name, rule in tool_spec.sink_rules.items():
                if rule.required_integrity != Integrity.TRUSTED.value:
                    continue

                # Check if the author pinned this argument on the agent or tool config
                is_pinned = (
                    arg_name in pinned_args
                    or f"{tool_name}.{arg_name}" in pinned_args
                    or node.config.get(f"pinned_{arg_name}") is not None
                    or node.config.get("pinned_to") is not None and arg_name == "to"
                )

                if is_pinned:
                    continue

                # If unpinned, the LLM supplies it, carrying the agent's input join label
                if agent_input_label.integrity == Integrity.UNTRUSTED.value:
                    violations.append(
                        Violation(
                            node_id=node_id,
                            target_arg=f"{tool_name}.{arg_name}",
                            path=current_path + [tool_name],
                            reason=(
                                f"Sink tool {tool_name!r} attached to agent {node_id!r} requires "
                                f"trusted argument {arg_name!r}, but argument is unpinned and "
                                f"receives untrusted context from source(s) {sorted(agent_input_label.sources)}."
                            ),
                        )
                    )

    def _compute_output_labels(
        self,
        node_id: str,
        node: Any,
        spec: NodeSpec,
        effective_inbound: Label,
        arg_labels: dict[str, Label],
    ) -> dict[str, Label]:
        """Compute output labels for a node based on its type and declassification semantics."""
        # 1. Webhook trigger produces untrusted output
        if node.type == "webhook_trigger":
            lbl = Label.untrusted(sources={node_id})
            return {"payload": lbl, "headers": lbl}

        # 2. Approval node declassifies all approved fields to trusted
        if node.type == "approval":
            declassified = Label.trusted(
                confidentiality=effective_inbound.confidentiality,
                sources=effective_inbound.sources | {node_id},
            )
            return {"*": declassified, "approved": declassified, "data": declassified}

        # 3. Validator node declassifies ONLY constrained field types
        if node.type == "validator":
            field_name = node.config.get("field", "data")
            field_type = node.config.get("field_type", "allowlist_match")

            # Constrained types: enum, bool, bounded_number, allowlist_match
            if field_type in spec.constrained_fields or field_type in (
                "enum",
                "bool",
                "bounded_number",
                "allowlist_match",
            ):
                declassified = Label.trusted(
                    confidentiality=effective_inbound.confidentiality,
                    sources=effective_inbound.sources | {node_id},
                )
            else:
                # SOUNDNESS RULE: Free-text fields stay untrusted even after passing validation!
                declassified = Label.untrusted(
                    confidentiality=effective_inbound.confidentiality,
                    sources=effective_inbound.sources | {node_id},
                )
            return {field_name: declassified, "*": declassified, "data": declassified}

        # 4. LLM and Agent inherit input label join
        if node.type in ("llm", "agent"):
            out_lbl = Label(
                integrity=effective_inbound.integrity,
                confidentiality=effective_inbound.confidentiality,
                sources=effective_inbound.sources | {node_id},
            )
            return {"output": out_lbl, "completion": out_lbl, "*": out_lbl}

        # Default fallback: inherit effective inbound label
        out_lbl = Label(
            integrity=effective_inbound.integrity,
            confidentiality=effective_inbound.confidentiality,
            sources=effective_inbound.sources | {node_id},
        )
        return {"*": out_lbl}

    def _topological_sort(self) -> list[str]:
        """Sort nodes in topological order."""
        adj: dict[str, list[str]] = {nid: [] for nid in self.flow.nodes}
        in_degree: dict[str, int] = {nid: 0 for nid in self.flow.nodes}

        # Ignore declared loop back-edges for topological ordering
        loop_back_edges: set[tuple[str, str]] = set()
        for loop_info in self.flow.loops.values():
            back_edge = loop_info.get("back_edge")
            if back_edge and isinstance(back_edge, (list, tuple)) and len(back_edge) == 2:
                loop_back_edges.add((str(back_edge[0]), str(back_edge[1])))

        for edge in self.flow.edges:
            if (edge.source, edge.target) in loop_back_edges:
                continue
            adj[edge.source].append(edge.target)
            in_degree[edge.target] += 1

        queue = [n for n, d in in_degree.items() if d == 0]
        order: list[str] = []

        while queue:
            curr = queue.pop(0)
            order.append(curr)
            for neighbor in adj[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        return order
