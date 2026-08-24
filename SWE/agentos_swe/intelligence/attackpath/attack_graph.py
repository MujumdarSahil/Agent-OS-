"""
M16 Attack Graph Builder.

Generates structured node-edge AttackGraphs and Graphviz DOT representations.
"""

from typing import List
from agentos_swe.intelligence.attackpath.models import (
    AttackPath,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
)


class AttackGraphBuilder:
    """
    Generates AttackGraph objects from AttackPath models.
    """

    def build_attack_graph(self, attack_path: AttackPath) -> AttackGraph:
        """
        Builds directed AttackGraph representation for visualization.
        """
        nodes = []
        edges = []

        # 1. Entrypoint Node
        ep_id = f"ep_{attack_path.id}"
        nodes.append(
            AttackGraphNode(
                node_id=ep_id,
                label=f"Entry: {attack_path.entrypoint}",
                node_type="ENTRYPOINT",
                metadata={"type": attack_path.entrypoint_type.value if hasattr(attack_path.entrypoint_type, "value") else str(attack_path.entrypoint_type)},
            )
        )

        # 2. Source Node
        src_id = f"src_{attack_path.id}"
        nodes.append(
            AttackGraphNode(
                node_id=src_id,
                label=f"Source: {attack_path.source_type} ({attack_path.source_file}:{attack_path.source_line})",
                node_type="SOURCE",
            )
        )
        edges.append(AttackGraphEdge(source_id=ep_id, target_id=src_id, edge_type="ENTERS"))

        # 3. Propagation & Trust Boundary Nodes
        prev_id = src_id
        for step in attack_path.propagation_steps:
            if step.step_type in ("CALL", "PROPAGATION"):
                step_id = f"step_{attack_path.id}_{step.step_index}"
                lbl = f"Fn: {step.function_name or 'scope'}"
                nodes.append(AttackGraphNode(node_id=step_id, label=lbl, node_type="FUNCTION"))
                edges.append(AttackGraphEdge(source_id=prev_id, target_id=step_id, edge_type="PROPAGATES"))
                prev_id = step_id

        # 4. Sanitizer Nodes (if any)
        if attack_path.sanitizer_steps:
            for san in attack_path.sanitizer_steps:
                san_id = f"san_{attack_path.id}_{san}"
                nodes.append(AttackGraphNode(node_id=san_id, label=f"Sanitizer: {san}", node_type="SANITIZER"))
                edges.append(AttackGraphEdge(source_id=prev_id, target_id=san_id, edge_type="SANITIZES"))
                prev_id = san_id

        # 5. Sink Node
        snk_id = f"snk_{attack_path.id}"
        nodes.append(
            AttackGraphNode(
                node_id=snk_id,
                label=f"Sink: {attack_path.sink_type} ({attack_path.sink_file}:{attack_path.sink_line})",
                node_type="SINK",
            )
        )
        edges.append(AttackGraphEdge(source_id=prev_id, target_id=snk_id, edge_type="REACHES"))

        # 6. Root Cause Vulnerability Node
        vuln_id = f"vuln_{attack_path.id}"
        nodes.append(
            AttackGraphNode(
                node_id=vuln_id,
                label=f"Vulnerability: {attack_path.root_cause}",
                node_type="VULNERABILITY",
            )
        )
        edges.append(AttackGraphEdge(source_id=snk_id, target_id=vuln_id, edge_type="EXPLOITS"))

        return AttackGraph(nodes=nodes, edges=edges)
