"""
M17 Remediation Graph Builder.

Builds structured graph representations connecting Findings -> Root Causes -> Attack Paths -> Remediations -> Validations -> Risk Reductions.
"""

from typing import List, Dict, Any
from agentos_swe.remediation.models import (
    RemediationPlan,
    RemediationItem,
    RemediationGraph,
    RemediationGraphNode,
    RemediationGraphEdge,
)


class RemediationGraphBuilder:
    """
    Deterministic Remediation Graph Builder.
    """

    def build_graph(self, plan: RemediationPlan) -> RemediationGraph:
        """
        Constructs a complete RemediationGraph for a RemediationPlan.
        """
        nodes: List[RemediationGraphNode] = []
        edges: List[RemediationGraphEdge] = []
        seen_nodes = set()

        def add_node(nid: str, label: str, ntype: str, meta: Dict[str, Any] = None):
            if nid not in seen_nodes:
                seen_nodes.add(nid)
                nodes.append(RemediationGraphNode(node_id=nid, label=label, node_type=ntype, metadata=meta or {}))

        def add_edge(src: str, tgt: str, etype: str, label: str = ""):
            edges.append(RemediationGraphEdge(source_id=src, target_id=tgt, edge_type=etype, label=label))

        for item in plan.remediation_items:
            rem_node_id = f"rem_{item.item_id}"
            add_node(rem_node_id, f"Fix: {item.title}", "REMEDIATION", {"item_id": item.item_id})

            # Root cause node
            rc_node_id = f"rc_{item.root_cause}"
            add_node(rc_node_id, f"Root Cause: {item.root_cause}", "ROOT_CAUSE")
            add_edge(rc_node_id, rem_node_id, "REMEDIATES")

            # Finding nodes
            for fid in item.affected_finding_ids:
                f_node_id = f"f_{fid}"
                add_node(f_node_id, f"Finding: {fid}", "FINDING")
                add_edge(f_node_id, rc_node_id, "GROUPS")

            # Attack path nodes
            for pid in item.affected_attack_path_ids:
                ap_node_id = f"ap_{pid}"
                add_node(ap_node_id, f"Attack Path: {pid}", "ATTACK_PATH")
                add_edge(rem_node_id, ap_node_id, "BREAKS")

            # Validation node
            val_node_id = f"val_{item.item_id}"
            add_node(val_node_id, f"Validation ({item.governance_status.value})", "VALIDATION")
            add_edge(rem_node_id, val_node_id, "REQUIRES")

            # Risk reduction node
            rr_node_id = f"rr_{item.item_id}"
            add_node(rr_node_id, f"+{item.projected_risk_reduction} Score", "RISK_REDUCTION")
            add_edge(val_node_id, rr_node_id, "REDUCES")

        return RemediationGraph(nodes=nodes, edges=edges)
