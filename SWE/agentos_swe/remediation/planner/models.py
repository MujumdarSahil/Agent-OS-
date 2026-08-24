"""
Domain models for M17 Intelligent Security Remediation Orchestration & Fix Planning.

Defines RemediationStatus, EffortCategory, RemediationItem, RemediationGraphNode,
RemediationGraphEdge, RemediationGraph, and RemediationPlan.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime


class RemediationStatus(str, Enum):
    """Governance and execution status of a remediation item or plan."""
    PLAN_ONLY = "PLAN_ONLY"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    BLOCKED = "BLOCKED"
    CONFLICT = "CONFLICT"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    APPROVED = "APPROVED"


class EffortCategory(str, Enum):
    """Categorized engineering effort estimation."""
    TRIVIAL = "TRIVIAL"     # Single line / trivial fix
    SMALL = "SMALL"         # Local function fix
    MEDIUM = "MEDIUM"        # Single file / module fix
    LARGE = "LARGE"         # Multi-file / cross-module fix
    COMPLEX = "COMPLEX"     # Public API change / architectural refactor


@dataclass
class RemediationItem:
    """Individual actionable remediation item, potentially grouping multiple findings."""
    item_id: str
    title: str
    root_cause: str
    affected_finding_ids: List[str] = field(default_factory=list)
    affected_attack_path_ids: List[str] = field(default_factory=list)
    affected_files: List[str] = field(default_factory=list)
    affected_symbols: List[str] = field(default_factory=list)
    earliest_break_point: str = ""
    recommended_fix: str = ""
    repair_strategy: str = "DEFENSIVE_SANITIZATION"
    priority_score: int = 50
    priority_tier: str = "P2"
    effort: EffortCategory = EffortCategory.MEDIUM
    current_risk_score: int = 50
    projected_risk_reduction: int = 20
    projected_post_score: int = 70
    dependencies: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    validation_requirements: List[str] = field(default_factory=list)
    governance_status: RemediationStatus = RemediationStatus.READY_FOR_REVIEW
    evidence_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["effort"] = self.effort.value if isinstance(self.effort, Enum) else self.effort
        d["governance_status"] = self.governance_status.value if isinstance(self.governance_status, Enum) else self.governance_status
        return d


@dataclass
class RemediationGraphNode:
    """Node in a remediation graph."""
    node_id: str
    label: str
    node_type: str  # FINDING, ROOT_CAUSE, ATTACK_PATH, REMEDIATION, VALIDATION, RISK_REDUCTION
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationGraphEdge:
    """Directed edge in a remediation graph."""
    source_id: str
    target_id: str
    edge_type: str  # GROUPS, BREAKS, REMEDIATES, REQUIRES, REDUCES
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationGraph:
    """Graph representation connecting findings, attack paths, remediations, and risk reductions."""
    nodes: List[RemediationGraphNode] = field(default_factory=list)
    edges: List[RemediationGraphEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_dot(self) -> str:
        """Generates Graphviz DOT string for UI visualization."""
        dot_lines = [
            'digraph RemediationGraph {',
            '  rankdir="LR";',
            '  node [fontname="Helvetica", shape="rect", style="filled"];',
        ]
        
        type_colors = {
            "FINDING": "#fee2e2",
            "ROOT_CAUSE": "#fef3c7",
            "ATTACK_PATH": "#fca5a5",
            "REMEDIATION": "#dcfce7",
            "VALIDATION": "#bae6fd",
            "RISK_REDUCTION": "#e0f2fe",
        }

        for node in self.nodes:
            color = type_colors.get(node.node_type, "#ffffff")
            label_clean = node.label.replace('"', '\\"')
            dot_lines.append(f'  "{node.node_id}" [label="{label_clean}", fillcolor="{color}"];')

        for edge in self.edges:
            lbl = f' [label="{edge.edge_type}"]' if edge.edge_type else ""
            dot_lines.append(f'  "{edge.source_id}" -> "{edge.target_id}"{lbl};')

        dot_lines.append("}")
        return "\n".join(dot_lines)


@dataclass
class RemediationPlan:
    """Complete structured security remediation plan."""
    plan_id: str
    repository: str
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    findings_count: int = 0
    remediation_items: List[RemediationItem] = field(default_factory=list)
    execution_order: List[str] = field(default_factory=list)
    dependency_relationships: Dict[str, List[str]] = field(default_factory=dict)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    total_estimated_effort: EffortCategory = EffortCategory.MEDIUM
    current_security_score: int = 100
    projected_security_score: int = 100
    total_risk_reduction: int = 0
    affected_files: List[str] = field(default_factory=list)
    affected_symbols: List[str] = field(default_factory=list)
    validation_requirements: List[str] = field(default_factory=list)
    governance_status: str = "ALLOW"
    final_recommendation: str = "PLAN_ONLY"
    graph: Optional[RemediationGraph] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["total_estimated_effort"] = self.total_estimated_effort.value if isinstance(self.total_estimated_effort, Enum) else self.total_estimated_effort
        d["remediation_items"] = [item.to_dict() if hasattr(item, "to_dict") else item for item in self.remediation_items]
        if self.graph:
            d["graph"] = self.graph.to_dict()
        return d
