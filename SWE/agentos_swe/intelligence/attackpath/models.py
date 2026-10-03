"""
Domain models for M16 Autonomous Attack-Path Reasoning & Security Investigation.
Defines EntrypointType, TrustBoundary, AuthStatus, PathClassification, AttackStep,
AttackPath, AttackGraphNode, AttackGraphEdge, AttackGraph, and SecurityInvestigation.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


class EntrypointType(str, Enum):
    """Types of system entrypoints."""
    INTERNET = "INTERNET"
    AUTHENTICATED_HTTP = "AUTHENTICATED_HTTP"
    USER_CLI = "USER_CLI"
    INTERNAL_API = "INTERNAL_API"
    SCHEDULED = "SCHEDULED"
    UNKNOWN = "UNKNOWN"


class TrustBoundary(str, Enum):
    """Trust boundaries crossed along an attack path."""
    INTERNET = "INTERNET"
    USER = "USER"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    APPLICATION = "APPLICATION"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    DATABASE = "DATABASE"
    FILESYSTEM = "FILESYSTEM"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    EXTERNAL_API = "EXTERNAL_API"
    LLM = "LLM"
    UNKNOWN = "UNKNOWN"


class AuthStatus(str, Enum):
    """Authentication and authorization status of the attack path entrypoint."""
    AUTHENTICATED = "AUTHENTICATED"
    AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNKNOWN = "UNKNOWN"


class PathClassification(str, Enum):
    """Exploitability classification of the complete attack path."""
    EXPLOITABLE = "EXPLOITABLE"
    PARTIALLY_MITIGATED = "PARTIALLY_MITIGATED"
    BLOCKED = "BLOCKED"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class AttackStep:
    """Individual propagation or transformation step along an attack path."""
    step_index: int
    file: str
    line: int
    function_name: Optional[str] = None
    operation: str = ""
    step_type: str = "PROPAGATION"  # SOURCE, CALL, ASSIGNMENT, PROPAGATION, SANITY_CHECK, TRUST_CROSSING, SINK
    trust_boundary: Optional[TrustBoundary] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.trust_boundary and isinstance(self.trust_boundary, Enum):
            d["trust_boundary"] = self.trust_boundary.value
        return d


@dataclass
class AttackPath:
    """Complete end-to-end attack path representation."""
    id: str
    fingerprint: str
    repository: str
    entrypoint: str
    entrypoint_type: EntrypointType
    source: str
    source_type: str
    source_file: str
    source_line: int
    propagation_steps: List[AttackStep] = field(default_factory=list)
    trust_boundaries_crossed: List[TrustBoundary] = field(default_factory=list)
    auth_status: AuthStatus = AuthStatus.UNKNOWN
    sanitizer_steps: List[str] = field(default_factory=list)
    sink: str = ""
    sink_type: str = ""
    sink_file: str = ""
    sink_line: int = 0
    root_cause: str = "UNKNOWN"
    classification: PathClassification = PathClassification.UNKNOWN
    risk_score: int = 0  # 0 - 100
    severity: str = "MEDIUM"
    confidence: float = 0.85
    evidence: Dict[str, Any] = field(default_factory=dict)
    repair_strategy: Optional[str] = None
    validation_status: str = "UNTESTED"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["entrypoint_type"] = self.entrypoint_type.value if isinstance(self.entrypoint_type, Enum) else self.entrypoint_type
        d["trust_boundaries_crossed"] = [tb.value if isinstance(tb, Enum) else tb for tb in self.trust_boundaries_crossed]
        d["auth_status"] = self.auth_status.value if isinstance(self.auth_status, Enum) else self.auth_status
        d["classification"] = self.classification.value if isinstance(self.classification, Enum) else self.classification
        d["propagation_steps"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.propagation_steps]
        return d


@dataclass
class AttackGraphNode:
    """Node in an attack graph."""
    node_id: str
    label: str
    node_type: str  # ENTRYPOINT, SOURCE, FUNCTION, VARIABLE, SANITIZER, TRUST_BOUNDARY, SINK, VULNERABILITY
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackGraphEdge:
    """Directed edge in an attack graph."""
    source_id: str
    target_id: str
    edge_type: str  # ENTERS, PROPAGATES, CALLS, SANITIZES, CROSSES, REACHES, EXPLOITS
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackGraph:
    """Attack Graph representation for visual rendering and reasoning."""
    nodes: List[AttackGraphNode] = field(default_factory=list)
    edges: List[AttackGraphEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_dot(self) -> str:
        """Generates Graphviz DOT string for UI visualization."""
        dot_lines = ["digraph AttackGraph {", '  rankdir="LR";', '  node [fontname="Helvetica", shape="rect", style="filled"];']
        
        type_colors = {
            "ENTRYPOINT": "#e0f2fe",
            "SOURCE": "#bae6fd",
            "TRUST_BOUNDARY": "#fef3c7",
            "FUNCTION": "#f1f5f9",
            "SANITIZER": "#dcfce7",
            "SINK": "#fee2e2",
            "VULNERABILITY": "#fca5a5",
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
class SecurityInvestigation:
    """Complete autonomous security investigation output for a target finding/path."""
    investigation_id: str
    target_finding_id: str
    attack_path: AttackPath
    why_dangerous_narrative: str
    how_to_break_narrative: str
    risk_score: int
    exploitability: str
    exposure: str
    blast_radius: str
    historical_status: str
    root_cause: str
    recommendation: str
    repair_strategy: Optional[str] = None
    validation_status: str = "UNTESTED"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["attack_path"] = self.attack_path.to_dict()
        return d
