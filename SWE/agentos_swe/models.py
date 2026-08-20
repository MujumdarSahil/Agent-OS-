"""
Domain models for AgentOS-SWE (M0 Architecture).
Provides minimal, typed domain representations for code entities, relationships,
evidence, and verification findings.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import time
import uuid


class NodeType(str, Enum):
    """Types of code entities represented in the code graph."""
    FILE = "file"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    ENDPOINT = "endpoint"


class RelationType(str, Enum):
    """Relationships between code entities."""
    IMPORTS = "imports"
    CALLS = "calls"
    INHERITS = "inherits"
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"


class FindingStatus(str, Enum):
    """Lifecycle status of a bug/security/performance finding."""
    DISCOVERED = "DISCOVERED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    EVIDENCE_FOUND = "EVIDENCE_FOUND"
    VERIFYING = "VERIFYING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FIXING = "FIXING"
    TESTING = "TESTING"
    REGRESSION_CHECK = "REGRESSION_CHECK"
    APPROVED = "APPROVED"
    FAILED = "FAILED"
    PR_CREATED = "PR_CREATED"


class EvidenceSource(str, Enum):
    """Source origin of evidence supporting a finding."""
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    CODE_GRAPH = "CODE_GRAPH"
    AST = "AST"
    TEST = "TEST"
    RUNTIME = "RUNTIME"
    LLM_REASONING = "LLM_REASONING"
    DOCUMENTATION = "DOCUMENTATION"
    DEPENDENCY_ANALYSIS = "DEPENDENCY_ANALYSIS"
    SEMANTIC_ANALYSIS = "SEMANTIC_ANALYSIS"


class EvidenceKind(str, Enum):
    """Verification state of evidence."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    VERIFIED = "VERIFIED"


@dataclass
class CodeNode:
    """Represents a code entity in the repository graph."""
    id: str
    name: str
    type: NodeType
    path: str
    line_range: Optional[Tuple[int, int]] = None
    symbol: Optional[str] = None
    source: str = "graphify"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["type"] = self.type.value if isinstance(self.type, Enum) else self.type
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CodeNode":
        data = data.copy()
        if "type" in data and isinstance(data["type"], str):
            data["type"] = NodeType(data["type"])
        if "line_range" in data and data["line_range"] is not None:
            data["line_range"] = tuple(data["line_range"])
        return cls(**data)


@dataclass
class CodeRelationship:
    """Represents a directional relationship between two code entities."""
    source_id: str
    target_id: str
    relation_type: RelationType
    source: str = "graphify"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["relation_type"] = (
            self.relation_type.value
            if isinstance(self.relation_type, Enum)
            else self.relation_type
        )
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CodeRelationship":
        data = data.copy()
        if "relation_type" in data and isinstance(data["relation_type"], str):
            data["relation_type"] = RelationType(data["relation_type"])
        return cls(**data)


@dataclass
class Evidence:
    """Represents evidence supporting or refuting a finding hypothesis."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: EvidenceSource = EvidenceSource.CODE_GRAPH
    kind: EvidenceKind = EvidenceKind.OBSERVED
    description: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["source"] = self.source.value if isinstance(self.source, Enum) else self.source
        data["kind"] = self.kind.value if isinstance(self.kind, Enum) else self.kind
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        data = data.copy()
        if "source" in data and isinstance(data["source"], str):
            data["source"] = EvidenceSource(data["source"])
        if "kind" in data and isinstance(data["kind"], str):
            data["kind"] = EvidenceKind(data["kind"])
        return cls(**data)


@dataclass
class Finding:
    """Represents an issue, vulnerability, or defect finding in the repository."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = "general"
    severity: str = "medium"
    title: str = ""
    description: str = ""
    repository: str = ""
    file: Optional[str] = None
    line_range: Optional[Tuple[int, int]] = None
    symbol: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    graph_context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    status: FindingStatus = FindingStatus.DISCOVERED

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        data["evidence"] = [
            e.to_dict() if hasattr(e, "to_dict") else e for e in self.evidence
        ]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        data = data.copy()
        if "status" in data and isinstance(data["status"], str):
            data["status"] = FindingStatus(data["status"])
        if "line_range" in data and data["line_range"] is not None:
            data["line_range"] = tuple(data["line_range"])
        if "evidence" in data and isinstance(data["evidence"], list):
            data["evidence"] = [
                Evidence.from_dict(e) if isinstance(e, dict) else e
                for e in data["evidence"]
            ]
        return cls(**data)
