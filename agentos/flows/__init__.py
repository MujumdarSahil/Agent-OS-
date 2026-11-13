"""AgentOS Flow Engine package.

Provides graph-based multi-agent execution with Information Flow Control (IFC)
security labels, declarative static analysis, and tool mediation.
"""

from agentos.flows.labels import (
    Confidentiality,
    Integrity,
    Label,
    Labeled,
)
from agentos.flows.models import (
    CyclicFlowError,
    EdgeDefinition,
    FlowDefinition,
    InvalidFlowConfigError,
    NodeDefinition,
)
from agentos.flows.specs import (
    BUILTIN_NODE_SPECS,
    NodeSpec,
    SideEffectClass,
    SinkArgumentRule,
)
from agentos.flows.static_analyzer import (
    PublishVerificationResult,
    StaticFlowAnalyzer,
    Violation,
)

__all__ = [
    "BUILTIN_NODE_SPECS",
    "Confidentiality",
    "CyclicFlowError",
    "EdgeDefinition",
    "FlowDefinition",
    "Integrity",
    "InvalidFlowConfigError",
    "Label",
    "Labeled",
    "NodeDefinition",
    "NodeSpec",
    "PublishVerificationResult",
    "SideEffectClass",
    "SinkArgumentRule",
    "StaticFlowAnalyzer",
    "Violation",
]
