"""
M12 Security Data-Flow & Taint Analysis Package.

Provides deterministic, provider-agnostic taint analysis tracking:
    SOURCE → PROPAGATION → SINK

Python is fully implemented. JS/TS is reserved for future milestones via the
SemanticTaintProvider interface.
"""

from agentos_swe.security.taint.models import (
    TaintSeverity,
    TaintSourceKind,
    TaintSinkKind,
    TaintSource,
    TaintSink,
    TaintPropagation,
    SanitizerEvidence,
    TaintPath,
    TaintFinding,
)
from agentos_swe.security.taint.analyzer import (
    SemanticTaintProvider,
    TaintAnalysisResult,
)
from agentos_swe.security.taint.python_analyzer import PythonTaintAnalyzer

__all__ = [
    # Models
    "TaintSeverity",
    "TaintSourceKind",
    "TaintSinkKind",
    "TaintSource",
    "TaintSink",
    "TaintPropagation",
    "SanitizerEvidence",
    "TaintPath",
    "TaintFinding",
    # Interface
    "SemanticTaintProvider",
    "TaintAnalysisResult",
    # Implementations
    "PythonTaintAnalyzer",
]
