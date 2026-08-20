"""
M12 Taint Analysis — Strongly Typed Domain Models.

Defines the complete data model for taint sources, sinks, propagation steps,
sanitizer evidence, taint paths, and taint findings.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TaintSeverity(str, Enum):
    """Severity classification for a taint finding."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    UNKNOWN  = "UNKNOWN"


class TaintSourceKind(str, Enum):
    """Category of an untrusted data source."""
    HTTP_REQUEST          = "HTTP_REQUEST"
    QUERY_PARAMETER       = "QUERY_PARAMETER"
    FORM_INPUT            = "FORM_INPUT"
    JSON_INPUT            = "JSON_INPUT"
    ENVIRONMENT_VARIABLE  = "ENVIRONMENT_VARIABLE"
    FILE_INPUT            = "FILE_INPUT"
    USER_INPUT            = "USER_INPUT"
    LLM_OUTPUT            = "LLM_OUTPUT"
    DATABASE_RESULT       = "DATABASE_RESULT"
    CLI_ARGUMENT          = "CLI_ARGUMENT"
    UNKNOWN_EXTERNAL_INPUT = "UNKNOWN_EXTERNAL_INPUT"


class TaintSinkKind(str, Enum):
    """Category of a dangerous data sink."""
    COMMAND_EXECUTION     = "COMMAND_EXECUTION"
    SHELL_EXECUTION       = "SHELL_EXECUTION"
    EVAL_EXECUTION        = "EVAL_EXECUTION"
    FILE_WRITE            = "FILE_WRITE"
    FILE_PATH_OPERATION   = "FILE_PATH_OPERATION"
    SQL_QUERY             = "SQL_QUERY"
    HTML_OUTPUT           = "HTML_OUTPUT"
    HTTP_REQUEST          = "HTTP_REQUEST"
    DESERIALIZATION       = "DESERIALIZATION"
    TEMPLATE_RENDERING    = "TEMPLATE_RENDERING"
    DYNAMIC_CODE_EXECUTION = "DYNAMIC_CODE_EXECUTION"


# ---------------------------------------------------------------------------
# Data model classes
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    """Represents a location in source code where untrusted data enters."""
    var_name: str
    source_kind: TaintSourceKind
    line_no: int
    code_snippet: str
    file: str
    confidence: float = 0.9
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_kind"] = self.source_kind.value
        return d

    def label(self) -> str:
        return f"{self.code_snippet.strip()} [{self.source_kind.value} @ line {self.line_no}]"


@dataclass
class TaintSink:
    """Represents a location in source code where tainted data reaches a dangerous operation."""
    var_name: str
    sink_kind: TaintSinkKind
    line_no: int
    code_snippet: str
    file: str
    is_shell_true: bool = False
    confidence: float = 0.9
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["sink_kind"] = self.sink_kind.value
        return d

    def label(self) -> str:
        return f"{self.code_snippet.strip()} [{self.sink_kind.value} @ line {self.line_no}]"


@dataclass
class TaintPropagation:
    """Represents a single step in the propagation chain from source to sink."""
    from_var: str
    to_var: str
    line_no: int
    operation: str          # e.g. "assignment", "argument", "concat", "fstring"
    code_snippet: str
    file: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def label(self) -> str:
        return f"{self.from_var} → {self.to_var} ({self.operation} @ line {self.line_no})"


@dataclass
class SanitizerEvidence:
    """Evidence that a sanitizer was applied to tainted data along the path."""
    var_name: str
    sanitizer_name: str
    line_no: int
    code_snippet: str
    file: str
    confidence: float = 0.95
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def label(self) -> str:
        return f"{self.sanitizer_name}({self.var_name}) @ line {self.line_no}"


@dataclass
class TaintPath:
    """Complete data-flow chain from a taint source through propagation to a dangerous sink."""
    source: TaintSource
    sink: TaintSink
    propagation_steps: List[TaintPropagation] = field(default_factory=list)
    sanitizers: List[SanitizerEvidence] = field(default_factory=list)
    file: str = ""

    @property
    def is_sanitized(self) -> bool:
        """True when at least one sanitizer with confidence ≥ 0.90 covers the tainted variable."""
        tainted_vars = {self.source.var_name}
        for step in self.propagation_steps:
            if step.from_var in tainted_vars:
                tainted_vars.add(step.to_var)

        for san in self.sanitizers:
            if san.var_name in tainted_vars and san.confidence >= 0.90:
                return True
        return False

    def chain_description(self) -> str:
        """Human-readable propagation chain."""
        parts = [self.source.code_snippet.strip()]
        for step in self.propagation_steps:
            parts.append(step.to_var)
        parts.append(self.sink.code_snippet.strip())
        return "\n→ ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "propagation_steps": [s.to_dict() for s in self.propagation_steps],
            "sanitizers": [s.to_dict() for s in self.sanitizers],
            "file": self.file,
            "is_sanitized": self.is_sanitized,
        }


@dataclass
class TaintFinding:
    """
    A complete taint analysis finding with severity, confidence, and full path evidence.
    Wraps a TaintPath with analysis metadata.
    """
    path: TaintPath
    severity: TaintSeverity
    confidence: float
    title: str
    explanation: str
    evidence_sources: List[str] = field(default_factory=list)
    is_sanitized: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path.to_dict(),
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "explanation": self.explanation,
            "evidence_sources": self.evidence_sources,
            "is_sanitized": self.is_sanitized,
        }

    def source_label(self) -> str:
        return self.path.source.label()

    def sink_label(self) -> str:
        return self.path.sink.label()

    def chain_description(self) -> str:
        return self.path.chain_description()
