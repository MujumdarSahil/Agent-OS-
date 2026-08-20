"""
M12 Taint Analysis — Provider Interface & Result Model.

Defines the abstract SemanticTaintProvider interface for provider-agnostic
taint analysis, enabling future JS/TS providers alongside the Python implementation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import ast

from agentos_swe.security.taint.models import (
    TaintSource,
    TaintSink,
    TaintFinding,
)


@dataclass
class TaintAnalysisResult:
    """
    Complete result of a taint analysis run on a single file.
    """
    file_path: str
    findings: List[TaintFinding] = field(default_factory=list)
    unsupported: bool = False
    error: Optional[str] = None
    # Diagnostic metadata
    sources_found: int = 0
    sinks_found: int = 0
    sanitizers_found: int = 0
    analysis_depth: int = 0

    @property
    def has_findings(self) -> bool:
        return bool(self.findings) and not self.unsupported

    @property
    def confirmed_findings(self) -> List[TaintFinding]:
        """Non-sanitized findings with confidence ≥ 0.70."""
        return [f for f in self.findings if not f.is_sanitized and f.confidence >= 0.70]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "findings": [f.to_dict() for f in self.findings],
            "unsupported": self.unsupported,
            "error": self.error,
            "sources_found": self.sources_found,
            "sinks_found": self.sinks_found,
            "sanitizers_found": self.sanitizers_found,
            "analysis_depth": self.analysis_depth,
        }


class SemanticTaintProvider(ABC):
    """
    Provider-agnostic interface for taint analysis across languages.

    Python is fully implemented in PythonTaintAnalyzer.
    JavaScript/TypeScript providers can return UNSUPPORTED results via this
    interface without producing false positives.

    Each provider must implement:
      - analyze_sources(): identify untrusted data entry points
      - analyze_sinks(): identify dangerous operation endpoints
      - build_taint_paths(): connect sources to sinks through propagation
    """

    @abstractmethod
    def analyze_sources(
        self,
        file_path: str,
        tree: Any,
        content: str,
    ) -> List[TaintSource]:
        """
        Identify all taint sources (untrusted data entry points) in a file.

        Args:
            file_path: relative or absolute path to the file
            tree: language-specific parsed AST (ast.AST for Python)
            content: raw source code string

        Returns:
            List of TaintSource objects, empty if none found.
        """
        pass

    @abstractmethod
    def analyze_sinks(
        self,
        file_path: str,
        tree: Any,
        content: str,
    ) -> List[TaintSink]:
        """
        Identify all dangerous sinks in a file.

        Returns:
            List of TaintSink objects, empty if none found.
        """
        pass

    @abstractmethod
    def build_taint_paths(
        self,
        file_path: str,
        tree: Any,
        sources: List[TaintSource],
        sinks: List[TaintSink],
    ) -> List[TaintFinding]:
        """
        Connect sources to sinks through propagation and sanitizer analysis.

        Returns:
            List of TaintFinding objects with complete path evidence.
            Sanitized paths are included but marked with is_sanitized=True.
        """
        pass

    def analyze(self, file_path: str, content: str) -> TaintAnalysisResult:
        """
        Full taint analysis pipeline for a file. Default implementation
        orchestrates analyze_sources → analyze_sinks → build_taint_paths.

        Override for language-specific parsing.
        """
        return TaintAnalysisResult(
            file_path=file_path,
            unsupported=True,
            error="Language not supported by this provider.",
        )


class UnsupportedTaintProvider(SemanticTaintProvider):
    """
    Stub provider for languages without taint analysis support.
    Returns UNSUPPORTED rather than producing false positives.
    Used for JS/TS until those providers are implemented.
    """

    def analyze_sources(self, file_path, tree, content):
        return []

    def analyze_sinks(self, file_path, tree, content):
        return []

    def build_taint_paths(self, file_path, tree, sources, sinks):
        return []

    def analyze(self, file_path: str, content: str) -> TaintAnalysisResult:
        return TaintAnalysisResult(
            file_path=file_path,
            unsupported=True,
            error=f"Taint analysis not yet implemented for this file type.",
        )
