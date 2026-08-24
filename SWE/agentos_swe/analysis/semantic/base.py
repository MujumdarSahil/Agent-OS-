"""
Base data models and abstract provider interface for M10 Semantic Code Intelligence.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, Optional, List
import ast


class SemanticCategory(str, Enum):
    """Semantic category of a call or expression."""
    DICT_LOOKUP = "DICT_LOOKUP"
    HTTP_NETWORK_CALL = "HTTP_NETWORK_CALL"
    FILE_IO_CALL = "FILE_IO_CALL"
    DATABASE_QUERY = "DATABASE_QUERY"
    UNKNOWN = "UNKNOWN"


class ExceptionIntent(str, Enum):
    """Semantic intent classification of an exception handling block."""
    INTENTIONAL_FALLBACK = "INTENTIONAL_FALLBACK"
    POSSIBLE_ERROR_SWALLOW = "POSSIBLE_ERROR_SWALLOW"
    UNKNOWN = "UNKNOWN"


class ModuleRole(str, Enum):
    """Architectural role classification of a python/polyglot module."""
    ENTRYPOINT_LAUNCHER = "ENTRYPOINT_LAUNCHER"
    LIBRARY_MODULE = "LIBRARY_MODULE"
    TEST_HARNESS = "TEST_HARNESS"


@dataclass
class SemanticCallResult:
    """Detailed semantic resolution result for a function/method call."""
    category: SemanticCategory
    confidence: float
    resolved_symbol: str
    resolved_receiver_type: str = "unknown"
    reason: str = ""
    language: str = "unknown"
    provider: str = "unknown"
    rule: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value if isinstance(self.category, Enum) else self.category
        return data


@dataclass
class ExceptionAnalysisResult:
    """Detailed semantic resolution result for an exception handling block."""
    intent: ExceptionIntent
    confidence: float
    reason: str = ""
    caught_exceptions: List[str] = field(default_factory=list)
    has_fallback_value: bool = False
    language: str = "unknown"
    provider: str = "unknown"
    rule: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["intent"] = self.intent.value if isinstance(self.intent, Enum) else self.intent
        return data


@dataclass
class ModuleRoleResult:
    """Detailed architectural role result for a module."""
    role: ModuleRole
    confidence: float
    reason: str = ""
    language: str = "unknown"
    provider: str = "unknown"
    rule: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["role"] = self.role.value if isinstance(self.role, Enum) else self.role
        return data


class SemanticCodeProvider(ABC):
    """
    Provider-agnostic interface for semantic code intelligence.
    Enables symbol resolution, call categorization, exception intent analysis, and module role classification.
    """

    @abstractmethod
    def resolve_call(
        self,
        file_path: str,
        call_node: ast.Call,
        context_tree: Optional[ast.AST] = None
    ) -> SemanticCallResult:
        """Resolve call node to semantic category and symbol."""
        pass

    @abstractmethod
    def analyze_exception_block(
        self,
        file_path: str,
        handler_node: ast.ExceptHandler,
        context_tree: Optional[ast.AST] = None
    ) -> ExceptionAnalysisResult:
        """Analyze exception handler for intentional fallback vs swallowed bug."""
        pass

    @abstractmethod
    def analyze_module_role(
        self,
        file_path: str,
        context: Optional[Any] = None
    ) -> ModuleRoleResult:
        """Determine whether module acts as entrypoint launcher or library module."""
        pass
