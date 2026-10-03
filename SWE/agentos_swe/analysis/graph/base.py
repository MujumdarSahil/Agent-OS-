"""
Abstract Base Class for Code Graph Providers.
Establishes a provider-agnostic contract for building and querying code graphs.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from agentos_swe.core.models import CodeNode, CodeRelationship


class CodeGraphProvider(ABC):
    """
    Abstract interface for code graph engine implementations.
    Future adapters (e.g. GraphifyAdapter, Neo4jAdapter) must implement this interface.
    """

    @abstractmethod
    def build(self, repository_path: str) -> Dict[str, Any]:
        """
        Analyze repository and build code graph index.
        Returns graph metadata dictionary (e.g., node_count, edge_count, provider, timestamp).
        """
        pass

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[CodeNode]:
        """Retrieve a specific CodeNode by its ID."""
        pass

    @abstractmethod
    def query(self, query_str: str) -> List[CodeNode]:
        """Search or query nodes matching a symbol, name, or pattern."""
        pass

    @abstractmethod
    def get_dependencies(self, node_id: str) -> List[CodeNode]:
        """Find entities that the given node depends on / imports."""
        pass

    @abstractmethod
    def get_dependents(self, node_id: str) -> List[CodeNode]:
        """Find entities that depend on / import the given node."""
        pass

    @abstractmethod
    def get_callers(self, node_id: str) -> List[CodeNode]:
        """Find entities (functions/methods) that call the given node."""
        pass

    @abstractmethod
    def get_callees(self, node_id: str) -> List[CodeNode]:
        """Find entities (functions/methods) called by the given node."""
        pass

    @abstractmethod
    def get_relationships(self, node_id: Optional[str] = None) -> List[CodeRelationship]:
        """Retrieve relationships associated with a specific node or all relationships."""
        pass
