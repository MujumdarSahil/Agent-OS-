"""
RepositoryContext - Machine-readable context representation of a repository for AgentOS-SWE agents.
Combines repository intake metadata with code graph query capabilities.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import os

from agentos_swe.core.models import CodeNode, CodeRelationship
from agentos_swe.analysis.graph.base import CodeGraphProvider
from agentos_swe.analysis.graph.graphify_adapter import GraphifyAdapter
from agentos_swe.core.intake import RepositoryIntake
from agentos_swe.core.exceptions import RepositoryContextError


@dataclass
class RepositoryContext:
    """
    Lightweight, queryable context object passed to investigation & verification agents.
    Does not duplicate raw source code blobs in memory.
    """
    name: str
    repository_path: str
    is_git_repo: bool = False
    commit_ref: Optional[str] = None
    languages: List[str] = field(default_factory=list)
    source_files_count: int = 0
    source_files: List[str] = field(default_factory=list)
    test_directories: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)
    graph_metadata: Dict[str, Any] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    graph_provider: Optional[CodeGraphProvider] = field(default=None, repr=False)

    def get_node(self, node_id: str) -> Optional[CodeNode]:
        """Proxy get_node query to graph provider."""
        self._ensure_provider()
        return self.graph_provider.get_node(node_id)  # type: ignore

    def query_graph(self, query_str: str) -> List[CodeNode]:
        """Proxy query to graph provider."""
        self._ensure_provider()
        return self.graph_provider.query(query_str)  # type: ignore

    def get_dependencies(self, node_id: str) -> List[CodeNode]:
        """Proxy get_dependencies to graph provider."""
        self._ensure_provider()
        return self.graph_provider.get_dependencies(node_id)  # type: ignore

    def get_dependents(self, node_id: str) -> List[CodeNode]:
        """Proxy get_dependents to graph provider."""
        self._ensure_provider()
        return self.graph_provider.get_dependents(node_id)  # type: ignore

    def get_callers(self, node_id: str) -> List[CodeNode]:
        """Proxy get_callers to graph provider."""
        self._ensure_provider()
        return self.graph_provider.get_callers(node_id)  # type: ignore

    def get_callees(self, node_id: str) -> List[CodeNode]:
        """Proxy get_callees to graph provider."""
        self._ensure_provider()
        return self.graph_provider.get_callees(node_id)  # type: ignore

    def _ensure_provider(self) -> None:
        if self.graph_provider is None:
            raise RepositoryContextError("Graph provider is not initialized on this RepositoryContext.")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metadata (excluding un-serializable provider instance)."""
        return {
            "name": self.name,
            "repository_path": self.repository_path,
            "is_git_repo": self.is_git_repo,
            "commit_ref": self.commit_ref,
            "languages": self.languages,
            "source_files_count": self.source_files_count,
            "source_files": self.source_files,
            "test_directories": self.test_directories,
            "test_files": self.test_files,
            "graph_metadata": self.graph_metadata,
            "analysis_metadata": self.analysis_metadata,
        }


def build_repository_context(
    repository_path: str,
    graph_provider: Optional[CodeGraphProvider] = None,
    intake_component: Optional[RepositoryIntake] = None,
) -> RepositoryContext:
    """
    Factory function executing M1 Intake & Graph Generation pipeline:
    Repository Intake -> Graphify Adapter -> Code Graph -> RepositoryContext
    """
    if intake_component is None:
        intake_component = RepositoryIntake()

    repo_info = intake_component.analyze(repository_path)

    if graph_provider is None:
        graph_provider = GraphifyAdapter()

    graph_meta = graph_provider.build(repo_info["root_path"])

    context = RepositoryContext(
        name=repo_info["name"],
        repository_path=repo_info["root_path"],
        is_git_repo=repo_info["is_git_repo"],
        commit_ref=repo_info["commit_ref"],
        languages=repo_info["languages"],
        source_files_count=repo_info["source_files_count"],
        source_files=repo_info["source_files"],
        test_directories=repo_info["test_directories"],
        test_files=repo_info["test_files"],
        graph_metadata=graph_meta,
        analysis_metadata={"intake_status": "success"},
        graph_provider=graph_provider,
    )
    return context
