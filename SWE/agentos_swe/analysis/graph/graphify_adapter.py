"""
GraphifyAdapter - Implementation of CodeGraphProvider wrapping Graphify.
Preserves data provenance (source="graphify") and provides deterministic code graph
query capabilities.
"""

import ast
import os
import logging
import subprocess
import json
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

from agentos_swe.analysis.graph.base import CodeGraphProvider
from agentos_swe.core.models import (
    CodeNode,
    CodeRelationship,
    NodeType,
    RelationType,
)
from agentos_swe.core.exceptions import GraphBuildError, GraphProviderError

logger = logging.getLogger(__name__)


class GraphifyAdapter(CodeGraphProvider):
    """
    Adapter interfacing Graphify code intelligence engine into AgentOS-SWE.
    Maintains clean boundary and enforces source provenance.
    """

    PROVENANCE_SOURCE = "graphify"

    def __init__(self, use_ast_fallback: bool = True):
        self.use_ast_fallback = use_ast_fallback
        self.repository_path: Optional[str] = None
        self._nodes: Dict[str, CodeNode] = {}
        self._relationships: List[CodeRelationship] = []
        self._is_built: bool = False

    def build(self, repository_path: str) -> Dict[str, Any]:
        """
        Build graph for repository path.
        """
        if not repository_path or not os.path.exists(repository_path):
            raise GraphBuildError(f"Repository path does not exist: {repository_path}")

        self.repository_path = os.path.abspath(repository_path)
        self._nodes.clear()
        self._relationships.clear()

        built_via_graphify = self._try_build_graphify(self.repository_path)

        if not built_via_graphify:
            if self.use_ast_fallback:
                logger.info("Graphify CLI/module not present. Using deterministic AST graph fallback.")
                self._build_ast_graph(self.repository_path)
            else:
                raise GraphBuildError("Graphify engine is unavailable and fallback is disabled.")

        self._is_built = True

        metadata = {
            "provider": self.PROVENANCE_SOURCE,
            "repository_path": self.repository_path,
            "node_count": len(self._nodes),
            "edge_count": len(self._relationships),
            "external_graphify_used": built_via_graphify,
        }
        return metadata

    def _try_build_graphify(self, repo_path: str) -> bool:
        """Attempt build using Graphify python module or CLI if available."""
        # 1. Try python module import
        try:
            import graphify  # type: ignore
            if hasattr(graphify, "build_graph"):
                graph_data = graphify.build_graph(repo_path)
                self._load_from_graphify_json(graph_data)
                return True
        except Exception:
            pass

        # 2. Try Graphify CLI invocation
        import shutil
        if shutil.which("graphify"):
            try:
                result = subprocess.run(
                    ["graphify", "dump", repo_path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    self._load_from_graphify_json(data)
                    return True
            except Exception:
                pass

        return False

    def _load_from_graphify_json(self, data: Dict[str, Any]) -> None:
        """Parse raw Graphify JSON export into CodeNodes and CodeRelationships."""
        raw_nodes = data.get("nodes", [])
        raw_edges = data.get("edges", [])

        for n in raw_nodes:
            node_id = n.get("id")
            if not node_id:
                continue
            n_type = n.get("type", "file").lower()
            try:
                node_type = NodeType(n_type)
            except ValueError:
                node_type = NodeType.FILE

            node = CodeNode(
                id=node_id,
                name=n.get("name", node_id),
                type=node_type,
                path=n.get("path", ""),
                line_range=n.get("line_range"),
                symbol=n.get("symbol"),
                source=self.PROVENANCE_SOURCE,
                metadata=n.get("metadata", {}),
            )
            self._nodes[node_id] = node

        for e in raw_edges:
            src = e.get("source")
            tgt = e.get("target")
            if not src or not tgt:
                continue
            rel_str = e.get("relation", "depends_on").lower()
            try:
                rel_type = RelationType(rel_str)
            except ValueError:
                rel_type = RelationType.DEPENDS_ON

            rel = CodeRelationship(
                source_id=src,
                target_id=tgt,
                relation_type=rel_type,
                source=self.PROVENANCE_SOURCE,
                metadata=e.get("metadata", {}),
            )
            self._relationships.append(rel)

    def _build_ast_graph(self, repo_path: str) -> None:
        """
        Deterministic AST fallback graph builder for Python files.
        Builds modules, classes, functions, calls, and imports.
        """
        ignore_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules", "dist", "build"}
        python_files: List[Path] = []

        repo_p = Path(repo_path)
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file in files:
                if file.endswith(".py"):
                    full_path = Path(root) / file
                    python_files.append(full_path)

        # 1. Create file/module nodes
        for p in python_files:
            rel_path = str(p.relative_to(repo_p)).replace("\\", "/")
            module_id = f"file::{rel_path}"
            mod_node = CodeNode(
                id=module_id,
                name=p.stem,
                type=NodeType.MODULE,
                path=rel_path,
                line_range=(1, 1),
                symbol=p.stem,
                source=self.PROVENANCE_SOURCE,
            )
            self._nodes[module_id] = mod_node

            # Parse AST
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=str(p))
                self._extract_ast_nodes_and_edges(module_id, rel_path, tree)
            except Exception as ex:
                logger.debug(f"AST parse skipped for {rel_path}: {ex}")

    def _extract_ast_nodes_and_edges(self, module_id: str, rel_path: str, tree: ast.AST) -> None:
        """Extract classes, functions, imports, and calls from AST."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        target_id = f"file::{alias.name.replace('.', '/')}.py"
                        self._relationships.append(
                            CodeRelationship(
                                source_id=module_id,
                                target_id=target_id,
                                relation_type=RelationType.IMPORTS,
                                source=self.PROVENANCE_SOURCE,
                            )
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        target_id = f"file::{node.module.replace('.', '/')}.py"
                        self._relationships.append(
                            CodeRelationship(
                                source_id=module_id,
                                target_id=target_id,
                                relation_type=RelationType.IMPORTS,
                                source=self.PROVENANCE_SOURCE,
                            )
                        )

            elif isinstance(node, ast.ClassDef):
                class_id = f"class::{rel_path}::{node.name}"
                line_no = getattr(node, "lineno", 1)
                end_line = getattr(node, "end_lineno", line_no)
                cls_node = CodeNode(
                    id=class_id,
                    name=node.name,
                    type=NodeType.CLASS,
                    path=rel_path,
                    line_range=(line_no, end_line),
                    symbol=node.name,
                    source=self.PROVENANCE_SOURCE,
                )
                self._nodes[class_id] = cls_node
                self._relationships.append(
                    CodeRelationship(
                        source_id=module_id,
                        target_id=class_id,
                        relation_type=RelationType.CONTAINS,
                        source=self.PROVENANCE_SOURCE,
                    )
                )

                # Inheritance
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        self._relationships.append(
                            CodeRelationship(
                                source_id=class_id,
                                target_id=f"symbol::{base.id}",
                                relation_type=RelationType.INHERITS,
                                source=self.PROVENANCE_SOURCE,
                            )
                        )

            elif isinstance(node, ast.FunctionDef):
                fn_id = f"function::{rel_path}::{node.name}"
                line_no = getattr(node, "lineno", 1)
                end_line = getattr(node, "end_lineno", line_no)
                fn_node = CodeNode(
                    id=fn_id,
                    name=node.name,
                    type=NodeType.FUNCTION,
                    path=rel_path,
                    line_range=(line_no, end_line),
                    symbol=node.name,
                    source=self.PROVENANCE_SOURCE,
                )
                self._nodes[fn_id] = fn_node
                self._relationships.append(
                    CodeRelationship(
                        source_id=module_id,
                        target_id=fn_id,
                        relation_type=RelationType.CONTAINS,
                        source=self.PROVENANCE_SOURCE,
                    )
                )

                # Extract calls inside function
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        called_name = None
                        if isinstance(child.func, ast.Name):
                            called_name = child.func.id
                        elif isinstance(child.func, ast.Attribute):
                            called_name = child.func.attr

                        if called_name:
                            target_call_id = f"function::{rel_path}::{called_name}"
                            self._relationships.append(
                                CodeRelationship(
                                    source_id=fn_id,
                                    target_id=target_call_id,
                                    relation_type=RelationType.CALLS,
                                    source=self.PROVENANCE_SOURCE,
                                )
                            )

    def _ensure_built(self) -> None:
        if not self._is_built:
            raise GraphProviderError("Graph has not been built yet. Call build() first.")

    def get_node(self, node_id: str) -> Optional[CodeNode]:
        self._ensure_built()
        return self._nodes.get(node_id)

    def query(self, query_str: str) -> List[CodeNode]:
        self._ensure_built()
        q = query_str.lower()
        results: List[CodeNode] = []
        for n in self._nodes.values():
            if (
                q in n.id.lower()
                or q in n.name.lower()
                or q in n.path.lower()
                or (n.symbol and q in n.symbol.lower())
            ):
                results.append(n)
        return results

    def get_dependencies(self, node_id: str) -> List[CodeNode]:
        self._ensure_built()
        targets: Set[str] = set()
        for rel in self._relationships:
            if rel.source_id == node_id and rel.relation_type in (
                RelationType.IMPORTS,
                RelationType.DEPENDS_ON,
            ):
                targets.add(rel.target_id)
        return [self._nodes[tid] for tid in targets if tid in self._nodes]

    def get_dependents(self, node_id: str) -> List[CodeNode]:
        self._ensure_built()
        sources: Set[str] = set()
        for rel in self._relationships:
            if rel.target_id == node_id and rel.relation_type in (
                RelationType.IMPORTS,
                RelationType.DEPENDS_ON,
            ):
                sources.add(rel.source_id)
        return [self._nodes[sid] for sid in sources if sid in self._nodes]

    def get_callers(self, node_id: str) -> List[CodeNode]:
        self._ensure_built()
        callers: Set[str] = set()
        for rel in self._relationships:
            if rel.target_id == node_id and rel.relation_type == RelationType.CALLS:
                callers.add(rel.source_id)
        return [self._nodes[sid] for sid in callers if sid in self._nodes]

    def get_callees(self, node_id: str) -> List[CodeNode]:
        self._ensure_built()
        callees: Set[str] = set()
        for rel in self._relationships:
            if rel.source_id == node_id and rel.relation_type == RelationType.CALLS:
                callees.add(rel.target_id)
        return [self._nodes[tid] for tid in callees if tid in self._nodes]

    def get_relationships(self, node_id: Optional[str] = None) -> List[CodeRelationship]:
        self._ensure_built()
        if node_id is None:
            return list(self._relationships)
        return [
            rel for rel in self._relationships
            if rel.source_id == node_id or rel.target_id == node_id
        ]
