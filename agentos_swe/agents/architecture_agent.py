"""
ArchitectureAgent - Specialized investigation agent leveraging CodeGraphProvider
to identify structural coupling, circular dependencies, high fan-in/fan-out, and architectural flaws.
"""

import os
import logging
from typing import List, Dict, Any, Optional, Set

from agentos_swe.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.models import (
    Finding,
    Evidence,
    EvidenceSource,
    EvidenceKind,
)
from agentos_swe.context import RepositoryContext

from agentos_swe.semantic import PythonSemanticResolver, ModuleRole

logger = logging.getLogger(__name__)


class ArchitectureAgent(BaseInvestigatorAgent):
    """
    Agent analyzing code graph structure, dependency relationships, coupling, and circular dependencies.
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="ArchitectureAgent",
            role="Software Architecture Investigator",
            goal="Identify structural coupling, circular dependencies, modularity violations, and high fan-out bottlenecks.",
            backstory="Specialized software architect using graph intelligence to evaluate system modularity and cohesion.",
            **kwargs,
        )
        self.semantic_resolver = PythonSemanticResolver()

    def investigate(self, context: RepositoryContext) -> List[Finding]:
        findings: List[Finding] = []

        if not context.graph_metadata:
            return findings

        # 1. Graph Analysis for High Fan-Out / High Coupling
        for rel_file in context.source_files:
            file_node_id = f"file::{rel_file}"
            deps = context.get_dependencies(file_node_id)
            dependents = context.get_dependents(file_node_id)

            # Check High Fan-Out (High Coupling)
            if len(deps) >= 10:
                # M10 Semantic Module Role Analysis
                role_res = self.semantic_resolver.analyze_module_role(rel_file, context)

                # EXPLICITLY SKIP ENTRYPOINT LAUNCHERS (main.py, server.py, streamlit_app.py, CLI scripts)
                if role_res.role == ModuleRole.ENTRYPOINT_LAUNCHER:
                    continue

                ev_sem = Evidence(
                    source=EvidenceSource.SEMANTIC_ANALYSIS,
                    kind=EvidenceKind.OBSERVED,
                    description=f"Module role resolved to {role_res.role.value}: {role_res.reason}",
                    payload=role_res.to_dict(),
                )
                ev_graph = Evidence(
                    source=EvidenceSource.CODE_GRAPH,
                    kind=EvidenceKind.OBSERVED,
                    description=f"Library module '{rel_file}' depends on {len(deps)} other modules (high fan-out).",
                    payload={"file": rel_file, "dependencies_count": len(deps)},
                )
                finding = self.create_finding(
                    category="architecture",
                    severity="medium",
                    title=f"High Coupling / Fan-Out in '{rel_file}'",
                    description=f"Library module '{rel_file}' imports/depends on {len(deps)} external modules, indicating high architectural coupling and low modular cohesion.",
                    file=rel_file,
                    evidence=[ev_graph, ev_sem],
                    graph_context={"dependency_count": len(deps), "dependencies": [d.id for d in deps]},
                    confidence=role_res.confidence,
                )
                findings.append(finding)

        # 2. Circular Dependency Detection in Code Graph
        cycles = self._detect_circular_dependencies(context)
        for cycle in cycles:
            cycle_str = " -> ".join(cycle)
            ev_graph = Evidence(
                source=EvidenceSource.CODE_GRAPH,
                kind=EvidenceKind.OBSERVED,
                description=f"Circular dependency cycle detected: {cycle_str}.",
                payload={"cycle": cycle},
            )
            finding = self.create_finding(
                category="architecture",
                severity="high",
                title="Circular Module Dependency Detected",
                description=f"Circular dependency cycle identified in repository code graph: {cycle_str}.",
                file=cycle[0] if cycle else None,
                evidence=[ev_graph],
                graph_context={"cycle": cycle},
                confidence=0.95,
            )
            findings.append(finding)

        return findings

    def _detect_circular_dependencies(self, context: RepositoryContext) -> List[List[str]]:
        """Find circular import dependencies among module nodes."""
        cycles: List[List[str]] = []
        visited: Set[str] = set()
        stack: List[str] = []

        def dfs(node_id: str):
            visited.add(node_id)
            stack.append(node_id)

            for dep in context.get_dependencies(node_id):
                target_id = dep.id
                if target_id in stack:
                    # Cycle found
                    idx = stack.index(target_id)
                    cycle_nodes = stack[idx:] + [target_id]
                    clean_cycle = [n.replace("file::", "") for n in cycle_nodes]
                    if clean_cycle not in cycles:
                        cycles.append(clean_cycle)
                elif target_id not in visited:
                    dfs(target_id)

            stack.pop()

        for rel_file in context.source_files:
            file_node_id = f"file::{rel_file}"
            if file_node_id not in visited:
                dfs(file_node_id)

        return cycles[:5]  # Cap at top 5 unique cycles
