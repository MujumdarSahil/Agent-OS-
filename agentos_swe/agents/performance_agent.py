"""
PerformanceAgent - Specialized investigation agent for detecting performance bottlenecks,
N+1 patterns, repeated I/O in hot loops, and inefficient algorithms.
"""

import ast
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.models import (
    Finding,
    Evidence,
    EvidenceSource,
    EvidenceKind,
)
from agentos_swe.context import RepositoryContext

from agentos_swe.semantic import PythonSemanticResolver, SemanticCategory

logger = logging.getLogger(__name__)


class PerformanceAgent(BaseInvestigatorAgent):
    """
    Agent identifying potential performance issues, N+1 patterns, and redundant loop computations.
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="PerformanceAgent",
            role="Software Performance Investigator",
            goal="Identify potential performance bottlenecks, loop I/O patterns, and inefficient operations.",
            backstory="Specialized performance engineer analyzing algorithmic efficiency and resource usage.",
            **kwargs,
        )
        self.semantic_resolver = PythonSemanticResolver()

    def investigate(self, context: RepositoryContext) -> List[Finding]:
        findings: List[Finding] = []

        for rel_file in context.source_files:
            if not rel_file.endswith(".py"):
                continue

            snippet = self.read_source_snippet(context, rel_file)
            if not snippet:
                continue

            ast_findings = self._analyze_ast_performance(rel_file, snippet)
            findings.extend(ast_findings)

        return findings

    def _analyze_ast_performance(self, rel_file: str, snippet: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(snippet, filename=rel_file)
        except Exception:
            return findings

        for node in ast.walk(tree):
            # Check 1: Expensive operations inside loops (For / While)
            if isinstance(node, (ast.For, ast.While)):
                loop_line = getattr(node, "lineno", 1)

                for child in ast.walk(node):
                    if child is node:
                        continue

                    # Check I/O calls inside loop (open, requests.get, db queries)
                    if isinstance(child, ast.Call):
                        line_no = getattr(child, "lineno", loop_line)

                        # M10 Semantic Call Resolution
                        sem_result = self.semantic_resolver.resolve_call(rel_file, child, tree)

                        # EXPLICITLY SKIP DICT LOOKUPS (e.g., job.get("title"))
                        if sem_result.category == SemanticCategory.DICT_LOOKUP:
                            continue

                        # If unresolved or ambiguous '.get', DO NOT flag as network I/O
                        if sem_result.category == SemanticCategory.UNKNOWN:
                            fn_name = ""
                            if isinstance(child.func, ast.Name):
                                fn_name = child.func.id
                            elif isinstance(child.func, ast.Attribute):
                                fn_name = child.func.attr
                            if fn_name == "get":
                                continue

                        # Trigger finding only for confirmed/probable I/O calls
                        if sem_result.category in (
                            SemanticCategory.HTTP_NETWORK_CALL,
                            SemanticCategory.FILE_IO_CALL,
                            SemanticCategory.DATABASE_QUERY,
                        ):
                            fn_symbol = sem_result.resolved_symbol
                            ev_sem = Evidence(
                                source=EvidenceSource.SEMANTIC_ANALYSIS,
                                kind=EvidenceKind.OBSERVED,
                                description=f"Semantic analysis resolved call at line {line_no} to {sem_result.category.value} ({fn_symbol}). {sem_result.reason}",
                                payload=sem_result.to_dict(),
                            )
                            ev_obs = Evidence(
                                source=EvidenceSource.STATIC_ANALYSIS,
                                kind=EvidenceKind.OBSERVED,
                                description=f"Repeated I/O call '{fn_symbol}' observed inside loop at line {line_no}.",
                                payload={"file": rel_file, "loop_line": loop_line, "call_line": line_no},
                            )
                            ev_inf = Evidence(
                                source=EvidenceSource.LLM_REASONING,
                                kind=EvidenceKind.INFERRED,
                                description="Repeated I/O operation inside loop can cause N+1 performance degradation.",
                            )
                            fn_name = ""
                            if isinstance(child.func, ast.Name):
                                fn_name = child.func.id
                            elif isinstance(child.func, ast.Attribute):
                                fn_name = child.func.attr

                            finding = self.create_finding(
                                category="performance",
                                severity="medium",
                                title=f"Potential Performance Issue: Repeated '{fn_name}' Call inside Loop",
                                description=f"Potential performance issue in '{rel_file}' at line {line_no}: Repeated {sem_result.category.value} ('{fn_symbol}') inside loop starting at line {loop_line}.",
                                file=rel_file,
                                line_range=(line_no, line_no),
                                evidence=[ev_obs, ev_sem, ev_inf],
                                confidence=sem_result.confidence,
                            )
                            findings.append(finding)

            # Check 2: Quadratic string concatenation inside loops (s += str)
            elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
                line_no = getattr(node, "lineno", 1)
                # If target is string name and inside loop
                ev_obs = Evidence(
                    source=EvidenceSource.STATIC_ANALYSIS,
                    kind=EvidenceKind.OBSERVED,
                    description=f"In-place addition assignment ('+=') at line {line_no}.",
                )

        return findings
