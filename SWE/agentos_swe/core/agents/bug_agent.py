"""
BugAgent - Specialized investigation agent for detecting software logic, correctness,
exception handling, and boundary condition defects.
"""

import ast
import os
import logging
from typing import List, Dict, Any, Optional

from agentos_swe.core.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.core.models import (
    Finding,
    Evidence,
    EvidenceSource,
    EvidenceKind,
)
from agentos_swe.core.context import RepositoryContext

from agentos_swe.analysis.semantic import SemanticProviderRegistry, PythonSemanticResolver, ExceptionIntent

logger = logging.getLogger(__name__)


class BugAgent(BaseInvestigatorAgent):
    """
    Agent identifying correctness, exception handling, and logical boundary flaws.
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="BugAgent",
            role="Software Bug & Logic Investigator",
            goal="Identify logic errors, unhandled exceptions, unreachable code, and boundary defects.",
            backstory="Specialized code auditor analyzing correctness, edge cases, and exception safety.",
            **kwargs,
        )
        self.semantic_registry = SemanticProviderRegistry()
        self.semantic_resolver = self.semantic_registry

    def investigate(self, context: RepositoryContext) -> List[Finding]:
        findings: List[Finding] = []

        for rel_file in context.source_files:
            if not rel_file.endswith(".py"):
                continue

            snippet = self.read_source_snippet(context, rel_file)
            if not snippet:
                continue

            # 1. Deterministic AST Analysis
            ast_findings = self._analyze_ast(context, rel_file, snippet)
            findings.extend(ast_findings)

            # 2. Graph Context Check
            graph_nodes = context.query_graph(os.path.basename(rel_file))
            if graph_nodes:
                file_node = graph_nodes[0]
                callers = context.get_callers(file_node.id)
                if not callers and "test" not in rel_file.lower() and "main" not in rel_file.lower():
                    # Unused / uncalled module function check
                    pass

        return findings

    def _analyze_ast(
        self, context: RepositoryContext, rel_file: str, snippet: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(snippet, filename=rel_file)
        except Exception as ex:
            logger.warning(f"[BugAgent] AST parse failed for '{rel_file}': {ex}")
            return findings

        for node in ast.walk(tree):
            # Check 1: Bare except or swallowed exception (except Exception: pass)
            if isinstance(node, ast.ExceptHandler):
                line_no = getattr(node, "lineno", 1)

                # M10 Semantic Exception Analysis
                exc_res = self.semantic_resolver.analyze_exception_block(rel_file, node, tree)

                # EXPLICITLY SKIP INTENTIONAL FALLBACKS (e.g. ImportError, parser fallback, DB init fallback)
                if exc_res.intent == ExceptionIntent.INTENTIONAL_FALLBACK:
                    continue

                if exc_res.intent in (ExceptionIntent.POSSIBLE_ERROR_SWALLOW, ExceptionIntent.UNKNOWN):
                    ev_sem = Evidence(
                        source=EvidenceSource.SEMANTIC_ANALYSIS,
                        kind=EvidenceKind.OBSERVED,
                        description=f"Semantic exception analysis: {exc_res.intent.value}. {exc_res.reason}",
                        payload=exc_res.to_dict(),
                    )
                    ev_ast = Evidence(
                        source=EvidenceSource.STATIC_ANALYSIS,
                        kind=EvidenceKind.OBSERVED,
                        description=f"Except handler at line {line_no} swallows exception without fallback.",
                        payload={"file": rel_file, "line": line_no},
                    )
                    finding = self.create_finding(
                        category="bug",
                        severity="medium" if exc_res.intent == ExceptionIntent.POSSIBLE_ERROR_SWALLOW else "low",
                        title="Swallowed or Bare Exception Handler",
                        description=f"File '{rel_file}' line {line_no} contains an exception handler that swallows errors without explicit fallback or logging.",
                        file=rel_file,
                        line_range=(line_no, line_no),
                        evidence=[ev_ast, ev_sem],
                        confidence=exc_res.confidence,
                    )
                    findings.append(finding)

            # Check 2: Mutable default arguments (def f(x=[]))
            elif isinstance(node, ast.FunctionDef):
                fn_name = node.name
                line_no = getattr(node, "lineno", 1)
                for default in node.args.defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        ev_ast = Evidence(
                            source=EvidenceSource.STATIC_ANALYSIS,
                            kind=EvidenceKind.OBSERVED,
                            description=f"Function '{fn_name}' uses mutable default argument of type {type(default).__name__}.",
                            payload={"file": rel_file, "function": fn_name, "line": line_no},
                        )
                        finding = self.create_finding(
                            category="bug",
                            severity="high",
                            title=f"Mutable Default Argument in '{fn_name}'",
                            description=f"Function '{fn_name}' in '{rel_file}' line {line_no} uses a mutable default argument ({type(default).__name__}), causing shared state across invocations.",
                            file=rel_file,
                            line_range=(line_no, line_no),
                            symbol=fn_name,
                            evidence=[ev_ast],
                            confidence=0.95,
                        )
                        findings.append(finding)

            # Check 3: Unreachable code after return/raise
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for idx, stmt in enumerate(node.body[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        next_stmt = node.body[idx + 1]
                        line_no = getattr(next_stmt, "lineno", getattr(stmt, "lineno", 1))
                        ev_ast = Evidence(
                            source=EvidenceSource.STATIC_ANALYSIS,
                            kind=EvidenceKind.OBSERVED,
                            description=f"Statement at line {line_no} is unreachable after {type(stmt).__name__}.",
                            payload={"file": rel_file, "line": line_no},
                        )
                        finding = self.create_finding(
                            category="bug",
                            severity="low",
                            title="Unreachable Code Detected",
                            description=f"Unreachable statement found in '{rel_file}' at line {line_no} following a {type(stmt).__name__} statement.",
                            file=rel_file,
                            line_range=(line_no, line_no),
                            symbol=node.name,
                            evidence=[ev_ast],
                            confidence=0.85,
                        )
                        findings.append(finding)
                        break

        return findings
