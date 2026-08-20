"""
SecurityAgent - Specialized investigation agent for detecting security vulnerabilities,
hardcoded secrets, injection risks, and unsafe deserialization.
"""

import ast
import re
import os
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
from agentos_swe.semantic import SemanticProviderRegistry

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key|password|auth[_-]?token)\s*=\s*['\"]([^'\"]{8,})['\"]", "Hardcoded Secret / Password"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
]


class SecurityAgent(BaseInvestigatorAgent):
    """
    Agent identifying security flaws, hardcoded credentials, unsafe deserialization, and dangerous subprocesses.
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="SecurityAgent",
            role="Software Security Investigator",
            goal="Identify security vulnerabilities, hardcoded secrets, injection risks, and dangerous operations.",
            backstory="Specialized cybersecurity auditor focused on vulnerability assessment and secure coding.",
            **kwargs,
        )
        self.semantic_registry = SemanticProviderRegistry()

    def investigate(self, context: RepositoryContext) -> List[Finding]:
        findings: List[Finding] = []

        for rel_file in context.source_files:
            snippet = self.read_source_snippet(context, rel_file)
            if not snippet:
                continue

            # 1. Hardcoded Secret Regex Scanning
            secret_findings = self._scan_secrets(rel_file, snippet)
            findings.extend(secret_findings)

            # 2. AST / Semantic Security Analysis for Python
            if rel_file.endswith(".py"):
                ast_findings = self._analyze_ast_security(rel_file, snippet)
                findings.extend(ast_findings)

            # 3. Polyglot Security Analysis (JS/TS/Vue/React)
            ext = os.path.splitext(rel_file)[1].lower()
            if ext in (".js", ".jsx", ".ts", ".tsx", ".vue"):
                poly_sec = self.semantic_registry.analyze_security_patterns(rel_file, snippet)
                for p_item in poly_sec:
                    ev_sec = Evidence(
                        source=EvidenceSource.SEMANTIC_ANALYSIS,
                        kind=EvidenceKind.OBSERVED,
                        description=p_item.get("reason", "Security vulnerability pattern detected."),
                        payload=p_item,
                    )
                    finding = self.create_finding(
                        category="security",
                        severity=p_item.get("severity", "high"),
                        title=p_item.get("title", "Security Vulnerability"),
                        description=f"File '{rel_file}': {p_item.get('reason', '')}",
                        file=rel_file,
                        evidence=[ev_sec],
                        confidence=0.90,
                    )
                    findings.append(finding)

        return findings

    def _scan_secrets(self, rel_file: str, snippet: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = snippet.splitlines()

        for idx, line in enumerate(lines, 1):
            if "test" in rel_file.lower() or "example" in rel_file.lower():
                continue

            for pattern, title in SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    ev_secret = Evidence(
                        source=EvidenceSource.STATIC_ANALYSIS,
                        kind=EvidenceKind.OBSERVED,
                        description=f"Potential secret pattern '{title}' detected on line {idx}.",
                        payload={"file": rel_file, "line": idx, "pattern": title},
                    )
                    finding = self.create_finding(
                        category="security",
                        severity="high",
                        title=title,
                        description=f"Potential hardcoded secret or token ('{title}') detected in '{rel_file}' at line {idx}.",
                        file=rel_file,
                        line_range=(idx, idx),
                        evidence=[ev_secret],
                        confidence=0.85,
                    )
                    findings.append(finding)
        return findings

    def _analyze_ast_security(self, rel_file: str, snippet: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tree = ast.parse(snippet, filename=rel_file)
        except Exception:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                line_no = getattr(node, "lineno", 1)

                # Check 1: eval() / exec()
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    fn_name = node.func.id
                    ev_ast = Evidence(
                        source=EvidenceSource.STATIC_ANALYSIS,
                        kind=EvidenceKind.OBSERVED,
                        description=f"Dangerous function call '{fn_name}' observed on line {line_no}.",
                        payload={"file": rel_file, "line": line_no, "function": fn_name},
                    )
                    finding = self.create_finding(
                        category="security",
                        severity="critical",
                        title=f"Use of Dangerous Function '{fn_name}'",
                        description=f"Dynamic code execution via '{fn_name}' in '{rel_file}' at line {line_no} allows arbitrary code execution risks.",
                        file=rel_file,
                        line_range=(line_no, line_no),
                        evidence=[ev_ast],
                        confidence=0.95,
                    )
                    findings.append(finding)

                # Check 2: subprocess.run/Popen with shell=True
                elif isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "call"):
                    is_shell_true = False
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            is_shell_true = True
                            break
                    if is_shell_true:
                        ev_ast = Evidence(
                            source=EvidenceSource.STATIC_ANALYSIS,
                            kind=EvidenceKind.OBSERVED,
                            description=f"Subprocess call with shell=True on line {line_no}.",
                            payload={"file": rel_file, "line": line_no},
                        )
                        ev_infer = Evidence(
                            source=EvidenceSource.LLM_REASONING,
                            kind=EvidenceKind.INFERRED,
                            description="shell=True with un-sanitized arguments allows command injection vulnerabilities.",
                        )
                        finding = self.create_finding(
                            category="security",
                            severity="high",
                            title="Subprocess Execution with shell=True",
                            description=f"Subprocess execution with shell=True detected in '{rel_file}' at line {line_no}, posing command injection risks.",
                            file=rel_file,
                            line_range=(line_no, line_no),
                            evidence=[ev_ast, ev_infer],
                            confidence=0.9,
                        )
                        findings.append(finding)

                # Check 3: pickle.loads() or yaml.unsafe_load()
                elif isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load", "unsafe_load"):
                    mod_name = ""
                    if isinstance(node.func.value, ast.Name):
                        mod_name = node.func.value.id

                    if mod_name == "pickle" or (mod_name == "yaml" and node.func.attr in ("unsafe_load", "load")):
                        ev_ast = Evidence(
                            source=EvidenceSource.STATIC_ANALYSIS,
                            kind=EvidenceKind.OBSERVED,
                            description=f"Unsafe deserialization call '{mod_name}.{node.func.attr}' on line {line_no}.",
                        )
                        finding = self.create_finding(
                            category="security",
                            severity="high",
                            title=f"Unsafe Deserialization via {mod_name}",
                            description=f"Unsafe deserialization call '{mod_name}.{node.func.attr}' in '{rel_file}' at line {line_no} enables remote code execution vulnerabilities.",
                            file=rel_file,
                            line_range=(line_no, line_no),
                            evidence=[ev_ast],
                            confidence=0.9,
                        )
                        findings.append(finding)

        return findings
