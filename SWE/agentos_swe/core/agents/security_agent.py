"""
SecurityAgent - Specialized investigation agent for detecting security vulnerabilities,
hardcoded secrets, injection risks, and unsafe deserialization.

M12: Enhanced with deterministic data-flow / taint analysis via PythonTaintAnalyzer.
Existing static rules remain intact; M12 adds taint findings on top.
"""

import ast
import re
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
from agentos_swe.analysis.semantic import SemanticProviderRegistry

# M12: Taint analysis
try:
    from agentos_swe.security.taint.python_analyzer import PythonTaintAnalyzer
    from agentos_swe.security.taint.models import TaintSeverity, TaintFinding
    _TAINT_AVAILABLE = True
except ImportError:
    _TAINT_AVAILABLE = False

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key|password|auth[_-]?token)\s*=\s*['\"]([^'\"]{8,})['\"]", "Hardcoded Secret / Password"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
]


class SecurityAgent(BaseInvestigatorAgent):
    """
    Agent identifying security flaws, hardcoded credentials, unsafe deserialization, and dangerous subprocesses.

    M12: Combines existing static security rules with deterministic data-flow / taint analysis.
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
        # M12: Initialize taint analyzer
        self._taint_analyzer = PythonTaintAnalyzer() if _TAINT_AVAILABLE else None

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

                # 3. M12: Taint / Data-Flow Analysis (Python only)
                taint_findings = self._run_taint_analysis(rel_file, snippet, context)
                findings.extend(taint_findings)

            # 4. Polyglot Security Analysis (JS/TS/Vue/React)
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

    def _run_taint_analysis(
        self, rel_file: str, snippet: str, context: RepositoryContext
    ) -> List[Finding]:
        """
        M12: Run deterministic taint/data-flow analysis on a Python source file.
        Returns Finding objects for each confirmed taint path.
        Does NOT replace existing _analyze_ast_security results.
        """
        if not _TAINT_AVAILABLE or self._taint_analyzer is None:
            return []

        # Read the full file for taint analysis (not limited snippet)
        full_path = os.path.join(context.repository_path, rel_file)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            content = snippet

        try:
            result = self._taint_analyzer.analyze(rel_file, content)
        except Exception as ex:
            logger.debug(f"[SecurityAgent/Taint] Analysis failed for {rel_file}: {ex}")
            return []

        if result.unsupported or result.error:
            return []

        findings: List[Finding] = []

        for taint_finding in result.findings:
            # Skip sanitized paths — they are not security issues
            if taint_finding.is_sanitized:
                continue

            # Skip UNKNOWN severity with low confidence (insufficient evidence)
            if taint_finding.severity == TaintSeverity.UNKNOWN and taint_finding.confidence < 0.65:
                continue

            path = taint_finding.path
            source = path.source
            sink = path.sink

            # Build evidence chain
            ev_source = Evidence(
                source=EvidenceSource.STATIC_ANALYSIS,
                kind=EvidenceKind.OBSERVED,
                description=f"Taint source detected: {source.label()}",
                payload={
                    "taint_source": source.to_dict(),
                    "file": rel_file,
                    "line": source.line_no,
                },
            )
            ev_sink = Evidence(
                source=EvidenceSource.STATIC_ANALYSIS,
                kind=EvidenceKind.OBSERVED,
                description=f"Dangerous sink detected: {sink.label()}",
                payload={
                    "taint_sink": sink.to_dict(),
                    "file": rel_file,
                    "line": sink.line_no,
                },
            )
            ev_taint = Evidence(
                source=EvidenceSource.SEMANTIC_ANALYSIS,
                kind=EvidenceKind.INFERRED,
                description=(
                    f"Taint propagation chain: {path.chain_description()}\n"
                    f"Propagation steps: {len(path.propagation_steps)}"
                ),
                payload={
                    "taint_finding": taint_finding.to_dict(),
                    "chain": path.chain_description(),
                },
            )
            evidence = [ev_source, ev_sink, ev_taint]

            # Add sanitizer evidence if any (explains why path is medium/low)
            for san in path.sanitizers:
                ev_san = Evidence(
                    source=EvidenceSource.SEMANTIC_ANALYSIS,
                    kind=EvidenceKind.OBSERVED,
                    description=f"Sanitizer evidence: {san.label()}",
                    payload=san.to_dict(),
                )
                evidence.append(ev_san)

            # Map TaintSeverity → Finding severity string
            severity_map = {
                TaintSeverity.CRITICAL: "critical",
                TaintSeverity.HIGH: "high",
                TaintSeverity.MEDIUM: "medium",
                TaintSeverity.LOW: "low",
                TaintSeverity.UNKNOWN: "medium",
            }
            severity_str = severity_map.get(taint_finding.severity, "high")

            finding = self.create_finding(
                category="security",
                severity=severity_str,
                title=taint_finding.title,
                description=(
                    f"{taint_finding.explanation}\n\n"
                    f"Source: {source.code_snippet.strip()}\n"
                    f"Propagation:\n{path.chain_description()}\n"
                    f"Sink: {sink.code_snippet.strip()}\n"
                    f"Severity: {taint_finding.severity.value}\n"
                    f"Confidence: {taint_finding.confidence:.2f}"
                ),
                file=rel_file,
                line_range=(source.line_no, sink.line_no),
                evidence=evidence,
                confidence=taint_finding.confidence,
                graph_context={
                    "taint_finding": True,
                    "taint_severity": taint_finding.severity.value,
                    "source_kind": source.source_kind.value,
                    "sink_kind": sink.sink_kind.value,
                    "propagation_depth": len(path.propagation_steps),
                    "source_line": source.line_no,
                    "sink_line": sink.line_no,
                    "chain": path.chain_description(),
                },
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
        except Exception as ex:
            logger.warning(f"[SecurityAgent] AST parse failed for '{rel_file}': {ex}")
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
                    
                    # Ignore hardcoded static command strings (e.g. subprocess.run("echo static", shell=True))
                    is_static_cmd = False
                    if node.args and isinstance(node.args[0], ast.Constant):
                        is_static_cmd = True

                    if is_shell_true and not is_static_cmd:
                        ev_ast = Evidence(
                            source=EvidenceSource.STATIC_ANALYSIS,
                            kind=EvidenceKind.OBSERVED,
                            description=f"Subprocess call with shell=True on line {line_no}.",
                            payload={"file": rel_file, "line": line_no},
                        )
                        ev_infer = Evidence(
                            source=EvidenceSource.STATIC_ANALYSIS,
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
