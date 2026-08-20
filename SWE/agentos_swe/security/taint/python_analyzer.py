"""
M12 Taint Analysis — Python AST Taint Analyzer (Full Implementation).

Implements SemanticTaintProvider for Python using deterministic AST analysis.

Capabilities:
  - Source detection: HTTP params, os.environ, sys.argv, input(), argparse
  - Sink detection: subprocess (shell=True), eval/exec, SQL execute, pickle, templates
  - Intra-procedural propagation: assignment, concat, f-string, format, containers
  - Inter-procedural propagation: bounded to MAX_TAINT_DEPTH=8 hops
  - Sanitizer awareness: shlex.quote, html.escape, markupsafe.escape, parameterized SQL
  - Severity scoring: evidence-driven CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
"""

import ast
import logging
from typing import List, Dict, Set, Optional, Tuple, Any

from agentos_swe.security.taint.models import (
    TaintSource,
    TaintSink,
    TaintSinkKind,
    TaintSourceKind,
    TaintPropagation,
    SanitizerEvidence,
    TaintPath,
    TaintFinding,
    TaintSeverity,
)
from agentos_swe.security.taint.sources import SourceDetector
from agentos_swe.security.taint.sinks import SinkDetector
from agentos_swe.security.taint.sanitizer import SanitizerDetector
from agentos_swe.security.taint.propagation import PropagationTracker, InterProceduralTracker
from agentos_swe.security.taint.analyzer import SemanticTaintProvider, TaintAnalysisResult

logger = logging.getLogger(__name__)

MAX_TAINT_DEPTH = 8


class PythonTaintAnalyzer(SemanticTaintProvider):
    """
    Full Python AST-based taint analyzer implementing the SemanticTaintProvider interface.

    Performs deterministic, bounded source-to-sink taint tracking with sanitizer
    awareness and inter-procedural propagation support.
    """

    def __init__(self):
        pass

    # ------------------------------------------------------------------
    # SemanticTaintProvider interface
    # ------------------------------------------------------------------

    def analyze_sources(
        self,
        file_path: str,
        tree: ast.AST,
        content: str,
    ) -> List[TaintSource]:
        lines = content.splitlines()
        detector = SourceDetector(file_path)
        return detector.detect(tree, lines)

    def analyze_sinks(
        self,
        file_path: str,
        tree: ast.AST,
        content: str,
    ) -> List[TaintSink]:
        lines = content.splitlines()
        detector = SinkDetector(file_path)
        return detector.detect(tree, lines)

    def build_taint_paths(
        self,
        file_path: str,
        tree: ast.AST,
        sources: List[TaintSource],
        sinks: List[TaintSink],
    ) -> List[TaintFinding]:
        """Connect sources to sinks and return TaintFinding objects with full chains."""
        if not sources or not sinks:
            return []

        content = ast.unparse(tree) if hasattr(ast, "unparse") else ""
        lines = content.splitlines() if content else []
        # Fall back — regenerate lines from tree
        # (tree was parsed from original content, lines may be empty if unparse fails)

        return self._connect_sources_to_sinks(file_path, tree, lines, sources, sinks)

    def analyze(self, file_path: str, content: str) -> TaintAnalysisResult:
        """
        Full pipeline: parse → detect sources → detect sinks → detect sanitizers
        → propagate → connect paths → score severity.
        """
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            return TaintAnalysisResult(
                file_path=file_path,
                error=f"Syntax error during parse: {e}",
            )

        lines = content.splitlines()

        # Step 1: Detect sources
        source_detector = SourceDetector(file_path)
        sources = source_detector.detect(tree, lines)

        # Step 2: Detect sinks
        sink_detector = SinkDetector(file_path)
        sinks = sink_detector.detect(tree, lines)

        # Step 3: Detect sanitizers
        san_detector = SanitizerDetector(file_path)
        sanitizers = san_detector.detect(tree, lines)

        if not sources or not sinks:
            return TaintAnalysisResult(
                file_path=file_path,
                sources_found=len(sources),
                sinks_found=len(sinks),
                sanitizers_found=len(sanitizers),
            )

        # Step 4: Build taint paths
        findings = self._build_all_paths(
            file_path, tree, lines, sources, sinks, sanitizers
        )

        return TaintAnalysisResult(
            file_path=file_path,
            findings=findings,
            sources_found=len(sources),
            sinks_found=len(sinks),
            sanitizers_found=len(sanitizers),
            analysis_depth=MAX_TAINT_DEPTH,
        )

    # ------------------------------------------------------------------
    # Core path-building logic
    # ------------------------------------------------------------------

    def _build_all_paths(
        self,
        file_path: str,
        tree: ast.AST,
        lines: List[str],
        sources: List[TaintSource],
        sinks: List[TaintSink],
        sanitizers: List[SanitizerEvidence],
    ) -> List[TaintFinding]:
        """Build complete taint paths from all sources through all sinks."""
        findings: List[TaintFinding] = []

        intra_tracker = PropagationTracker(file_path)
        inter_tracker = InterProceduralTracker(file_path)

        # Build initial tainted set from all sources
        initial_tainted: Set[str] = {s.var_name for s in sources if s.var_name}

        # Intra-procedural propagation
        all_tainted, intra_steps = intra_tracker.track(tree, lines, initial_tainted)

        # Inter-procedural propagation
        call_sites = inter_tracker.extract_call_sites(tree, lines)
        all_tainted, inter_steps = inter_tracker.track_inter_procedural(
            tree, lines, all_tainted, call_sites
        )
        all_steps = intra_steps + inter_steps

        # Build source→var ancestry map for path reconstruction
        ancestry = _build_ancestry(sources, all_steps)

        # Match sinks to reachable tainted variables
        san_detector = SanitizerDetector(file_path)

        for sink in sinks:
            if sink.var_name not in all_tainted and not _sink_has_tainted_arg(sink, all_tainted, tree):
                continue

            # Which source(s) can reach this sink?
            sink_var = sink.var_name
            if not sink_var or sink_var == "<expr>":
                # Try to find a tainted name embedded in the sink snippet
                sink_var = _find_best_tainted_var_for_sink(sink, all_tainted, tree, lines)
                if not sink_var:
                    continue

            reachable_sources = _find_reachable_sources(sink_var, sources, ancestry, all_tainted)
            if not reachable_sources:
                continue

            for source in reachable_sources:
                # Reconstruct propagation chain
                prop_chain = _reconstruct_chain(source.var_name, sink_var, all_steps)

                # Check sanitizers
                chain_vars: Set[str] = {source.var_name, sink_var}
                for step in prop_chain:
                    chain_vars.add(step.from_var)
                    chain_vars.add(step.to_var)
                covering_san = san_detector.covers_any_var(sanitizers, chain_vars)

                # Also check parameterized SQL
                sql_parameterized = False
                if sink.sink_kind == TaintSinkKind.SQL_QUERY:
                    sql_parameterized = _check_sql_parameterized(sink, sanitizers)

                path = TaintPath(
                    source=source,
                    sink=sink,
                    propagation_steps=prop_chain,
                    sanitizers=[covering_san] if covering_san else [],
                    file=file_path,
                )

                is_san = path.is_sanitized or sql_parameterized

                severity, confidence, explanation = _score_severity(
                    source, sink, prop_chain, is_san
                )

                finding = TaintFinding(
                    path=path,
                    severity=severity,
                    confidence=confidence,
                    title=_make_title(source, sink),
                    explanation=explanation,
                    evidence_sources=["AST_TAINT_ANALYSIS", "SOURCE_DETECTION", "SINK_DETECTION"],
                    is_sanitized=is_san,
                )
                findings.append(finding)

        return findings

    def _connect_sources_to_sinks(
        self,
        file_path: str,
        tree: ast.AST,
        lines: List[str],
        sources: List[TaintSource],
        sinks: List[TaintSink],
    ) -> List[TaintFinding]:
        """Wrapper used when calling build_taint_paths from interface."""
        san_detector = SanitizerDetector(file_path)
        sanitizers = san_detector.detect(tree, lines)
        return self._build_all_paths(file_path, tree, lines, sources, sinks, sanitizers)


# ---------------------------------------------------------------------------
# Path reconstruction helpers
# ---------------------------------------------------------------------------

def _build_ancestry(
    sources: List[TaintSource],
    steps: List[TaintPropagation],
) -> Dict[str, str]:
    """
    Build a map: variable → immediate parent variable in taint chain.
    Used for path reconstruction from sink back to source.
    """
    ancestry: Dict[str, str] = {}
    for step in steps:
        if step.to_var not in ancestry:
            ancestry[step.to_var] = step.from_var
    return ancestry


def _find_reachable_sources(
    sink_var: str,
    sources: List[TaintSource],
    ancestry: Dict[str, str],
    all_tainted: Set[str],
) -> List[TaintSource]:
    """
    Walk up the ancestry chain from sink_var to find which sources can reach it.
    """
    # Build the ancestry path back to source
    chain: List[str] = [sink_var]
    current = sink_var
    visited: Set[str] = {current}

    for _ in range(MAX_TAINT_DEPTH + 2):
        parent = ancestry.get(current)
        if not parent or parent in visited:
            break
        chain.append(parent)
        visited.add(parent)
        current = parent

    chain_set = set(chain)
    return [s for s in sources if s.var_name in chain_set]


def _reconstruct_chain(
    source_var: str,
    sink_var: str,
    steps: List[TaintPropagation],
) -> List[TaintPropagation]:
    """
    Reconstruct the ordered propagation chain from source_var to sink_var.
    Returns the minimal path covering the ancestry.
    """
    if source_var == sink_var:
        return []

    # Build parent map
    parent: Dict[str, Optional[str]] = {}
    step_map: Dict[str, TaintPropagation] = {}

    for step in steps:
        if step.to_var not in parent:
            parent[step.to_var] = step.from_var
            step_map[step.to_var] = step

    # Walk from sink back to source
    chain_reversed: List[TaintPropagation] = []
    current = sink_var
    visited: Set[str] = {current}

    for _ in range(MAX_TAINT_DEPTH + 2):
        p = parent.get(current)
        if p is None:
            break
        if p in visited:
            break
        s = step_map.get(current)
        if s:
            chain_reversed.append(s)
        visited.add(p)
        if p == source_var:
            break
        current = p

    return list(reversed(chain_reversed))


def _sink_has_tainted_arg(
    sink: TaintSink, all_tainted: Set[str], tree: ast.AST
) -> bool:
    """
    Check if any embedded name in the sink's var_name string is tainted.
    Handles comma-separated multi-name results from f-string detection.
    """
    if not sink.var_name:
        return False
    parts = [p.strip() for p in sink.var_name.split(",")]
    return any(p in all_tainted for p in parts)


def _find_best_tainted_var_for_sink(
    sink: TaintSink,
    all_tainted: Set[str],
    tree: ast.AST,
    lines: List[str],
) -> Optional[str]:
    """
    When the sink's direct var_name is not tainted, attempt to find a tainted
    variable referenced in the same sink call expression.
    """
    # Check comma-separated multi-names
    if sink.var_name:
        parts = [p.strip() for p in sink.var_name.split(",")]
        for p in parts:
            if p in all_tainted:
                return p

    # Check if any tainted var appears in the sink's code snippet
    snippet = sink.code_snippet
    for var in all_tainted:
        if var and var in snippet:
            return var

    return None


def _find_reachable_sources_for_embedded_var(
    embedded_var: str,
    source_var: str,
    sources: List[TaintSource],
    ancestry: Dict[str, str],
    all_tainted: Set[str],
) -> List[TaintSource]:
    """Extended source finding when sink embeds a tainted variable."""
    return _find_reachable_sources(embedded_var, sources, ancestry, all_tainted)


def _check_sql_parameterized(
    sink: TaintSink, sanitizers: List[SanitizerEvidence]
) -> bool:
    """Check if a SQL sink is covered by a parameterized_sql sanitizer."""
    for san in sanitizers:
        if san.sanitizer_name == "parameterized_sql" and san.line_no == sink.line_no:
            return True
    return False


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

def _score_severity(
    source: TaintSource,
    sink: TaintSink,
    prop_chain: List[TaintPropagation],
    is_sanitized: bool,
) -> Tuple[TaintSeverity, float, str]:
    """
    Evidence-driven severity scoring.

    Returns (severity, confidence, explanation).
    """
    if is_sanitized:
        return (
            TaintSeverity.LOW,
            0.75,
            f"Tainted data from {source.source_kind.value} reaches {sink.sink_kind.value} "
            f"but a sanitizer is present in the data flow path.",
        )

    # CRITICAL: external input → eval/exec or shell=True command execution
    if sink.sink_kind in (TaintSinkKind.EVAL_EXECUTION, TaintSinkKind.DYNAMIC_CODE_EXECUTION):
        return (
            TaintSeverity.CRITICAL,
            0.96,
            f"Untrusted {source.source_kind.value} data flows directly to {sink.sink_kind.value}. "
            f"This allows arbitrary code execution.",
        )

    if sink.sink_kind == TaintSinkKind.SHELL_EXECUTION and sink.is_shell_true:
        return (
            TaintSeverity.CRITICAL,
            0.95,
            f"Untrusted {source.source_kind.value} data flows to subprocess with shell=True. "
            f"This enables command injection attacks.",
        )

    if sink.sink_kind == TaintSinkKind.COMMAND_EXECUTION:
        return (
            TaintSeverity.HIGH,
            0.88,
            f"Untrusted {source.source_kind.value} data flows to command execution sink. "
            f"Without shell=True, direct argument injection is possible.",
        )

    # HIGH: SQL injection, deserialization, unsafe file path, template injection
    if sink.sink_kind == TaintSinkKind.SQL_QUERY:
        return (
            TaintSeverity.HIGH,
            0.91,
            f"Untrusted {source.source_kind.value} data is concatenated into SQL query. "
            f"SQL injection vulnerability.",
        )

    if sink.sink_kind == TaintSinkKind.DESERIALIZATION:
        return (
            TaintSeverity.HIGH,
            0.89,
            f"Untrusted {source.source_kind.value} data passed to unsafe deserializer. "
            f"Remote code execution risk.",
        )

    if sink.sink_kind in (TaintSinkKind.FILE_PATH_OPERATION, TaintSinkKind.FILE_WRITE):
        return (
            TaintSeverity.HIGH,
            0.85,
            f"Untrusted {source.source_kind.value} data used in file path operation. "
            f"Path traversal vulnerability.",
        )

    if sink.sink_kind == TaintSinkKind.TEMPLATE_RENDERING:
        return (
            TaintSeverity.HIGH,
            0.88,
            f"Untrusted {source.source_kind.value} data used in template rendering. "
            f"Server-Side Template Injection (SSTI) risk.",
        )

    # MEDIUM: external influence on outbound HTTP or HTML output
    if sink.sink_kind == TaintSinkKind.HTML_OUTPUT:
        return (
            TaintSeverity.MEDIUM,
            0.82,
            f"Untrusted {source.source_kind.value} data reflected in HTML output. "
            f"Cross-Site Scripting (XSS) risk.",
        )

    if sink.sink_kind == TaintSinkKind.HTTP_REQUEST:
        return (
            TaintSeverity.MEDIUM,
            0.78,
            f"Externally-influenced data used in outbound HTTP request. "
            f"Server-Side Request Forgery (SSRF) risk.",
        )

    # UNKNOWN: incomplete data-flow evidence
    return (
        TaintSeverity.UNKNOWN,
        0.55,
        f"Tainted data from {source.source_kind.value} reaches {sink.sink_kind.value}, "
        f"but severity cannot be determined without more context.",
    )


# ---------------------------------------------------------------------------
# Title generation
# ---------------------------------------------------------------------------

def _make_title(source: TaintSource, sink: TaintSink) -> str:
    """Generate a human-readable finding title."""
    source_label_map = {
        TaintSourceKind.HTTP_REQUEST: "HTTP Request Input",
        TaintSourceKind.QUERY_PARAMETER: "HTTP Query Parameter",
        TaintSourceKind.FORM_INPUT: "HTTP Form Input",
        TaintSourceKind.JSON_INPUT: "HTTP JSON Input",
        TaintSourceKind.ENVIRONMENT_VARIABLE: "Environment Variable",
        TaintSourceKind.CLI_ARGUMENT: "CLI Argument",
        TaintSourceKind.USER_INPUT: "User Input",
        TaintSourceKind.FILE_INPUT: "File Input",
        TaintSourceKind.LLM_OUTPUT: "LLM Output",
        TaintSourceKind.DATABASE_RESULT: "Database Result",
        TaintSourceKind.UNKNOWN_EXTERNAL_INPUT: "External Input",
    }
    sink_label_map = {
        TaintSinkKind.SHELL_EXECUTION: "Shell Command Execution",
        TaintSinkKind.COMMAND_EXECUTION: "Command Execution",
        TaintSinkKind.EVAL_EXECUTION: "eval()/exec()",
        TaintSinkKind.SQL_QUERY: "SQL Query",
        TaintSinkKind.FILE_WRITE: "File Write",
        TaintSinkKind.FILE_PATH_OPERATION: "File Path Operation",
        TaintSinkKind.HTML_OUTPUT: "HTML Output",
        TaintSinkKind.HTTP_REQUEST: "HTTP Request",
        TaintSinkKind.DESERIALIZATION: "Unsafe Deserialization",
        TaintSinkKind.TEMPLATE_RENDERING: "Template Rendering",
        TaintSinkKind.DYNAMIC_CODE_EXECUTION: "Dynamic Code Execution",
    }
    src = source_label_map.get(source.source_kind, source.source_kind.value)
    snk = sink_label_map.get(sink.sink_kind, sink.sink_kind.value)
    return f"Potential {snk} via {src}"
