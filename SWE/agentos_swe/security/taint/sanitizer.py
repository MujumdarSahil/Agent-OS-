"""
M12 Taint Analysis — Sanitizer Detector.

Identifies locations where known, deterministic sanitization is applied to
tainted variables. Uses evidence of actual sanitizer function calls rather
than name-based heuristics.

IMPORTANT: A function is NOT considered a sanitizer merely because its name
contains "safe", "clean", "sanitize", "validate", "escape", etc.
Only deterministically known sanitization APIs are recognized.
"""

import ast
import logging
from typing import List, Optional, Dict, Set, Tuple

from agentos_swe.security.taint.models import SanitizerEvidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known safe sanitizers (deterministic evidence only)
# ---------------------------------------------------------------------------

# Shell sanitizers
_SHELL_SANITIZERS = {
    "shlex.quote",   # shlex.quote(x)
    "pipes.quote",   # deprecated but still encountered
}

# HTML sanitizers
_HTML_SANITIZERS = {
    "html.escape",           # html.escape(x)
    "markupsafe.escape",     # markupsafe.escape(x)
    "bleach.clean",          # bleach.clean(x)
    "cgi.escape",            # legacy Python 2
}

# Path safety functions (note: these must be combined with proper validation)
_PATH_SANITIZERS = {
    "pathlib.Path",     # used with .resolve() then checked
    "os.path.abspath",  # when followed by prefix check
    "os.path.realpath",
}


class SanitizerDetector:
    """
    Deterministic Python AST-based sanitizer detector.

    Identifies when a tainted variable passes through a known safe function
    before reaching a sink. Uses deterministic function-call evidence; does
    NOT rely on function name heuristics.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def detect(self, tree: ast.AST, lines: List[str]) -> List[SanitizerEvidence]:
        """
        Walk the AST and return all detected sanitizer applications
        as SanitizerEvidence objects.
        """
        results: List[SanitizerEvidence] = []
        import_aliases = _build_import_aliases(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                ev = self._check_sanitized_assignment(node, lines, import_aliases)
                if ev:
                    results.append(ev)

            elif isinstance(node, ast.Call):
                ev = self._check_sanitizer_call(node, lines, import_aliases)
                if ev:
                    results.append(ev)

        # Also detect parameterized SQL (cursor.execute(query, params))
        sql_evs = self._detect_parameterized_sql(tree, lines, import_aliases)
        results.extend(sql_evs)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_sanitized_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        import_aliases: Dict[str, str],
    ) -> Optional[SanitizerEvidence]:
        """Detect: safe_x = shlex.quote(x) or safe_x = html.escape(x) etc."""
        value = node.value
        line_no = getattr(node, "lineno", 1)
        snippet = _get_line(lines, line_no)

        var_name = _extract_target_name(node.targets)
        if not var_name:
            return None

        sanitizer_name, input_var = self._identify_sanitizer_call(value, import_aliases)
        if sanitizer_name and input_var:
            return SanitizerEvidence(
                var_name=input_var,         # the variable being sanitized (input to sanitizer)
                sanitizer_name=sanitizer_name,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.97,
            )
        return None

    def _check_sanitizer_call(
        self,
        node: ast.Call,
        lines: List[str],
        import_aliases: Dict[str, str],
    ) -> Optional[SanitizerEvidence]:
        """Detect inline sanitizer calls (not assigned to a variable)."""
        line_no = getattr(node, "lineno", 1)
        snippet = _get_line(lines, line_no)

        sanitizer_name, input_var = self._identify_sanitizer_call(node, import_aliases)
        if sanitizer_name and input_var:
            return SanitizerEvidence(
                var_name=input_var,
                sanitizer_name=sanitizer_name,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.95,
            )
        return None

    def _identify_sanitizer_call(
        self, call_node: ast.expr, import_aliases: Dict[str, str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns (sanitizer_qualified_name, input_variable_name) if this is a
        known sanitizer call with an identifiable input variable. Otherwise (None, None).
        """
        if not isinstance(call_node, ast.Call):
            return None, None

        func = call_node.func

        # Resolve the fully qualified name of the function
        qualified = _resolve_qualified_name(func, import_aliases)

        # Check shell sanitizers
        if qualified in _SHELL_SANITIZERS or qualified in ("quote",) and _is_imported_from(import_aliases, "shlex", "quote"):
            input_var = _extract_first_arg_name(call_node)
            if input_var:
                return qualified, input_var

        # Check HTML sanitizers
        if qualified in _HTML_SANITIZERS:
            input_var = _extract_first_arg_name(call_node)
            if input_var:
                return qualified, input_var

        # bleach.clean or just clean() if imported from bleach
        if qualified == "clean" and _is_imported_from(import_aliases, "bleach", "clean"):
            input_var = _extract_first_arg_name(call_node)
            if input_var:
                return "bleach.clean", input_var

        # markupsafe.escape or just escape() if imported
        if qualified == "escape" and _is_imported_from(import_aliases, "markupsafe", "escape"):
            input_var = _extract_first_arg_name(call_node)
            if input_var:
                return "markupsafe.escape", input_var

        if qualified == "escape" and _is_imported_from(import_aliases, "html", "escape"):
            input_var = _extract_first_arg_name(call_node)
            if input_var:
                return "html.escape", input_var

        # Primitive type casting (int, float, bool) neutralizes string injections
        if isinstance(func, ast.Name) and func.id in ("int", "float", "bool"):
            input_var = _extract_first_arg_name(call_node)
            if input_var:
                return f"typecast_{func.id}", input_var

        return None, None

    def _detect_parameterized_sql(
        self,
        tree: ast.AST,
        lines: List[str],
        import_aliases: Dict[str, str],
    ) -> List[SanitizerEvidence]:
        """
        Detect parameterized SQL: cursor.execute(query, params).
        When execute() is called with TWO or more arguments, the second
        argument is a parameter tuple/list, which is the safe pattern.
        """
        results: List[SanitizerEvidence] = []
        _SQL_CURSOR_RECEIVERS = {"cursor", "cur", "conn", "connection", "db",
                                  "session", "c", "engine", "curs"}
        _SQL_EXEC = {"execute", "executemany"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                line_no = getattr(node, "lineno", 1)
                snippet = _get_line(lines, line_no)

                if isinstance(func, ast.Attribute) and func.attr in _SQL_EXEC:
                    receiver = _resolve_name(func.value, import_aliases)
                    recv_base = receiver.split(".")[-1]
                    if recv_base in _SQL_CURSOR_RECEIVERS:
                        # Parameterized: execute(query, params) — 2+ args
                        if len(node.args) >= 2 or (len(node.args) >= 1 and node.keywords):
                            var_name = _extract_first_arg_name(node)
                            if var_name:
                                results.append(SanitizerEvidence(
                                    var_name=var_name,
                                    sanitizer_name="parameterized_sql",
                                    line_no=line_no,
                                    code_snippet=snippet,
                                    file=self.file_path,
                                    confidence=0.95,
                                ))
        return results

    def covers_var(self, evidence: List[SanitizerEvidence], var_name: str) -> bool:
        """Return True if any sanitizer evidence covers the given variable."""
        for ev in evidence:
            if ev.var_name == var_name and ev.confidence >= 0.90:
                return True
        return False

    def covers_any_var(
        self, evidence: List[SanitizerEvidence], var_names: Set[str]
    ) -> Optional[SanitizerEvidence]:
        """Return the first sanitizer evidence that covers any of the given variables."""
        for ev in evidence:
            if ev.var_name in var_names and ev.confidence >= 0.90:
                return ev
        return None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _resolve_qualified_name(func: ast.expr, import_aliases: Dict[str, str]) -> str:
    """Resolve a function expression to its qualified name, using import aliases."""
    if isinstance(func, ast.Name):
        return import_aliases.get(func.id, func.id)
    elif isinstance(func, ast.Attribute):
        receiver = _resolve_name(func.value, import_aliases)
        return f"{receiver}.{func.attr}" if receiver else func.attr
    return ""


def _resolve_name(node: ast.expr, import_aliases: Dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return import_aliases.get(node.id, node.id)
    elif isinstance(node, ast.Attribute):
        prefix = _resolve_name(node.value, import_aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_imported_from(import_aliases: Dict[str, str], module: str, name: str) -> bool:
    """Return True if `name` is in the import aliases as coming from `module`."""
    target = f"{module}.{name}"
    return target in import_aliases.values()


def _extract_target_name(targets: list) -> Optional[str]:
    for t in targets:
        if isinstance(t, ast.Name):
            return t.id
        elif isinstance(t, ast.Tuple):
            for elt in t.elts:
                if isinstance(elt, ast.Name):
                    return elt.id
    return None


def _extract_first_arg_name(call_node: ast.Call) -> Optional[str]:
    if not call_node.args:
        return None
    arg = call_node.args[0]
    if isinstance(arg, ast.Name):
        return arg.id
    return None


def _get_line(lines: List[str], line_no: int) -> str:
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip()
    return ""


def _build_import_aliases(tree: ast.AST) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                aliases[local] = f"{module}.{alias.name}" if module else alias.name
    return aliases
