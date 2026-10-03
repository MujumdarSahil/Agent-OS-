"""
M12 Taint Analysis — Sink Detector.

Identifies locations in Python AST where tainted data reaches a dangerous operation.
All detection is deterministic and evidence-based.
"""

import ast
import logging
from typing import List, Optional, Dict, Set

from agentos_swe.security.taint.models import TaintSink, TaintSinkKind

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sink detection patterns
# ---------------------------------------------------------------------------

# subprocess.run / Popen / call / check_call / check_output
_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}

# os-level shell execution
_OS_SHELL_FUNCS = {"system", "popen", "execv", "execve", "execvp", "execvpe",
                   "spawnv", "spawnve", "spawnvp", "spawnvpe"}

# eval / exec builtins
_EVAL_EXEC_NAMES = {"eval", "exec", "compile"}

# SQL execution methods
_SQL_EXEC_METHODS = {"execute", "executemany", "executescript", "callproc"}
_SQL_CURSOR_RECEIVERS = {"cursor", "cur", "conn", "connection", "db", "session",
                          "c", "engine", "curs"}

# Template rendering sinks
_TEMPLATE_FUNCS = {"render_template_string", "Template"}
_TEMPLATE_RENDER_METHODS = {"render", "render_string"}

# Pickle / YAML unsafe deserialization
_DESER_METHODS = {"loads", "load", "unsafe_load"}
_DESER_MODULES = {"pickle", "yaml", "marshal", "shelve"}

# File write sinks (external path)
_FILE_WRITE_METHODS = {"write", "write_text", "write_bytes", "writelines"}

# HTML output sinks
_HTML_OUTPUT_FUNCS = {"render", "make_response", "Response", "HTMLResponse"}


class SinkDetector:
    """
    Deterministic Python AST-based taint sink detector.

    Scans a parsed AST and code lines to identify all dangerous sink locations,
    recording what variable names are passed to them.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def detect(self, tree: ast.AST, lines: List[str]) -> List[TaintSink]:
        """Walk the AST and return all detected dangerous sinks."""
        sinks: List[TaintSink] = []
        import_aliases = _build_import_aliases(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                result = self._check_call_sink(node, lines, import_aliases)
                if result:
                    sinks.append(result)

        return sinks

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_call_sink(
        self,
        node: ast.Call,
        lines: List[str],
        import_aliases: Dict[str, str],
    ) -> Optional[TaintSink]:
        func = node.func
        line_no = getattr(node, "lineno", 1)
        snippet = _get_line(lines, line_no)

        # 1. eval() / exec() / compile()
        if isinstance(func, ast.Name) and func.id in _EVAL_EXEC_NAMES:
            var_name = _extract_first_arg_name(node)
            return TaintSink(
                var_name=var_name,
                sink_kind=TaintSinkKind.EVAL_EXECUTION,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.99,
            )

        if isinstance(func, ast.Attribute):
            fn_attr = func.attr
            receiver_name = _resolve_name(func.value, import_aliases)
            module_root = receiver_name.split(".")[0]

            # 2. subprocess.run/Popen/call with shell=True
            if fn_attr in _SUBPROCESS_FUNCS:
                # Check if receiver is subprocess (directly or aliased)
                if module_root in ("subprocess",) or receiver_name in ("subprocess",):
                    is_shell = _has_shell_true(node)
                    var_name = _extract_first_arg_name(node)
                    return TaintSink(
                        var_name=var_name,
                        sink_kind=TaintSinkKind.SHELL_EXECUTION if is_shell else TaintSinkKind.COMMAND_EXECUTION,
                        line_no=line_no,
                        code_snippet=snippet,
                        file=self.file_path,
                        is_shell_true=is_shell,
                        confidence=0.97 if is_shell else 0.85,
                    )

            # 3. os.system / os.popen / os.exec*
            if fn_attr in _OS_SHELL_FUNCS:
                if module_root == "os" or receiver_name in ("os",):
                    var_name = _extract_first_arg_name(node)
                    return TaintSink(
                        var_name=var_name,
                        sink_kind=TaintSinkKind.SHELL_EXECUTION,
                        line_no=line_no,
                        code_snippet=snippet,
                        file=self.file_path,
                        is_shell_true=True,
                        confidence=0.97,
                    )

            # 4. SQL execute methods
            if fn_attr in _SQL_EXEC_METHODS:
                # Must have at least one arg and receiver looks like a cursor/connection
                recv_base = receiver_name.split(".")[-1]
                if recv_base in _SQL_CURSOR_RECEIVERS or receiver_name in _SQL_CURSOR_RECEIVERS:
                    var_name = _extract_first_arg_name(node)
                    # Only flag if there are no parameterized placeholders being used
                    # (checked later in sanitizer layer; here we just detect the sink)
                    return TaintSink(
                        var_name=var_name,
                        sink_kind=TaintSinkKind.SQL_QUERY,
                        line_no=line_no,
                        code_snippet=snippet,
                        file=self.file_path,
                        confidence=0.92,
                    )

            # 5. pickle.loads / yaml.load / yaml.unsafe_load / marshal.loads
            if fn_attr in _DESER_METHODS:
                if module_root in _DESER_MODULES:
                    var_name = _extract_first_arg_name(node)
                    return TaintSink(
                        var_name=var_name,
                        sink_kind=TaintSinkKind.DESERIALIZATION,
                        line_no=line_no,
                        code_snippet=snippet,
                        file=self.file_path,
                        confidence=0.93,
                    )

            # 6. Template rendering sinks
            if fn_attr in _TEMPLATE_RENDER_METHODS and receiver_name in ("template", "tmpl", "t"):
                var_name = _extract_first_arg_name(node)
                return TaintSink(
                    var_name=var_name,
                    sink_kind=TaintSinkKind.TEMPLATE_RENDERING,
                    line_no=line_no,
                    code_snippet=snippet,
                    file=self.file_path,
                    confidence=0.85,
                )

        # 7. render_template_string() / Template() as bare calls
        if isinstance(func, ast.Name) and func.id in _TEMPLATE_FUNCS:
            var_name = _extract_first_arg_name(node)
            return TaintSink(
                var_name=var_name,
                sink_kind=TaintSinkKind.TEMPLATE_RENDERING,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.88,
            )

        return None

    def get_sinks_for_vars(
        self, sinks: List[TaintSink], tainted_vars: Set[str]
    ) -> List[TaintSink]:
        """Filter sinks to those that receive a tainted variable."""
        return [s for s in sinks if s.var_name in tainted_vars]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _has_shell_true(call_node: ast.Call) -> bool:
    """Return True if shell=True is present as a keyword argument."""
    for kw in call_node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _extract_first_arg_name(call_node: ast.Call) -> str:
    """Extract the first positional argument as a variable name string (best effort)."""
    if not call_node.args:
        return ""
    arg = call_node.args[0]
    if isinstance(arg, ast.Name):
        return arg.id
    elif isinstance(arg, (ast.JoinedStr, ast.BinOp)):
        # f-string or concat — extract constituent names
        names = _extract_names_from_expr(arg)
        return ", ".join(names) if names else "<expr>"
    elif isinstance(arg, ast.Constant):
        return f"<const:{repr(arg.value)[:20]}>"
    return "<expr>"


def _extract_names_from_expr(node: ast.expr) -> List[str]:
    """Recursively extract all Name nodes from an expression."""
    names: List[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.append(child.id)
    return list(dict.fromkeys(names))  # preserve order, deduplicate


def _resolve_name(node: ast.expr, import_aliases: Dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return import_aliases.get(node.id, node.id)
    elif isinstance(node, ast.Attribute):
        prefix = _resolve_name(node.value, import_aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


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
