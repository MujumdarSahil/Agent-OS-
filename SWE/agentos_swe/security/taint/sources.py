"""
M12 Taint Analysis — Source Detector.

Identifies locations in Python AST where untrusted data enters the program.
All detection is deterministic and evidence-based (no name heuristics for safety).
"""

import ast
import logging
from typing import List, Set, Dict, Any, Optional

from agentos_swe.security.taint.models import TaintSource, TaintSourceKind

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known taint-source patterns (deterministic, not heuristic)
# ---------------------------------------------------------------------------

# request.args["x"] / request.args.get("x") / request.form["x"] / request.values["x"]
_FLASK_REQUEST_ATTRS = {"args", "form", "values", "files", "cookies", "headers", "data"}

# request.get_json() / request.json() / request.json
_FLASK_JSON_METHODS = {"get_json", "json"}

# os.environ["X"] / os.getenv("X") / os.environ.get("X")
_ENV_FUNCS = {"getenv"}

# sys.argv
_CLI_MODULES = {"sys"}

# argparse / click argument sources
_ARGPARSE_ATTRS = {"parse_args", "parse_known_args"}

# File reads treated as external input (path given by external actor)
_FILE_READ_METHODS = {"read", "readline", "readlines", "read_text", "read_bytes"}

# LLM / AI output receivers
_LLM_RECEIVER_NAMES = {"response", "llm_response", "ai_response", "model_output",
                        "completion", "llm_output", "gpt_response", "chat_response"}
_LLM_RESPONSE_ATTRS = {"content", "text", "message", "output", "choices"}


class SourceDetector:
    """
    Deterministic Python AST-based taint source detector.

    Scans a parsed AST and code lines to identify all locations where
    untrusted/external data enters the program, returning typed TaintSource objects.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def detect(self, tree: ast.AST, lines: List[str]) -> List[TaintSource]:
        """
        Walk the AST and return all detected taint sources with variable names,
        kinds, line numbers, and code snippets.
        """
        sources: List[TaintSource] = []
        # Collect import aliases first (e.g. `from flask import request`)
        import_aliases = _build_import_aliases(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                result = self._check_assignment(node, lines, import_aliases)
                if result:
                    sources.append(result)

            elif isinstance(node, (ast.AnnAssign,)):
                # Annotated assignment: x: str = request.args["cmd"]
                if node.value:
                    fake_assign = ast.Assign(
                        targets=[node.target] if node.target else [],
                        value=node.value,
                        lineno=node.lineno,
                        col_offset=node.col_offset,
                    )
                    result = self._check_assignment(fake_assign, lines, import_aliases)
                    if result:
                        sources.append(result)

        return sources

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        import_aliases: Dict[str, str],
    ) -> Optional[TaintSource]:
        """
        Check if an assignment node receives untrusted data on the right-hand side.
        Returns a TaintSource if detected, else None.
        """
        value = node.value
        line_no = getattr(node, "lineno", 1)
        snippet = _get_line(lines, line_no)

        # Extract assigned variable name (first simple Name target)
        var_name = _extract_target_name(node.targets)
        if not var_name:
            return None

        # 1. Flask / Starlette / FastAPI request attributes
        source_kind = self._check_request_source(value, import_aliases)
        if source_kind:
            return TaintSource(
                var_name=var_name,
                source_kind=source_kind,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.95,
            )

        # 2. os.environ / os.getenv
        source_kind = self._check_env_source(value, import_aliases)
        if source_kind:
            return TaintSource(
                var_name=var_name,
                source_kind=TaintSourceKind.ENVIRONMENT_VARIABLE,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.97,
            )

        # 3. sys.argv
        source_kind = self._check_argv_source(value, import_aliases)
        if source_kind:
            return TaintSource(
                var_name=var_name,
                source_kind=TaintSourceKind.CLI_ARGUMENT,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.97,
            )

        # 4. input() builtin
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "input":
            return TaintSource(
                var_name=var_name,
                source_kind=TaintSourceKind.USER_INPUT,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.99,
            )

        # 5. argparse Namespace / click argument
        if self._check_argparse_source(value, import_aliases):
            return TaintSource(
                var_name=var_name,
                source_kind=TaintSourceKind.CLI_ARGUMENT,
                line_no=line_no,
                code_snippet=snippet,
                file=self.file_path,
                confidence=0.90,
            )

        return None

    def _check_request_source(
        self, value: ast.expr, import_aliases: Dict[str, str]
    ) -> Optional[TaintSourceKind]:
        """Detect Flask/FastAPI/Starlette request parameter accesses."""
        # Pattern: request.args["x"] or request.args.get("x")
        if isinstance(value, ast.Subscript):
            # request.args["x"]
            if isinstance(value.value, ast.Attribute):
                attr = value.value
                receiver = _resolve_name(attr.value, import_aliases)
                recv_base = receiver.split(".")[-1] if receiver else ""
                if recv_base in ("request", "req") and attr.attr in _FLASK_REQUEST_ATTRS:
                    kind_map = {
                        "args": TaintSourceKind.QUERY_PARAMETER,
                        "form": TaintSourceKind.FORM_INPUT,
                        "values": TaintSourceKind.HTTP_REQUEST,
                        "files": TaintSourceKind.FILE_INPUT,
                        "cookies": TaintSourceKind.HTTP_REQUEST,
                        "headers": TaintSourceKind.HTTP_REQUEST,
                        "data": TaintSourceKind.HTTP_REQUEST,
                    }
                    return kind_map.get(attr.attr, TaintSourceKind.HTTP_REQUEST)

        elif isinstance(value, ast.Call):
            func = value.func
            # request.args.get("x") or request.form.get("x")
            if isinstance(func, ast.Attribute) and func.attr == "get":
                if isinstance(func.value, ast.Attribute):
                    inner = func.value
                    receiver = _resolve_name(inner.value, import_aliases)
                    recv_base = receiver.split(".")[-1] if receiver else ""
                    if recv_base in ("request", "req") and inner.attr in _FLASK_REQUEST_ATTRS:
                        kind_map = {
                            "args": TaintSourceKind.QUERY_PARAMETER,
                            "form": TaintSourceKind.FORM_INPUT,
                            "values": TaintSourceKind.HTTP_REQUEST,
                            "files": TaintSourceKind.FILE_INPUT,
                            "cookies": TaintSourceKind.HTTP_REQUEST,
                            "headers": TaintSourceKind.HTTP_REQUEST,
                            "data": TaintSourceKind.HTTP_REQUEST,
                        }
                        return kind_map.get(inner.attr, TaintSourceKind.HTTP_REQUEST)

            # request.get_json() / request.json()
            if isinstance(func, ast.Attribute) and func.attr in _FLASK_JSON_METHODS:
                receiver = _resolve_name(func.value, import_aliases)
                recv_base = receiver.split(".")[-1] if receiver else ""
                if recv_base in ("request", "req"):
                    return TaintSourceKind.JSON_INPUT

        elif isinstance(value, ast.Attribute):
            # request.json (direct attribute, not a call)
            receiver = _resolve_name(value.value, import_aliases)
            recv_base = receiver.split(".")[-1] if receiver else ""
            if recv_base in ("request", "req") and value.attr in _FLASK_JSON_METHODS:
                return TaintSourceKind.JSON_INPUT

        return None

    def _check_env_source(
        self, value: ast.expr, import_aliases: Dict[str, str]
    ) -> Optional[TaintSourceKind]:
        """Detect os.environ["X"], os.getenv("X"), os.environ.get("X")."""
        if isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Attribute):
                attr = value.value
                receiver = _resolve_name(attr.value, import_aliases)
                recv_base = receiver.split(".")[-1] if receiver else ""
                if (recv_base == "os" or receiver == "os") and attr.attr == "environ":
                    return TaintSourceKind.ENVIRONMENT_VARIABLE
                if attr.attr == "environ" or recv_base == "environ":
                    return TaintSourceKind.ENVIRONMENT_VARIABLE
            # environ["X"] bare (if `from os import environ`)
            if isinstance(value.value, ast.Name):
                resolved = import_aliases.get(value.value.id, value.value.id)
                if "environ" in resolved:
                    return TaintSourceKind.ENVIRONMENT_VARIABLE

        elif isinstance(value, ast.Call):
            func = value.func
            if isinstance(func, ast.Attribute):
                receiver = _resolve_name(func.value, import_aliases)
                recv_base = receiver.split(".")[-1] if receiver else ""
                # os.getenv("X")
                if (recv_base == "os" or receiver == "os") and func.attr == "getenv":
                    return TaintSourceKind.ENVIRONMENT_VARIABLE
                # os.environ.get("X")
                if func.attr == "get" and isinstance(func.value, ast.Attribute):
                    inner = func.value
                    r2 = _resolve_name(inner.value, import_aliases)
                    r2_base = r2.split(".")[-1] if r2 else ""
                    if (r2_base == "os" or r2 == "os") and inner.attr == "environ":
                        return TaintSourceKind.ENVIRONMENT_VARIABLE
                    if inner.attr == "environ":
                        return TaintSourceKind.ENVIRONMENT_VARIABLE
            elif isinstance(func, ast.Name):
                resolved = import_aliases.get(func.id, func.id)
                if resolved == "os.getenv" or func.id == "getenv":
                    return TaintSourceKind.ENVIRONMENT_VARIABLE

        return None

    def _check_argv_source(
        self, value: ast.expr, import_aliases: Dict[str, str]
    ) -> Optional[TaintSourceKind]:
        """Detect sys.argv[N] accesses."""
        if isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Attribute):
                attr = value.value
                receiver = _resolve_name(attr.value, import_aliases)
                if receiver == "sys" and attr.attr == "argv":
                    return TaintSourceKind.CLI_ARGUMENT
            elif isinstance(value.value, ast.Name):
                resolved = import_aliases.get(value.value.id, value.value.id)
                if "argv" in resolved:
                    return TaintSourceKind.CLI_ARGUMENT
        return None

    def _check_argparse_source(
        self, value: ast.expr, import_aliases: Dict[str, str]
    ) -> bool:
        """Detect args = parser.parse_args() patterns."""
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
            if value.func.attr in _ARGPARSE_ATTRS:
                return True
        return False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _resolve_name(node: ast.expr, import_aliases: Dict[str, str]) -> str:
    """Extract and resolve a name from an AST node using import aliases."""
    if isinstance(node, ast.Name):
        return import_aliases.get(node.id, node.id)
    elif isinstance(node, ast.Attribute):
        prefix = _resolve_name(node.value, import_aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _extract_target_name(targets: list) -> Optional[str]:
    """Extract the first simple Name from an assignment target list."""
    for t in targets:
        if isinstance(t, ast.Name):
            return t.id
        elif isinstance(t, ast.Tuple):
            for elt in t.elts:
                if isinstance(elt, ast.Name):
                    return elt.id
    return None


def _get_line(lines: List[str], line_no: int) -> str:
    """Return source line (1-indexed), stripped."""
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip()
    return ""


def _build_import_aliases(tree: ast.AST) -> Dict[str, str]:
    """Build a map of local alias → fully-qualified module/name from import statements."""
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
