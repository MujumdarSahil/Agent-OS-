"""
PythonSemanticResolver - Lightweight, deterministic Python AST semantic analysis for AgentOS-SWE (M10).
"""

import ast
import os
import logging
from typing import Dict, Any, Optional, List, Set, Tuple

from agentos_swe.semantic.base import (
    SemanticCodeProvider,
    SemanticCategory,
    SemanticCallResult,
    ExceptionIntent,
    ExceptionAnalysisResult,
    ModuleRole,
    ModuleRoleResult,
)

logger = logging.getLogger(__name__)


class PythonSemanticResolver(SemanticCodeProvider):
    """
    Deterministic Python AST resolver for symbol, type, call, exception intent, and module role.
    """

    KNOWN_NETWORK_MODULES = {"requests", "httpx", "urllib", "urllib.request", "aiohttp"}
    KNOWN_FILE_IO_FUNCS = {"open", "read_text", "write_text", "read_bytes", "write_bytes"}
    KNOWN_DB_FUNCS = {"execute", "executemany", "query", "find", "find_one", "aggregate"}

    # Receiver variable names commonly used for dict lookups in Python codebases
    DICT_VAR_NAMES = {
        "job", "data", "row", "item", "config", "params", "headers", "payload",
        "kwargs", "record", "event", "doc", "metadata", "props", "ctx", "options",
        "query_params", "form", "json_data", "info", "result", "d", "mapping",
        "context", "env", "node", "edge", "attributes", "dict_val", "obj_dict"
    }

    def resolve_call(
        self,
        file_path: str,
        call_node: ast.Call,
        context_tree: Optional[ast.AST] = None
    ) -> SemanticCallResult:
        """
        Resolve call node to semantic category and symbol.
        """
        func = call_node.func
        fn_name = ""
        receiver_name = ""

        # Extract function name and receiver
        if isinstance(func, ast.Name):
            fn_name = func.id
        elif isinstance(func, ast.Attribute):
            fn_name = func.attr
            if isinstance(func.value, ast.Name):
                receiver_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                receiver_name = f"{func.value.value.id if isinstance(func.value.value, ast.Name) else ''}.{func.value.attr}"

        # Build import alias mapping if context_tree provided
        import_map = self._build_import_map(context_tree) if context_tree else {}

        # 1. Direct function call resolution (e.g., open(), get() imported from requests)
        resolved_func_symbol = import_map.get(fn_name, fn_name)
        if resolved_func_symbol in ("requests.get", "requests.post", "requests.put", "requests.delete",
                                    "httpx.get", "httpx.post", "urllib.request.urlopen"):
            return SemanticCallResult(
                category=SemanticCategory.HTTP_NETWORK_CALL,
                confidence=0.98,
                resolved_symbol=resolved_func_symbol,
                reason=f"Function '{fn_name}' resolved to imported network API '{resolved_func_symbol}'."
            )

        if fn_name == "open" and not receiver_name:
            return SemanticCallResult(
                category=SemanticCategory.FILE_IO_CALL,
                confidence=0.95,
                resolved_symbol="builtins.open",
                reason="Built-in 'open' function call."
            )

        # 2. Attribute call resolution (e.g., req.get(), data.get(), path.read_text())
        resolved_receiver = import_map.get(receiver_name, receiver_name)

        if resolved_receiver in self.KNOWN_NETWORK_MODULES or resolved_receiver.startswith("requests.") or resolved_receiver.startswith("httpx."):
            if fn_name in ("get", "post", "put", "delete", "request", "patch", "fetch"):
                return SemanticCallResult(
                    category=SemanticCategory.HTTP_NETWORK_CALL,
                    confidence=0.99,
                    resolved_symbol=f"{resolved_receiver}.{fn_name}",
                    resolved_receiver_type=resolved_receiver,
                    reason=f"Receiver '{receiver_name}' resolves to HTTP module/client '{resolved_receiver}'."
                )

        if fn_name in self.KNOWN_FILE_IO_FUNCS and receiver_name in ("Path", "file", "f", "fp", "file_obj"):
            return SemanticCallResult(
                category=SemanticCategory.FILE_IO_CALL,
                confidence=0.95,
                resolved_symbol=f"File.{fn_name}",
                resolved_receiver_type="File/Path",
                reason=f"Call to '{fn_name}' on File/Path object."
            )

        if fn_name in self.KNOWN_DB_FUNCS and receiver_name in ("cursor", "db", "session", "conn", "connection", "collection"):
            return SemanticCallResult(
                category=SemanticCategory.DATABASE_QUERY,
                confidence=0.92,
                resolved_symbol=f"DB.{fn_name}",
                resolved_receiver_type="Database",
                reason=f"Call to '{fn_name}' on Database/Cursor object."
            )

        # 3. Handle '.get' method calls specifically (The key false-positive resolution)
        if fn_name == "get":
            # Check receiver type from local scope in context_tree
            inferred_type = self._infer_receiver_type(receiver_name, call_node, context_tree)
            if inferred_type in ("dict", "Mapping", "dict_literal"):
                return SemanticCallResult(
                    category=SemanticCategory.DICT_LOOKUP,
                    confidence=0.98,
                    resolved_symbol="dict.get",
                    resolved_receiver_type="dict",
                    reason=f"Receiver variable '{receiver_name}' statically inferred as dictionary ({inferred_type})."
                )

            # Heuristic check for common dict variable names
            if receiver_name in self.DICT_VAR_NAMES or receiver_name.endswith("_dict") or receiver_name.endswith("_map"):
                return SemanticCallResult(
                    category=SemanticCategory.DICT_LOOKUP,
                    confidence=0.90,
                    resolved_symbol="dict.get",
                    resolved_receiver_type="dict (heuristic)",
                    reason=f"Receiver variable '{receiver_name}' follows dictionary naming pattern."
                )

            # Ambiguous receiver call to .get() where type is unknown
            return SemanticCallResult(
                category=SemanticCategory.UNKNOWN,
                confidence=0.40,
                resolved_symbol=f"{receiver_name or 'obj'}.get",
                resolved_receiver_type="unknown",
                reason=f"Receiver variable '{receiver_name}' type cannot be resolved; '.get' method call is ambiguous."
            )

        return SemanticCallResult(
            category=SemanticCategory.UNKNOWN,
            confidence=0.30,
            resolved_symbol=f"{receiver_name}.{fn_name}" if receiver_name else fn_name,
            reason="Unrecognized call target."
        )

    def analyze_exception_block(
        self,
        file_path: str,
        handler_node: ast.ExceptHandler,
        context_tree: Optional[ast.AST] = None
    ) -> ExceptionAnalysisResult:
        """
        Analyze exception handler for intentional fallback vs swallowed bug.
        """
        caught_types: List[str] = []
        if handler_node.type:
            if isinstance(handler_node.type, ast.Name):
                caught_types.append(handler_node.type.id)
            elif isinstance(handler_node.type, ast.Tuple):
                for elt in handler_node.type.elts:
                    if isinstance(elt, ast.Name):
                        caught_types.append(elt.id)
                    elif isinstance(elt, ast.Attribute):
                        caught_types.append(elt.attr)
            elif isinstance(handler_node.type, ast.Attribute):
                caught_types.append(handler_node.type.attr)

        # 0. Check for bare except: (no exception type specified)
        if not handler_node.type:
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.POSSIBLE_ERROR_SWALLOW,
                confidence=0.90,
                reason="Bare 'except:' handler catches all system exceptions and interrupts without type qualification.",
                caught_exceptions=["bare"],
                has_fallback_value=False,
            )

        # 1. Check for ImportError / ModuleNotFoundError (Optional dependency fallback)
        if any(t in ("ImportError", "ModuleNotFoundError") for t in caught_types):
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.INTENTIONAL_FALLBACK,
                confidence=0.99,
                reason="Import error handler used for optional module dependency fallback.",
                caught_exceptions=caught_types,
                has_fallback_value=True,
            )

        # Inspect handler body statements
        body = handler_node.body
        has_return = any(isinstance(stmt, ast.Return) for stmt in body)
        has_assign = any(isinstance(stmt, (ast.Assign, ast.AugAssign)) for stmt in body)
        has_logging = False

        for stmt in body:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                fn_str = ""
                if isinstance(call.func, ast.Name):
                    fn_str = call.func.id
                elif isinstance(call.func, ast.Attribute):
                    fn_str = call.func.attr
                if fn_str in ("info", "warning", "error", "exception", "warn", "print", "log", "debug"):
                    has_logging = True

        # 2. If handler body has return value or assignment or logging, it's an intentional fallback
        if has_return or has_assign or has_logging:
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.INTENTIONAL_FALLBACK,
                confidence=0.92,
                reason=f"Exception handler provides explicit fallback behavior ({'return' if has_return else ''} {'assign' if has_assign else ''} {'logging' if has_logging else ''}).",
                caught_exceptions=caught_types,
                has_fallback_value=has_return or has_assign,
            )

        # 3. Check post-try control flow for multi-stage fallback patterns
        if context_tree:
            control_flow_res = self._analyze_post_try_control_flow(handler_node, context_tree)
            if control_flow_res:
                return control_flow_res

        # 4. Pure `pass` body with generic/bare Exception and no surrounding fallback -> POSSIBLE_ERROR_SWALLOW
        is_generic = not caught_types or any(t in ("Exception", "BaseException") for t in caught_types)
        if len(body) == 1 and isinstance(body[0], ast.Pass) and is_generic:
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.POSSIBLE_ERROR_SWALLOW,
                confidence=0.85,
                reason="Generic exception handler containing only 'pass' without explicit fallback or logging.",
                caught_exceptions=caught_types or ["bare"],
                has_fallback_value=False,
            )

        return ExceptionAnalysisResult(
            intent=ExceptionIntent.UNKNOWN,
            confidence=0.40,
            reason="Unable to determine intent of exception handler.",
            caught_exceptions=caught_types,
        )

    def analyze_module_role(
        self,
        file_path: str,
        context: Optional[Any] = None
    ) -> ModuleRoleResult:
        """
        Determine whether module acts as entrypoint launcher, test harness, or library module.
        """
        base_name = os.path.basename(file_path).lower()
        rel_path = file_path.lower().replace("\\", "/")

        # 1. Direct file/directory name & location conventions for TEST_HARNESS
        is_test_dir = rel_path.startswith("tests/") or "/tests/" in rel_path or rel_path.startswith("testing/") or "/testing/" in rel_path or rel_path.startswith("integration/") or "/integration/" in rel_path or rel_path.startswith("e2e/") or "/e2e/" in rel_path
        is_test_filename = base_name.startswith("test_") or base_name.endswith("_test.py") or base_name.endswith("_spec.py") or base_name in ("conftest.py", "pytest.ini")

        if is_test_dir or is_test_filename:
            return ModuleRoleResult(
                role=ModuleRole.TEST_HARNESS,
                confidence=0.95,
                reason=f"Module '{file_path}' matches test harness location or naming convention ({'test dir' if is_test_dir else ''} {'test filename' if is_test_filename else ''}).",
                language="python",
                provider="PythonSemanticResolver",
                rule="test_harness_convention",
            )

        # Direct file/directory name conventions for launchers
        if base_name in ("main.py", "app.py", "server.py", "streamlit_app.py", "manage.py", "cli.py", "run.py", "launcher.py"):
            return ModuleRoleResult(
                role=ModuleRole.ENTRYPOINT_LAUNCHER,
                confidence=0.95,
                reason=f"Filename '{base_name}' is a standard application entrypoint launcher convention.",
                language="python",
                provider="PythonSemanticResolver",
                rule="entrypoint_launcher_filename",
            )

        if "/scripts/" in rel_path or rel_path.startswith("scripts/"):
            return ModuleRoleResult(
                role=ModuleRole.ENTRYPOINT_LAUNCHER,
                confidence=0.90,
                reason=f"File path '{rel_path}' is located in scripts directory.",
                language="python",
                provider="PythonSemanticResolver",
                rule="scripts_directory",
            )

        # Inspect AST content if file exists
        full_path = file_path
        if context and hasattr(context, "repository_path"):
            full_path = os.path.join(context.repository_path, file_path)

        if os.path.isfile(full_path):
            try:
                content = open(full_path, "r", encoding="utf-8", errors="replace").read()

                # Content-based test harness detection (pytest fixtures, unittest.TestCase, test_ functions, unittest/pytest imports)
                if "import pytest" in content or "import unittest" in content or "from unittest" in content or "@pytest.fixture" in content or "unittest.TestCase" in content or "def test_" in content:
                    return ModuleRoleResult(
                        role=ModuleRole.TEST_HARNESS,
                        confidence=0.92,
                        reason="Module content contains test framework imports, unittest.TestCase, or test functions.",
                        language="python",
                        provider="PythonSemanticResolver",
                        rule="test_harness_content",
                    )

                if '__name__ == "__main__"' in content or "__name__ == '__main__'" in content:
                    return ModuleRoleResult(
                        role=ModuleRole.ENTRYPOINT_LAUNCHER,
                        confidence=0.98,
                        reason="Module contains '__name__ == \"__main__\"' launch block.",
                        language="python",
                        provider="PythonSemanticResolver",
                        rule="main_block",
                    )
                if "FastAPI(" in content or "Flask(" in content or "@click.command" in content or "@app.get(" in content:
                    return ModuleRoleResult(
                        role=ModuleRole.ENTRYPOINT_LAUNCHER,
                        confidence=0.90,
                        reason="Module initializes API server / CLI framework application root.",
                        language="python",
                        provider="PythonSemanticResolver",
                        rule="framework_app_root",
                    )
            except Exception:
                pass

        return ModuleRoleResult(
            role=ModuleRole.LIBRARY_MODULE,
            confidence=0.80,
            reason="Module represents a standard library/component module.",
            language="python",
            provider="PythonSemanticResolver",
            rule="library_module_default",
        )

    # -------------------------------------------------------------------------
    # Helper AST inspection methods
    # -------------------------------------------------------------------------

    def _build_import_map(self, tree: ast.AST) -> Dict[str, str]:
        """Map local import aliases to full canonical symbols."""
        mapping: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    mapping[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    full_symbol = f"{mod}.{alias.name}" if mod else alias.name
                    mapping[local_name] = full_symbol
        return mapping

    def _infer_receiver_type(
        self,
        receiver_name: str,
        call_node: ast.Call,
        tree: Optional[ast.AST]
    ) -> str:
        """Infer variable type from assignments and annotations in tree."""
        if not receiver_name or not tree:
            return "unknown"

        for node in ast.walk(tree):
            # Check typed function arguments: def fn(job: dict)
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    if arg.arg == receiver_name and arg.annotation:
                        if isinstance(arg.annotation, ast.Name) and arg.annotation.id in ("dict", "Dict", "Mapping"):
                            return "dict"

            # Check variable assignments: job = {} or job = dict()
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == receiver_name:
                        value = node.value
                        if isinstance(value, (ast.Dict, ast.DictComp)):
                            return "dict_literal"
                        if isinstance(value, ast.Call):
                            if isinstance(value.func, ast.Name) and value.func.id in ("dict", "Dict"):
                                return "dict"

            # Check annotated assignments: job: dict = ...
            if isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id == receiver_name:
                    if isinstance(node.annotation, ast.Name) and node.annotation.id in ("dict", "Dict", "Mapping"):
                        return "dict"

        return "unknown"

    def _analyze_post_try_control_flow(
        self,
        handler_node: ast.ExceptHandler,
        tree: ast.AST
    ) -> Optional[ExceptionAnalysisResult]:
        """
        Analyze AST statements following a try-except block to detect multi-stage fallback patterns.
        """
        enclosing_body: Optional[List[ast.stmt]] = None
        target_try_index: int = -1

        for parent in ast.walk(tree):
            body = getattr(parent, "body", None)
            if isinstance(body, list):
                for i, stmt in enumerate(body):
                    if isinstance(stmt, ast.Try):
                        if handler_node in stmt.handlers:
                            enclosing_body = body
                            target_try_index = i
                            break
            if enclosing_body is not None:
                break

        if enclosing_body is None or target_try_index == -1:
            return None

        # Check if this try block itself is a secondary or tertiary try block in a try-chain (index > 0)
        is_secondary_try_node = target_try_index > 0

        post_try_stmts = enclosing_body[target_try_index + 1:]

        # Signals
        has_secondary_operation = False
        has_secondary_try = False
        has_return = False
        has_final_raise = False

        for stmt in post_try_stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Try):
                    has_secondary_try = True
                    has_secondary_operation = True
                elif isinstance(node, (ast.Call, ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    has_secondary_operation = True
                elif isinstance(node, ast.Return) and node.value is not None:
                    has_return = True
                elif isinstance(node, ast.Raise) and node.exc is not None:
                    has_final_raise = True

        caught_types = []
        if handler_node.type:
            if isinstance(handler_node.type, ast.Name):
                caught_types.append(handler_node.type.id)
            elif isinstance(handler_node.type, ast.Attribute):
                caught_types.append(handler_node.type.attr)

        # 1. Multi-stage try chain or fallback attempt followed by explicit final raise
        if (has_secondary_operation or is_secondary_try_node) and has_final_raise:
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.INTENTIONAL_FALLBACK,
                confidence=0.95,
                reason="Multi-stage fallback control flow detected: primary try block falls through to secondary attempts followed by explicit final failure raise.",
                caught_exceptions=caught_types,
                has_fallback_value=True,
            )

        # 2. Multi-stage fallback with secondary try block
        if has_secondary_try or (is_secondary_try_node and has_return):
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.INTENTIONAL_FALLBACK,
                confidence=0.92,
                reason="Multi-stage fallback try-chain: exception falls through to secondary try block or final return.",
                caught_exceptions=caught_types,
                has_fallback_value=True,
            )

        # 3. Secondary operation with return path
        if has_secondary_operation and has_return:
            return ExceptionAnalysisResult(
                intent=ExceptionIntent.INTENTIONAL_FALLBACK,
                confidence=0.90,
                reason="Multi-stage fallback control flow: exception handler falls through to alternative processing strategy and return value.",
                caught_exceptions=caught_types,
                has_fallback_value=True,
            )

        return None
