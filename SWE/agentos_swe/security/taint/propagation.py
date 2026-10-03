"""
M12 Taint Analysis — Propagation Tracker.

Tracks how tainted data flows through variable assignments, function arguments,
string concatenation, f-strings, and inter-procedural calls.

Design:
- Intra-procedural: tracks within a single function body
- Inter-procedural (bounded): follows call arguments into function definitions
  up to MAX_TAINT_DEPTH hops
- Does NOT attempt whole-program symbolic execution
"""

import ast
import logging
from typing import List, Dict, Set, Optional, Tuple, FrozenSet

from agentos_swe.security.taint.models import TaintPropagation, TaintSource

logger = logging.getLogger(__name__)

MAX_TAINT_DEPTH = 8


class PropagationTracker:
    """
    Tracks taint propagation through Python AST.

    Given a set of initially tainted variable names, returns the set of
    all variables that become tainted through propagation (with the chain
    of TaintPropagation steps).
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def track(
        self,
        tree: ast.AST,
        lines: List[str],
        initial_tainted: Set[str],
    ) -> Tuple[Set[str], List[TaintPropagation]]:
        """
        Perform intra-procedural taint propagation.

        Returns:
            (all_tainted_vars, propagation_steps)
        """
        tainted: Set[str] = set(initial_tainted)
        steps: List[TaintPropagation] = []
        changed = True
        depth = 0

        while changed and depth < MAX_TAINT_DEPTH:
            changed = False
            depth += 1
            new_steps = self._propagate_once(tree, lines, tainted)
            for step in new_steps:
                if step.to_var not in tainted:
                    tainted.add(step.to_var)
                    steps.append(step)
                    changed = True

        return tainted, steps

    def _propagate_once(
        self,
        tree: ast.AST,
        lines: List[str],
        tainted: Set[str],
    ) -> List[TaintPropagation]:
        """Single propagation pass — returns new propagation steps discovered."""
        steps: List[TaintPropagation] = []

        for node in ast.walk(tree):
            # 1. Direct assignment: y = x (where x is tainted)
            if isinstance(node, ast.Assign):
                step = self._check_direct_assignment(node, lines, tainted)
                if step:
                    steps.append(step)

            # 2. String concatenation: query = "SELECT" + user_input
            if isinstance(node, ast.Assign):
                step = self._check_concat_assignment(node, lines, tainted)
                if step:
                    steps.append(step)

            # 3. F-string: cmd = f"run {user_input}"
            if isinstance(node, ast.Assign):
                step = self._check_fstring_assignment(node, lines, tainted)
                if step:
                    steps.append(step)

            # 4. % format string: cmd = "run %s" % user_input
            if isinstance(node, ast.Assign):
                step = self._check_format_assignment(node, lines, tainted)
                if step:
                    steps.append(step)

            # 5. Dict/list/tuple construction containing tainted values
            if isinstance(node, ast.Assign):
                step = self._check_container_assignment(node, lines, tainted)
                if step:
                    steps.append(step)

        return steps

    # ------------------------------------------------------------------
    # Propagation pattern checkers
    # ------------------------------------------------------------------

    def _check_direct_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        tainted: Set[str],
    ) -> Optional[TaintPropagation]:
        """y = x (direct alias or simple name assignment)."""
        value = node.value
        if not isinstance(value, ast.Name):
            return None
        if value.id not in tainted:
            return None
        target = _extract_target_name(node.targets)
        if not target or target == value.id:
            return None
        line_no = getattr(node, "lineno", 1)
        return TaintPropagation(
            from_var=value.id,
            to_var=target,
            line_no=line_no,
            operation="assignment",
            code_snippet=_get_line(lines, line_no),
            file=self.file_path,
        )

    def _check_concat_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        tainted: Set[str],
    ) -> Optional[TaintPropagation]:
        """query = 'SELECT ' + user_input  or  cmd = prefix + user_input."""
        value = node.value
        if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Add):
            return None
        tainted_operand = _find_tainted_name_in_expr(value, tainted)
        if not tainted_operand:
            return None
        target = _extract_target_name(node.targets)
        if not target:
            return None
        line_no = getattr(node, "lineno", 1)
        return TaintPropagation(
            from_var=tainted_operand,
            to_var=target,
            line_no=line_no,
            operation="concat",
            code_snippet=_get_line(lines, line_no),
            file=self.file_path,
        )

    def _check_fstring_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        tainted: Set[str],
    ) -> Optional[TaintPropagation]:
        """cmd = f'run {user_input}'."""
        value = node.value
        if not isinstance(value, ast.JoinedStr):
            return None
        tainted_operand = _find_tainted_name_in_expr(value, tainted)
        if not tainted_operand:
            return None
        target = _extract_target_name(node.targets)
        if not target:
            return None
        line_no = getattr(node, "lineno", 1)
        return TaintPropagation(
            from_var=tainted_operand,
            to_var=target,
            line_no=line_no,
            operation="fstring",
            code_snippet=_get_line(lines, line_no),
            file=self.file_path,
        )

    def _check_format_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        tainted: Set[str],
    ) -> Optional[TaintPropagation]:
        """cmd = 'run %s' % user_input  or  'query %s' % (var,)."""
        value = node.value
        if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Mod):
            return None
        tainted_operand = _find_tainted_name_in_expr(value.right, tainted)
        if not tainted_operand:
            return None
        target = _extract_target_name(node.targets)
        if not target:
            return None
        line_no = getattr(node, "lineno", 1)
        return TaintPropagation(
            from_var=tainted_operand,
            to_var=target,
            line_no=line_no,
            operation="format_string",
            code_snippet=_get_line(lines, line_no),
            file=self.file_path,
        )

    def _check_container_assignment(
        self,
        node: ast.Assign,
        lines: List[str],
        tainted: Set[str],
    ) -> Optional[TaintPropagation]:
        """data = {"key": user_input} or data = [user_input]."""
        value = node.value
        if not isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return None
        tainted_operand = _find_tainted_name_in_expr(value, tainted)
        if not tainted_operand:
            return None
        target = _extract_target_name(node.targets)
        if not target:
            return None
        line_no = getattr(node, "lineno", 1)
        return TaintPropagation(
            from_var=tainted_operand,
            to_var=target,
            line_no=line_no,
            operation="container_construction",
            code_snippet=_get_line(lines, line_no),
            file=self.file_path,
        )


class InterProceduralTracker:
    """
    Bounded inter-procedural taint propagation.

    Identifies function definitions in the module that receive tainted
    variables as arguments, then propagates taint through those function bodies.

    Depth is bounded by MAX_TAINT_DEPTH to prevent infinite recursion.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._intra = PropagationTracker(file_path)

    def track_inter_procedural(
        self,
        tree: ast.AST,
        lines: List[str],
        tainted_vars: Set[str],
        call_sites: List[Tuple[str, int, List[str]]],  # (func_name, line_no, arg_var_names)
    ) -> Tuple[Set[str], List[TaintPropagation]]:
        """
        Follow taint from call sites into function definitions.

        Args:
            tree: module-level AST
            lines: source lines
            tainted_vars: currently known tainted vars (at call site level)
            call_sites: list of (called_function_name, line_no, positional_arg_names)

        Returns:
            (expanded_tainted_set, additional_propagation_steps)
        """
        all_tainted = set(tainted_vars)
        all_steps: List[TaintPropagation] = []
        func_defs = self._index_function_defs(tree)

        # Process each call site that passes a tainted variable
        for func_name, call_line_no, arg_names in call_sites:
            if func_name not in func_defs:
                continue
            func_node = func_defs[func_name]

            # Map argument names → parameter names
            tainted_in_call = [a for a in arg_names if a in all_tainted]
            if not tainted_in_call:
                continue

            # Map positional args to parameter names
            param_names = [a.arg for a in func_node.args.args]
            param_tainted: Set[str] = set()

            for i, arg_name in enumerate(arg_names):
                if arg_name in all_tainted and i < len(param_names):
                    param_tainted.add(param_names[i])
                    all_steps.append(TaintPropagation(
                        from_var=arg_name,
                        to_var=param_names[i],
                        line_no=call_line_no,
                        operation="argument",
                        code_snippet=_get_line(lines, call_line_no),
                        file=self.file_path,
                        metadata={"into_function": func_name},
                    ))

            if not param_tainted:
                continue

            # Build a sub-tree for just the function body and propagate
            func_body_module = ast.Module(body=func_node.body, type_ignores=[])
            try:
                ast.fix_missing_locations(func_body_module)
            except Exception:
                pass

            new_tainted, new_steps = self._intra.track(
                func_body_module, lines, param_tainted
            )
            all_tainted.update(new_tainted)
            all_steps.extend(new_steps)

        return all_tainted, all_steps

    def extract_call_sites(
        self,
        tree: ast.AST,
        lines: List[str],
    ) -> List[Tuple[str, int, List[str]]]:
        """
        Extract all function calls in the module with their positional argument variable names.
        Returns list of (called_func_name, line_no, [arg_var_names]).
        """
        call_sites: List[Tuple[str, int, List[str]]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                func_name = ""
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr

                if not func_name:
                    continue

                line_no = getattr(node, "lineno", 1)
                arg_names = []
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        arg_names.append(arg.id)
                    elif isinstance(arg, ast.JoinedStr):
                        # f-string arg — extract constituent names
                        names = _find_names_in_expr(arg)
                        arg_names.extend(names if names else ["<fstr>"])
                    elif isinstance(arg, ast.BinOp):
                        names = _find_names_in_expr(arg)
                        arg_names.extend(names if names else ["<binop>"])
                    else:
                        arg_names.append("<expr>")

                call_sites.append((func_name, line_no, arg_names))

        return call_sites

    def _index_function_defs(self, tree: ast.AST) -> Dict[str, ast.FunctionDef]:
        """Build a map of function_name → FunctionDef node for module-level functions."""
        defs: Dict[str, ast.FunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs[node.name] = node
        return defs


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _find_tainted_name_in_expr(expr: ast.expr, tainted: Set[str]) -> Optional[str]:
    """Return the first tainted Name found recursively in an expression."""
    for child in ast.walk(expr):
        if isinstance(child, ast.Name) and child.id in tainted:
            return child.id
    return None


def _find_names_in_expr(expr: ast.expr) -> List[str]:
    """Return all Name ids found in an expression."""
    return [n.id for n in ast.walk(expr) if isinstance(n, ast.Name)]


def _extract_target_name(targets: list) -> Optional[str]:
    for t in targets:
        if isinstance(t, ast.Name):
            return t.id
        elif isinstance(t, ast.Tuple):
            for elt in t.elts:
                if isinstance(elt, ast.Name):
                    return elt.id
    return None


def _get_line(lines: List[str], line_no: int) -> str:
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip()
    return ""
