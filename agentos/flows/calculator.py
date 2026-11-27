"""Safe arithmetic for the `calculator` tool (3.1, Part 0b).

Whitelist over the Python AST; never eval/exec. Allowed: int/float literals, + - * / // % **, unary + -,
parentheses, and calls to a fixed set of math functions by bare name. Everything else is refused: names
other than those functions, attribute access, subscripts, strings, comprehensions, lambdas, keywords.
Limits are the ones agentos/flows/expressions.py uses: source length, |exponent| and pow base, magnitude.
The result is a plain number; as a tool output it is UNTRUSTED (tool_output_label), like every tool output.
"""

from __future__ import annotations

import ast
import math
import operator
from typing import Any, Callable

from agentos.flows.expressions import MAX_EXPONENT, MAX_NUMBER, MAX_POW_BASE, MAX_SOURCE_LEN

MAX_NODES = 200
MAX_RESULT = 10**15
FUNCTIONS: dict[str, Callable[..., Any]] = {
    "abs": abs, "round": round, "min": min, "max": max,
    "sqrt": math.sqrt, "floor": math.floor, "ceil": math.ceil, "log": math.log, "exp": math.exp,
}
_BINOPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
}
_UNARY: dict[type, Callable[[Any], Any]] = {ast.UAdd: operator.pos, ast.USub: operator.neg}


class CalculatorError(ValueError):
    """Invalid, unsafe or out-of-range expression."""


def _num(v: Any) -> int | float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise CalculatorError("only numbers are allowed")
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        raise CalculatorError("result is not a finite number")
    if abs(v) > MAX_NUMBER:
        raise CalculatorError("number too large")
    return v


def _eval(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        return _num(node.value)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _num(_UNARY[type(node.op)](_eval(node.operand)))
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
        left, right = _eval(node.left), _eval(node.right)
        if isinstance(node.op, ast.Pow):
            if abs(right) > MAX_EXPONENT or (abs(right) > 4 and abs(left) > MAX_POW_BASE):
                raise CalculatorError("exponent too large")
        if isinstance(node.op, ast.Mult) and abs(left) * abs(right) > MAX_NUMBER:
            raise CalculatorError("number too large")
        try:
            return _num(_BINOPS[type(node.op)](left, right))
        except CalculatorError:
            raise
        except ZeroDivisionError:
            raise CalculatorError("division by zero") from None
        except (OverflowError, ValueError) as e:
            raise CalculatorError(f"arithmetic error: {type(e).__name__}") from None
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in FUNCTIONS:
            raise CalculatorError("only these functions are allowed: " + ", ".join(sorted(FUNCTIONS)))
        if node.keywords or any(isinstance(a, ast.Starred) for a in node.args):
            raise CalculatorError("keyword or starred arguments are not allowed")
        args = [_eval(a) for a in node.args]
        try:
            return _num(FUNCTIONS[node.func.id](*args))
        except CalculatorError:
            raise
        except (TypeError, ValueError, OverflowError) as e:
            raise CalculatorError(f"{node.func.id}: {type(e).__name__}") from None
    if isinstance(node, ast.Name):
        raise CalculatorError("names are not allowed")
    if isinstance(node, ast.Attribute):
        raise CalculatorError("attribute access is not allowed")
    raise CalculatorError(f"{type(node).__name__} is not allowed")


def calculator_output_labels(node_id: str, inbound: Any) -> dict[str, Any]:
    """Shared by the analyzer and the engine: UNTRUSTED, the inbound confidentiality, inbound sources + node."""
    from agentos.flows.labels import Label

    lbl = Label.untrusted(confidentiality=inbound.confidentiality, sources=frozenset(inbound.sources) | {node_id})
    return {"result": lbl, "*": lbl}


def evaluate(expression: Any) -> int | float:
    """Evaluate an arithmetic expression safely, or raise CalculatorError."""
    if not isinstance(expression, str):
        raise CalculatorError("expression must be a string")
    if len(expression) > MAX_SOURCE_LEN:
        raise CalculatorError("expression too long")
    try:
        tree = ast.parse(expression.strip(), mode="eval")
    except SyntaxError:
        raise CalculatorError("not a valid arithmetic expression") from None
    if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
        raise CalculatorError("expression too complex")
    result = _eval(tree)
    if abs(result) > MAX_RESULT:
        raise CalculatorError("result too large")
    return result
