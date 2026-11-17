"""
Sandboxed expressions over upstream node outputs (sub-milestone 2.3).

- Jinja2 SandboxedEnvironment; additionally blocks every attribute/item starting with "_" (private
  and dunder names) and ALL method/function calls; no globals (no range/lipsum/cycler/...).
- The only variable is ``nodes``: ``{{ nodes.<node_id>.<field> }}`` (or ``nodes["id"]["field"]``).
- Never uses Python eval/exec.
- An expression's security label is the join of the labels of the values it references. A
  reference that cannot be resolved statically (dynamic subscript, bare ``nodes``) conservatively
  joins all labels of that node (or of all nodes).
"""

from __future__ import annotations

from typing import Any

from jinja2 import StrictUndefined, TemplateSyntaxError, Undefined, UndefinedError
from jinja2 import nodes as jn
from jinja2.compiler import CodeGenerator
from jinja2.meta import find_undeclared_variables
from jinja2.sandbox import SandboxedEnvironment, SecurityError

from agentos.flows.labels import Label

MAX_SOURCE_LEN = 2000
MAX_OUTPUT_LEN = 100_000
ROOT = "nodes"
ANY = "*"  # dynamic / unresolved reference


class ExpressionError(ValueError):
    """Invalid, unsafe or failing expression."""


MAX_NUMBER = 10**18  # largest magnitude a multiplication may produce
MAX_EXPONENT = 64
MAX_POW_BASE = 10**6  # "small number" bases only


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


class _CappedCodeGenerator(CodeGenerator):
    """Routes `~` concatenation through environment.checked_concat (size-checked before joining)."""

    def visit_Concat(self, node: jn.Concat, frame: Any) -> None:
        self.write("environment.checked_concat((")
        for arg in node.nodes:
            self.visit(arg, frame)
            self.write(", ")
        self.write("))")


class _StrictSandbox(SandboxedEnvironment):
    code_generator_class = _CappedCodeGenerator
    # Resource limits: these operators are checked before computing (and never constant-folded).
    intercepted_binops = frozenset(["*", "**"])

    def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
        if operator == "**":
            if not (_is_number(left) and _is_number(right)):
                raise SecurityError("'**' needs numbers")
            if abs(right) > MAX_EXPONENT or abs(left) > MAX_POW_BASE:
                raise SecurityError(f"'**' limited to |base| <= {MAX_POW_BASE} and |exponent| <= {MAX_EXPONENT}")
        elif operator == "*":
            if _is_number(left) and _is_number(right):
                if left and right and abs(left) > MAX_NUMBER / abs(right):
                    raise SecurityError(f"'*' result would exceed {MAX_NUMBER}")
            else:
                seq, count = (left, right) if isinstance(left, (str, list, tuple)) else (right, left)
                if isinstance(seq, (str, list, tuple)) and isinstance(count, int) and not isinstance(count, bool):
                    if len(seq) * max(count, 0) > MAX_OUTPUT_LEN:
                        raise SecurityError(f"'*' result would exceed {MAX_OUTPUT_LEN} characters/items")
        return super().call_binop(context, operator, left, right)

    def checked_concat(self, parts: tuple) -> str:
        strs = [p if isinstance(p, str) else str(p) for p in parts]
        if sum(len(s) for s in strs) > MAX_OUTPUT_LEN:
            raise SecurityError(f"'~' result would exceed {MAX_OUTPUT_LEN} characters")
        return "".join(strs)
    def is_safe_attribute(self, obj: Any, attr: Any, value: Any) -> bool:
        if isinstance(attr, str) and attr.startswith("_"):
            return False
        return super().is_safe_attribute(obj, attr, value)

    def is_safe_callable(self, obj: Any) -> bool:
        return False  # no method or function calls at all

    def getitem(self, obj: Any, argument: Any) -> Any:
        if isinstance(argument, str) and argument.startswith("_"):
            raise SecurityError(f"access to {argument!r} is not allowed")
        return super().getitem(obj, argument)

    def unsafe_undefined(self, obj: Any, attribute: Any) -> Any:
        raise SecurityError(f"access to attribute {attribute!r} is not allowed")


_ENV = _StrictSandbox(undefined=StrictUndefined, autoescape=False)
_ENV.globals.clear()


def _parse(source: str, template: bool) -> jn.Template:
    if not isinstance(source, str):
        raise ExpressionError("expression must be a string")
    if len(source) > MAX_SOURCE_LEN:
        raise ExpressionError(f"expression longer than {MAX_SOURCE_LEN} characters")
    try:
        ast = _ENV.parse(source if template else "{{ (" + source + ") }}")
    except TemplateSyntaxError as err:
        raise ExpressionError(f"syntax error: {err.message}") from err
    # Templates may contain only text and {{ ... }} placeholders (no {% %} statements).
    for stmt in ast.body:
        if not isinstance(stmt, jn.Output):
            raise ExpressionError("only {{ ... }} placeholders are allowed; {% %} statements are not")
    free = find_undeclared_variables(ast) - {ROOT}
    names = {n.name for n in ast.find_all(jn.Name)} - {ROOT}
    if free or names:
        raise ExpressionError(f"unknown variable(s) {sorted(free | names)}; only '{ROOT}' is available")
    return ast


def _chain(node: jn.Node) -> list[str] | None:
    """Path of a nodes.<a>.<b> chain, using ANY for dynamic parts; None if not rooted at ``nodes``."""
    if isinstance(node, jn.Name):
        return [] if node.name == ROOT else None
    if isinstance(node, jn.Getattr):
        base = _chain(node.node)
        return None if base is None else base + [node.attr]
    if isinstance(node, jn.Getitem):
        base = _chain(node.node)
        if base is None:
            return None
        arg = node.arg
        key = arg.value if isinstance(arg, jn.Const) and isinstance(arg.value, str) else ANY
        return base + [key]
    return None


def references(source: str, template: bool = False) -> set[tuple[str, str]]:
    """(node_id, field) pairs referenced; ANY marks an unresolved part."""
    ast = _parse(source, template)
    refs: set[tuple[str, str]] = set()

    def walk(n: jn.Node) -> None:
        path = _chain(n)
        if path is not None:
            node_id = path[0] if len(path) >= 1 else ANY
            field = path[1] if len(path) >= 2 else ANY
            refs.add((node_id, field))
            if isinstance(n, jn.Getitem):
                walk(n.arg)
            return
        for child in n.iter_child_nodes():
            walk(child)

    walk(ast)
    return refs


def validate(source: str, template: bool = False, upstream: set[str] | None = None) -> set[tuple[str, str]]:
    refs = references(source, template)
    if upstream is not None:
        unknown = sorted({nid for nid, _ in refs if nid != ANY and nid not in upstream})
        if unknown:
            raise ExpressionError(f"expression references node(s) {unknown} that are not upstream")
    return refs


def label_of(source: str, labels: dict[str, dict[str, Label]], template: bool = False) -> Label:
    """Join of the labels of every referenced value (trusted if nothing is referenced)."""
    parts: list[Label] = []
    for nid, field in references(source, template):
        if nid == ANY:
            parts.extend(lbl for node_lbls in labels.values() for lbl in node_lbls.values())
            if not labels:
                parts.append(Label.untrusted())
            continue
        node_lbls = labels.get(nid)
        if not node_lbls:
            parts.append(Label.untrusted(sources={nid}))
            continue
        if field == ANY:
            parts.extend(node_lbls.values())
        elif field in node_lbls:
            parts.append(node_lbls[field])
        elif "*" in node_lbls:
            parts.append(node_lbls["*"])
        else:
            parts.extend(node_lbls.values())
    return Label.join_all(parts, default=Label.trusted())


def evaluate(source: str, context: dict[str, dict[str, Any]]) -> Any:
    """Evaluate an expression against upstream outputs (``nodes``)."""
    _parse(source, template=False)
    try:
        fn = _ENV.compile_expression(source, undefined_to_none=False)
        result = fn(**{ROOT: context})
    except (SecurityError, UndefinedError, TypeError, ValueError, ZeroDivisionError) as err:
        raise ExpressionError(f"expression failed: {err}") from err
    if isinstance(result, Undefined):
        raise ExpressionError("expression refers to a value that does not exist")
    return result


def render(source: str, context: dict[str, dict[str, Any]]) -> str:
    """Render a template string (``{{ ... }}`` placeholders) against upstream outputs."""
    _parse(source, template=True)
    try:
        out = _ENV.from_string(source).render(**{ROOT: context})
    except (SecurityError, UndefinedError, TypeError, ValueError, ZeroDivisionError) as err:
        raise ExpressionError(f"template failed: {err}") from err
    if len(out) > MAX_OUTPUT_LEN:
        raise ExpressionError(f"template output longer than {MAX_OUTPUT_LEN} characters")
    return out
