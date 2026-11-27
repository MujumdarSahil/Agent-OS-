"""Sandboxed expressions (2.3, MOCK): no private/dunder access, no calls, no globals, label = join of refs."""

import pathlib

import pytest

from agentos.flows.expressions import ExpressionError, evaluate, label_of, references, render, validate
from agentos.flows.labels import Label

CTX = {"fetch": {"status": 200, "body": "hello world"}, "hook": {"payload": {"priority": "high"}}}
LABELS = {
    "fetch": {"status": Label.untrusted(sources={"fetch"}), "body": Label.untrusted(sources={"fetch"})},
    "hook": {"payload": Label.untrusted(sources={"hook"})},
    "cfg": {"limit": Label.trusted(sources={"cfg"})},
}


def test_basic_evaluation_and_render():
    assert evaluate("nodes.fetch.status == 200", CTX) is True
    assert evaluate("nodes.hook.payload.priority == 'high' and 'world' in nodes.fetch.body", CTX) is True
    assert render("Status {{ nodes.fetch.status }}: {{ nodes.fetch.body | upper }}", CTX) == "Status 200: HELLO WORLD"


@pytest.mark.parametrize("expr", [
    "nodes.fetch.__class__",
    "nodes.fetch.body.__class__.__mro__",
    "nodes.fetch._private",
    "nodes['fetch']['__class__']",
    "nodes.fetch.body['__len__']",
])
def test_private_and_dunder_access_blocked(expr):
    with pytest.raises(ExpressionError):
        evaluate(expr, CTX)


@pytest.mark.parametrize("expr", [
    "nodes.fetch.body.upper()",
    "nodes.fetch.body.format(1)",
    "range(10)",
    "lipsum()",
    "cycler(1, 2)",
])
def test_calls_and_globals_blocked(expr):
    with pytest.raises(ExpressionError):
        evaluate(expr, CTX)


@pytest.mark.parametrize("expr", ["config", "self", "request.environ", "x + 1"])
def test_only_nodes_variable_allowed(expr):
    with pytest.raises(ExpressionError, match="only 'nodes'"):
        evaluate(expr, CTX)


def test_length_limit_and_syntax_error():
    with pytest.raises(ExpressionError, match="longer"):
        evaluate("1 + " * 1000 + "1", CTX)
    with pytest.raises(ExpressionError, match="syntax"):
        evaluate("nodes.fetch.status ==", CTX)


def test_references_and_label_join():
    assert references("nodes.fetch.status == 200 and nodes.cfg.limit > 1") == {("fetch", "status"), ("cfg", "limit")}
    assert label_of("nodes.cfg.limit > 1", LABELS).integrity == "trusted"
    lbl = label_of("nodes.cfg.limit > 1 and nodes.hook.payload.priority == 'high'", LABELS)
    assert lbl.integrity == "untrusted" and {"hook", "cfg"} <= set(lbl.sources)
    assert label_of("1 == 1", LABELS).integrity == "trusted"


def test_dynamic_subscript_is_conservative():
    lbl = label_of("nodes[nodes.cfg.limit].x", LABELS)
    assert lbl.integrity == "untrusted"  # unresolved node id joins all nodes


def test_validate_rejects_non_upstream_reference():
    with pytest.raises(ExpressionError, match="not upstream"):
        validate("nodes.later.x == 1", upstream={"fetch"})


@pytest.mark.parametrize("expr", [
    "(nodes.fetch.body ~ 'x') * 200000000",
    "9 ** 9 ** 9",
    "2 ** 65",
    "10 ** 10 * 10 ** 10",
    "[1, 2] * 100000",
    "'a' ** 2",
])
def test_resource_limits_rejected_quickly(expr):
    import time

    start = time.perf_counter()
    with pytest.raises(ExpressionError):
        evaluate(expr, CTX)
    assert time.perf_counter() - start < 1.0


def test_concat_capped():
    big = {"big": {"s": "y" * 60_000}}
    with pytest.raises(ExpressionError):
        render("{{ nodes.big.s ~ nodes.big.s }}", big)
    with pytest.raises(ExpressionError):
        evaluate("nodes.big.s ~ nodes.big.s", big)
    assert len(render("{{ nodes.big.s ~ '!' }}", big)) == 60_001


def test_normal_arithmetic_still_works():
    assert evaluate("3 * 4 + 2 ** 10", CTX) == 1036
    assert evaluate("nodes.fetch.status * 2 == 400", CTX) is True
    assert evaluate("'ab' * 3", CTX) == "ababab"
    assert evaluate("2 ** 64", CTX) == 2**64
    assert evaluate("nodes.fetch.body ~ '!'", CTX) == "hello world!"


def test_template_statements_rejected():
    with pytest.raises(ExpressionError, match="statements"):
        render("{% for i in nodes.fetch.body %}{{ i }}{% endfor %}", CTX)


def test_module_never_uses_eval():
    src = pathlib.Path(__import__("agentos.flows.expressions", fromlist=["x"]).__file__).read_text(encoding="utf-8")
    assert "eval(" not in src.replace("evaluate(", "") and "exec(" not in src
