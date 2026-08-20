"""
Unit & Integration Tests for M10 Semantic Code Intelligence.
"""

import ast
import os
import pytest

os.environ["AGENTOS_MOCK_LLM"] = "1"

from agentos_swe.semantic import (
    PythonSemanticResolver,
    SemanticCategory,
    ExceptionIntent,
    ModuleRole,
)
from agentos_swe.agents.performance_agent import PerformanceAgent
from agentos_swe.agents.bug_agent import BugAgent
from agentos_swe.agents.architecture_agent import ArchitectureAgent
from agentos_swe.verification.verification_agent import VerificationAgent
from agentos_swe.verification.strategies import StaticVerificationStrategy
from agentos_swe.context import RepositoryContext, build_repository_context
from agentos_swe.models import Finding, FindingStatus


@pytest.fixture
def resolver():
    return PythonSemanticResolver()


def test_dict_literal_get_resolution(resolver):
    """Test 1: dict literal + .get() resolves to DICT_LOOKUP."""
    code = """
def test():
    job = {"title": "Engineer"}
    return job.get("title")
"""
    tree = ast.parse(code)
    call_node = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_node = node
            break

    res = resolver.resolve_call("test.py", call_node, tree)
    assert res.category == SemanticCategory.DICT_LOOKUP
    assert res.confidence >= 0.90
    assert "dict" in res.resolved_receiver_type


def test_requests_direct_get(resolver):
    """Test 2: import requests; requests.get(url) resolves to HTTP_NETWORK_CALL."""
    code = """
import requests

def fetch():
    return requests.get("https://api.example.com")
"""
    tree = ast.parse(code)
    call_node = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]

    res = resolver.resolve_call("test.py", call_node, tree)
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert res.confidence >= 0.95
    assert "requests.get" in res.resolved_symbol


def test_requests_alias_get(resolver):
    """Test 3: import requests as req; req.get(url) resolves to HTTP_NETWORK_CALL."""
    code = """
import requests as req

def fetch():
    return req.get("https://api.example.com")
"""
    tree = ast.parse(code)
    call_node = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]

    res = resolver.resolve_call("test.py", call_node, tree)
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert res.confidence >= 0.95


def test_from_requests_import_get(resolver):
    """Test 4: from requests import get; get(url) resolves to HTTP_NETWORK_CALL."""
    code = """
from requests import get

def fetch():
    return get("https://api.example.com")
"""
    tree = ast.parse(code)
    call_node = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]

    res = resolver.resolve_call("test.py", call_node, tree)
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert res.confidence >= 0.95


def test_intentional_parser_fallback(resolver):
    """Test 5: Intentional parser fallback returns INTENTIONAL_FALLBACK."""
    code = """
def parse_data(raw):
    try:
        return json.loads(raw)
    except Exception:
        return {"default": True}
"""
    tree = ast.parse(code)
    handler = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]

    res = resolver.analyze_exception_block("test.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK
    assert res.has_fallback_value is True


def test_optional_import_fallback(resolver):
    """Test 6: Optional package import returns INTENTIONAL_FALLBACK."""
    code = """
try:
    import dotenv
except ImportError:
    pass
"""
    tree = ast.parse(code)
    handler = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]

    res = resolver.analyze_exception_block("test.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK


def test_true_swallowed_exception(resolver):
    """Test 7: True swallowed exception returns POSSIBLE_ERROR_SWALLOW."""
    code = """
def process():
    try:
        do_critical_work()
    except Exception:
        pass
"""
    tree = ast.parse(code)
    handler = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]

    res = resolver.analyze_exception_block("test.py", handler, tree)
    assert res.intent == ExceptionIntent.POSSIBLE_ERROR_SWALLOW


def test_entrypoint_launcher_detection(resolver, tmp_path):
    """Test 8: main.py launcher returns ENTRYPOINT_LAUNCHER."""
    main_file = tmp_path / "main.py"
    main_file.write_text("""
import sys
import os

if __name__ == "__main__":
    print("Launching application")
""")
    res = resolver.analyze_module_role(str(main_file))
    assert res.role == ModuleRole.ENTRYPOINT_LAUNCHER


def test_performance_agent_ignores_dict_get(tmp_path):
    """Test 9: PerformanceAgent ignores job.get('title') inside loops."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    py_file = repo_dir / "worker.py"
    py_file.write_text("""
def process(jobs):
    titles = []
    for job in jobs:
        titles.append(job.get("title"))
    return titles
""")
    context = build_repository_context(str(repo_dir))
    agent = PerformanceAgent()
    findings = agent.investigate(context)

    # Should find ZERO loop I/O findings on job.get()
    assert len(findings) == 0


def test_unknown_object_get_not_classified_as_network(resolver):
    """Test 10: Unknown custom object .get() resolves to UNKNOWN, not NETWORK_IO."""
    code = """
def handle(custom_obj):
    return custom_obj.get("value")
"""
    tree = ast.parse(code)
    call_node = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]

    res = resolver.resolve_call("test.py", call_node, tree)
    assert res.category == SemanticCategory.UNKNOWN
    assert res.category != SemanticCategory.HTTP_NETWORK_CALL


def test_multistage_json_parser_fallback(resolver):
    """M10.1 Test 1: Multi-stage JSON parser (loads -> regex -> substring -> raise) returns INTENTIONAL_FALLBACK."""
    code = """
import json
import re

def parse_json_response(text: str) -> dict:
    if not text:
        raise ValueError("Empty response")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fenced:
        return json.loads(fenced.group(1))

    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return json.loads(text[start : end + 1])

    raise ValueError("Could not parse JSON")
"""
    tree = ast.parse(code)
    handler = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]

    res = resolver.analyze_exception_block("test.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK
    assert res.confidence >= 0.90


def test_multistage_parser_chain_fallback(resolver):
    """M10.1 Test 2: Multiple parser try-chain followed by final exception returns INTENTIONAL_FALLBACK."""
    code = """
def parse(data):
    try:
        return parser_a(data)
    except ParseError:
        pass

    try:
        return parser_b(data)
    except ParseError:
        pass

    raise ValueError("Unable to parse data using any strategy")
"""
    tree = ast.parse(code)
    handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)]

    res1 = resolver.analyze_exception_block("test.py", handlers[0], tree)
    res2 = resolver.analyze_exception_block("test.py", handlers[1], tree)

    assert res1.intent == ExceptionIntent.INTENTIONAL_FALLBACK
    assert res2.intent == ExceptionIntent.INTENTIONAL_FALLBACK


def test_primary_fails_alternate_succeeds(resolver):
    """M10.1 Test 3: Primary fails, alternate operation succeeds returns INTENTIONAL_FALLBACK."""
    code = """
def fetch_config(key):
    try:
        return primary_vault_fetch(key)
    except VaultError:
        pass

    fallback_val = env_fallback_fetch(key)
    if fallback_val:
        return fallback_val

    return None
"""
    tree = ast.parse(code)
    handler = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]

    res = resolver.analyze_exception_block("test.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK

