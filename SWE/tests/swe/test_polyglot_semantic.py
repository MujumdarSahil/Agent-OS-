"""
Focused Polyglot Semantic Intelligence Tests for AgentOS-SWE M11.
Covers Python, JavaScript, TypeScript, Vue, React, API Contracts, and Security audits.
"""

import ast
import os
import pytest

os.environ["AGENTOS_MOCK_LLM"] = "1"

from agentos_swe.semantic import (
    SemanticProviderRegistry,
    PythonSemanticResolver,
    JavaScriptSemanticResolver,
    TypeScriptSemanticResolver,
    VueSemanticResolver,
    ReactSemanticResolver,
    APIContractAnalyzer,
    SemanticCategory,
    ExceptionIntent,
    ModuleRole,
)


@pytest.fixture
def registry():
    return SemanticProviderRegistry()


@pytest.fixture
def contract_analyzer():
    return APIContractAnalyzer()


# === PYTHON TESTS ===

def test_py_dict_get(registry):
    """1. Python dict.get() -> DICT_LOOKUP."""
    res = registry.resolve_call("app.py", ast.parse("d = {}\nx = d.get('a')").body[1].value)
    assert res.category == SemanticCategory.DICT_LOOKUP


def test_py_requests_get(registry):
    """2. Python requests.get() -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("app.py", ast.parse("import requests\nx = requests.get('http://a')").body[1].value)
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL


def test_py_httpx_get(registry):
    """3. Python httpx.get() -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("app.py", ast.parse("import httpx\nx = httpx.get('http://a')").body[1].value)
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL


def test_py_unknown_get(registry):
    """4. Python unknown_obj.get() -> UNKNOWN."""
    res = registry.resolve_call("app.py", ast.parse("x = obj.get('a')").body[0].value)
    assert res.category == SemanticCategory.UNKNOWN


def test_py_intentional_fallback(registry):
    """5. Python intentional parser fallback -> INTENTIONAL_FALLBACK."""
    tree = ast.parse("def f(t):\n try: return json.loads(t)\n except json.JSONDecodeError: pass\n return re.search('a', t)")
    h = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]
    res = registry.analyze_exception_block("app.py", h, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK


def test_py_genuine_swallowed(registry):
    """6. Python generic except Exception: pass -> POSSIBLE_ERROR_SWALLOW."""
    tree = ast.parse("def f():\n try: work()\n except Exception: pass")
    h = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)][0]
    res = registry.analyze_exception_block("app.py", h, tree)
    assert res.intent == ExceptionIntent.POSSIBLE_ERROR_SWALLOW


# === JAVASCRIPT TESTS ===

def test_js_fetch_global(registry):
    """7. JS fetch('/api/jobs') -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("api.js", "fetch('/api/jobs')")
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert res.language == "javascript"


def test_js_axios_get(registry):
    """8. JS axios.get('/users') -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("api.js", "axios.get('/users')")
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL


def test_js_object_get(registry):
    """9. JS job.get('title') -> DICT_LOOKUP (not network I/O)."""
    res = registry.resolve_call("api.js", "const job = {}; job.get('title');")
    assert res.category == SemanticCategory.DICT_LOOKUP
    assert res.category != SemanticCategory.HTTP_NETWORK_CALL


def test_js_client_alias_get(registry):
    """10. JS import client; client.get('/items') -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("api.js", "client.get('/items')")
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL


# === TYPESCRIPT TESTS ===

def test_ts_fetch_call(registry):
    """11. TS fetch('/api/data') -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("client.ts", "fetch('/api/data')")
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert res.language == "typescript"


def test_ts_typed_api_client(registry):
    """12. TS typed apiClient.get<User>('/user') -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("client.ts", "apiClient.get<User>('/user')")
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert "TypedApiClient" in res.resolved_receiver_type


def test_ts_object_lookup(registry):
    """13. TS params.get('id') -> DICT_LOOKUP."""
    res = registry.resolve_call("client.ts", "params.get('id')")
    assert res.category == SemanticCategory.DICT_LOOKUP


# === VUE TESTS ===

def test_vue_fetch_in_script_setup(registry):
    """14. Vue fetch inside <script setup> -> HTTP_NETWORK_CALL."""
    vue_resolver = registry.get_provider_for_file("Component.vue")
    content = "<script setup>\nimport { onMounted } from 'vue'\nonMounted(() => { fetch('/api/vue') })\n</script>"
    analysis = vue_resolver.analyze_component("Component.vue", content)
    assert analysis["has_network_io"] is True
    assert "/api/vue" in analysis["api_endpoints"]


def test_vue_axios_in_component(registry):
    """15. Vue axios call inside component -> Network I/O detected."""
    vue_resolver = registry.get_provider_for_file("UserCard.vue")
    content = "<script>\nexport default {\n methods: { load() { axios.get('/api/users') } }\n}\n</script>"
    analysis = vue_resolver.analyze_component("UserCard.vue", content)
    assert analysis["has_network_io"] is True


def test_vue_component_import(registry):
    """16. Vue SFC component import detection."""
    vue_resolver = registry.get_provider_for_file("App.vue")
    content = "<script setup>\nimport Header from './Header.vue'\n</script>"
    analysis = vue_resolver.analyze_component("App.vue", content)
    assert len(analysis["component_imports"]) == 1
    assert analysis["component_imports"][0][0] == "Header"


# === REACT TESTS ===

def test_react_use_effect_fetch(registry):
    """17. React useEffect with fetch -> HTTP_NETWORK_CALL."""
    res = registry.resolve_call("App.jsx", "useEffect(() => { fetch('/api/react') }, [])")
    assert res.category == SemanticCategory.HTTP_NETWORK_CALL
    assert "useEffect" in res.reason


def test_react_axios_component(registry):
    """18. React component axios call detection."""
    react_resolver = registry.get_provider_for_file("Dashboard.tsx")
    content = "import React, { useEffect } from 'react';\nfunction Dashboard() { useEffect(() => { axios.get('/api/stats') }, []); return <div>Stats</div>; }"
    analysis = react_resolver.analyze_component("Dashboard.tsx", content)
    assert analysis["has_network_io"] is True
    assert "useEffect" in analysis["hooks"]


# === API CONTRACT TESTS ===

def test_api_contract_matching(contract_analyzer):
    """19. API contract path matching between frontend and backend."""
    fe = [{"file": "App.jsx", "endpoint": "/api/users", "method": "GET"}]
    be = [{"file": "routes.py", "endpoint": "/api/users", "method": "GET"}]
    mismatches = contract_analyzer.analyze_contracts(fe, be)
    assert len(mismatches) == 0


def test_api_contract_path_mismatch(contract_analyzer):
    """20. API contract path mismatch (singular vs plural)."""
    fe = [{"file": "App.jsx", "endpoint": "/api/users", "method": "GET"}]
    be = [{"file": "routes.py", "endpoint": "/api/user", "method": "GET"}]
    mismatches = contract_analyzer.analyze_contracts(fe, be)
    assert len(mismatches) == 1
    assert mismatches[0]["type"] == "PATH_MISMATCH"
    assert mismatches[0]["confidence"] == 0.75


# === SECURITY TESTS ===

def test_security_js_dangerously_set_inner_html(registry):
    """21. JS dangerouslySetInnerHTML security audit."""
    sec = registry.analyze_security_patterns("Widget.jsx", "<div dangerouslySetInnerHTML={{ __html: data }} />")
    assert len(sec) == 1
    assert "dangerouslySetInnerHTML" in sec[0]["title"]


def test_security_js_eval_execution(registry):
    """22. JS eval() security audit."""
    sec = registry.analyze_security_patterns("eval.js", "eval(userInput);")
    assert len(sec) == 1
    assert "eval" in sec[0]["title"]
