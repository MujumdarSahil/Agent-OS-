"""
M12.6 Test-Harness Exception Semantic Hardening Test Suite.
Verifies that diagnostic exception handlers with logging & fallbacks are correctly classified as INTENTIONAL_FALLBACK,
while genuine silent exception swallowing (except Exception: pass) remains classified as POSSIBLE_ERROR_SWALLOW across production and test harness code.
"""

import ast
import pytest
from agentos_swe.semantic.resolver import PythonSemanticResolver
from agentos_swe.semantic.base import ExceptionIntent


@pytest.fixture
def resolver():
    return PythonSemanticResolver()


def test_1_test_harness_logged_exception_with_return_fallback(resolver):
    """Test 1: TEST_HARNESS + logged exception + return None -> INTENTIONAL_FALLBACK."""
    code = """
try:
    r = requests.get(url)
except Exception as e:
    print(f"Request failed: {e}")
    return None
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("tests/test_api.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK
    assert res.confidence >= 0.95


def test_2_production_module_logged_exception_with_return_fallback(resolver):
    """Test 2: Production module + logged exception + return None -> INTENTIONAL_FALLBACK."""
    code = """
try:
    data = fetch_external_data()
except Exception as err:
    logger.warning(f"External service unavailable: {err}")
    return None
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("app/services/client.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK
    assert res.confidence >= 0.90


def test_3_test_harness_bare_pass_silent_exception(resolver):
    """Test 3: TEST_HARNESS + except Exception: pass -> POSSIBLE_ERROR_SWALLOW."""
    code = """
try:
    cleanup_temp_files()
except Exception:
    pass
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("tests/conftest.py", handler, tree)
    assert res.intent == ExceptionIntent.POSSIBLE_ERROR_SWALLOW


def test_4_production_module_bare_pass_silent_exception(resolver):
    """Test 4: Production module + except Exception: pass -> POSSIBLE_ERROR_SWALLOW."""
    code = """
try:
    save_to_database()
except Exception:
    pass
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("app/db/repository.py", handler, tree)
    assert res.intent == ExceptionIntent.POSSIBLE_ERROR_SWALLOW


def test_5_exception_logged_through_logger_error(resolver):
    """Test 5: Exception variable logged through logger.error() -> INTENTIONAL_FALLBACK."""
    code = """
try:
    process_order(order_id)
except Exception as ex:
    logger.error("Order processing failed", exc_info=ex)
    return False
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("app/orders.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK


def test_6_exception_printed_using_f_string(resolver):
    """Test 6: Exception variable printed using f-string -> INTENTIONAL_FALLBACK."""
    code = """
try:
    connect()
except Exception as e:
    print(f"Connection failed with error: {e}")
    continue
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("scripts/runner.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK


def test_7_exception_logged_without_fallback(resolver):
    """Test 7: Exception logged but no fallback -> UNKNOWN."""
    code = """
try:
    ping_server()
except Exception as e:
    logger.info(f"Ping info: {e}")
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("app/monitor.py", handler, tree)
    assert res.intent in (ExceptionIntent.UNKNOWN, ExceptionIntent.POSSIBLE_ERROR_SWALLOW)


def test_8_exception_fallback_without_logging(resolver):
    """Test 8: Specific exception fallback without logging -> INTENTIONAL_FALLBACK."""
    code = """
try:
    val = int(user_input)
except ValueError:
    val = 0
"""
    tree = ast.parse(code)
    handler = tree.body[0].handlers[0]
    res = resolver.analyze_exception_block("app/utils.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK


def test_9_omnitutor_ai_exact_pattern_reproduction(resolver):
    """Test 9: OmniTutor-AI exact pattern reproduced -> INTENTIONAL_FALLBACK."""
    code = """
def get(path: str) -> dict | list | None:
    try:
        r = requests.get(f"{BASE}{path}", timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"GET {path} failed: {e}")
        return None
"""
    tree = ast.parse(code)
    handler = tree.body[0].body[0].handlers[0]
    res = resolver.analyze_exception_block("scripts/test_api.py", handler, tree)
    assert res.intent == ExceptionIntent.INTENTIONAL_FALLBACK
    assert res.has_fallback_value is True


def test_10_genuine_silent_exception_in_test_harness(resolver):
    """Test 10: Genuine silent exception in a test harness -> POSSIBLE_ERROR_SWALLOW."""
    code = """
def teardown():
    try:
        remove_directory()
    except Exception:
        pass
"""
    tree = ast.parse(code)
    handler = tree.body[0].body[0].handlers[0]
    res = resolver.analyze_exception_block("tests/test_suite.py", handler, tree)
    assert res.intent == ExceptionIntent.POSSIBLE_ERROR_SWALLOW
