"""
Targeted tests for M6 Production Security & Execution Hardening.
"""

import os
import pytest
from agentos_swe.verification.sandbox import IsolatedSandbox
from agentos_swe.security.limits import ResourceLimits
from agentos_swe.security.command_policy import CommandPolicy
from agentos_swe.security.secret_protection import SecretProtection


@pytest.fixture(autouse=True)
def mock_llm_env(monkeypatch):
    monkeypatch.setenv("AGENTOS_MOCK_LLM", "1")


def test_command_policy_blocks_unauthorized_binaries():
    policy = CommandPolicy()

    # Allowed binary
    ok, msg = policy.validate_command(["python", "-c", "print('ok')"])
    assert ok is True

    # Denied binary (not in explicit allow list)
    ok_disallowed, msg_disallowed = policy.validate_command(["unauthorized_tool", "--run"])
    assert ok_disallowed is False
    assert "not in the explicit security allow list" in msg_disallowed


def test_command_policy_blocks_forbidden_patterns():
    policy = CommandPolicy()

    # Forbidden pattern: powershell or cmd
    ok_ps, msg_ps = policy.validate_command(["powershell", "-Command", "Get-Process"])
    assert ok_ps is False
    assert "forbidden security pattern" in msg_ps


def test_secret_protection_text_and_env():
    raw_text = "API Key: sk-proj-1234567890abcdef1234567890abcdef and token = 'secret_pass123'"
    sanitized = SecretProtection.sanitize_text(raw_text)

    assert "sk-proj" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized

    # Environment stripping
    mock_env = {
        "PATH": "/usr/bin",
        "DATABASE_PASSWORD": "super_secret_db_pass",
        "MY_API_KEY": "secret_key_999",
    }
    clean_env = SecretProtection.sanitize_env(mock_env)
    assert "PATH" in clean_env
    assert "DATABASE_PASSWORD" not in clean_env
    assert "MY_API_KEY" not in clean_env


def test_sandbox_timeout_termination_and_process_cleanup():
    limits = ResourceLimits(max_execution_time_sec=1.0)
    with IsolatedSandbox(limits=limits) as sandbox:
        res = sandbox.run_command(["python", "-c", "import time; time.sleep(5)"], timeout=1)

        assert res["success"] is False
        assert "timed out" in res["stderr"]
        assert sandbox.latest_metrics is not None
        assert sandbox.latest_metrics.resource_limits_exceeded is True


def test_sandbox_output_truncation():
    limits = ResourceLimits(max_output_size_bytes=100)
    with IsolatedSandbox(limits=limits) as sandbox:
        # Generate large output
        res = sandbox.run_command(["python", "-c", "print('A' * 500)"])

        assert res["success"] is True
        assert len(res["stdout"]) < 300
        assert "...[Output Truncated: Exceeded Max Output Limit]..." in res["stdout"]


def test_sandbox_network_denied_by_default():
    limits = ResourceLimits(network_allowed=False)
    with IsolatedSandbox(limits=limits) as sandbox:
        res = sandbox.run_command(["python", "-c", "print('Local Only')"])
        assert res["success"] is True
        assert sandbox.latest_metrics.network_accessed is False
