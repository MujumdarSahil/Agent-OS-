"""
End-to-end tests for SecurityAgent and ScriptAuthorAgent.
"""

import pytest
from agentos.agents.security_agent import SecurityAgent
from agentos.agents.script_author_agent import ScriptAuthorAgent
from agentos.core.governance import GovernanceEngine
from agentos.core.bootstrap import register_builtin_components

@pytest.fixture(autouse=True)
def setup_bootstrap():
    """Ensure registry components are bootstrapped before tests."""
    register_builtin_components()

@pytest.mark.asyncio
async def test_security_agent_run_tool_e2e():
    """
    E2E test: Instantiate a real SecurityAgent and run its registered tools
    with realistic parameters, confirming it returns real results without raising.
    """
    agent = SecurityAgent(
        name="TestSecurityAgent",
        role="analyst"
    )
    
    # 1. Test log analyzer tool
    log_entries = [
        {"content": "Failed login attempt from 192.168.1.100", "timestamp": "2024-01-01T10:00:00"},
        {"content": "Unauthorized access attempt detected", "timestamp": "2024-01-01T10:01:00"},
    ]
    log_result = await agent.run_tool("analyze_logs", {
        "log_entries": log_entries,
        "log_type": "syslog"
    })
    
    assert log_result is not None
    assert log_result.get("statistics", {}).get("total_events") == 2
    assert log_result.get("safety_metadata", {}).get("operation") == "read_only"

    # 2. Test firewall audit tool
    firewall_rules = [
        {
            "id": "rule1",
            "action": "allow",
            "source": "0.0.0.0/0",
            "port": 22,
        }
    ]
    firewall_result = await agent.run_tool("audit_firewall", {
        "firewall_rules": firewall_rules,
        "firewall_type": "iptables"
    })
    
    assert firewall_result is not None
    assert firewall_result.get("security_score") is not None
    assert len(firewall_result.get("vulnerable_rules", [])) > 0

    # 3. Test SIEM script builder tool
    siem_result = await agent.run_tool("build_siem_script", {
        "siem_type": "splunk",
        "log_sources": ["syslog"],
        "output_format": "python"
    })
    
    assert siem_result is not None
    assert "script_content" in siem_result
    assert "Splunk" in siem_result["script_content"]

@pytest.mark.asyncio
async def test_script_author_agent_generate_script_e2e():
    """
    E2E test: Instantiate a real ScriptAuthorAgent and generate a script,
    confirming it runs and governance pre-check validates successfully.
    """
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    agent = ScriptAuthorAgent(
        name="TestScriptAuthor",
        script_languages=["python", "bash"]
    )
    
    result = await agent.generate_script(
        script_type="firewall_check",
        language="python",
        category="firewall_config",
        governance=governance
    )
    
    assert result is not None
    assert result.get("success") is True
    assert "script_content" in result
    assert "Firewall Configuration Check Script" in result["script_content"]
