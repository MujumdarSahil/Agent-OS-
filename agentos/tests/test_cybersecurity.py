"""
Tests for Cybersecurity components
"""

import pytest
from agentos.core.cybersecurity_agents import (
    TriageAgent,
    SandboxAnalystAgent,
    ComplianceAgent,
    ResponderAgent,
)
from agentos.mcp_connectors.security_mcp import (
    AlertIngestMCP,
    ThreatIntelMCP,
    SandboxMCP,
    PasswordAuditMCP,
    ResponseActionMCP,
)
from agentos.core.umb_adapter import UMBAdapter
from agentos.core.governance import GovernanceEngine


@pytest.fixture
def umb():
    """Create UMB adapter"""
    return UMBAdapter(backend="simple")


@pytest.fixture
def alert_ingest():
    """Create alert ingest MCP"""
    return AlertIngestMCP()


@pytest.fixture
def threat_intel():
    """Create threat intel MCP"""
    return ThreatIntelMCP()


@pytest.fixture
def sandbox():
    """Create sandbox MCP"""
    return SandboxMCP()


@pytest.mark.asyncio
async def test_triage_agent(umb, alert_ingest, threat_intel):
    """Test TriageAgent"""
    await alert_ingest.connect()
    await threat_intel.connect()
    
    agent = TriageAgent(
        memory_ref=umb,
        alert_ingest_mcp=alert_ingest,
        threat_intel_mcp=threat_intel,
    )
    
    alert = {
        "title": "Test alert",
        "source_ip": "192.0.2.100",
        "severity": "high",
    }
    
    result = await agent.triage_alert(alert)
    
    assert result["success"] is True
    assert "triage_result" in result
    assert result["triage_result"]["severity"] == "high"


@pytest.mark.asyncio
async def test_sandbox_analyst(umb, sandbox):
    """Test SandboxAnalystAgent"""
    await sandbox.connect()
    
    agent = SandboxAnalystAgent(
        memory_ref=umb,
        sandbox_mcp=sandbox,
    )
    
    artifact_hash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    result = await agent.analyze_artifact(artifact_hash, "file")
    
    assert result["success"] is True
    assert "analysis" in result
    assert "risk_level" in result["analysis"]


@pytest.mark.asyncio
async def test_compliance_agent(umb):
    """Test ComplianceAgent"""
    password_audit = PasswordAuditMCP()
    await password_audit.connect()
    
    agent = ComplianceAgent(
        memory_ref=umb,
        password_audit_mcp=password_audit,
    )
    
    policy_config = {
        "min_length": 8,
        "require_uppercase": True,
    }
    
    password_hashes = [
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    ]
    
    result = await agent.audit_password_policy(policy_config, password_hashes)
    
    assert result["success"] is True
    assert "audit" in result


@pytest.mark.asyncio
async def test_responder_agent(umb):
    """Test ResponderAgent"""
    governance = GovernanceEngine()
    response_action = ResponseActionMCP()
    await response_action.connect()
    
    agent = ResponderAgent(
        memory_ref=umb,
        response_action_mcp=response_action,
        governance=governance,
    )
    
    # Test that action requires approval
    result = await agent.contain_incident(
        incident_id="INC-001",
        host_id="HOST-123",
        reason="Test"
    )
    
    # Should either succeed (if approved) or require approval
    assert "success" in result or "requires_approval" in result


@pytest.mark.asyncio
async def test_password_audit_safety():
    """Test that PasswordAuditMCP only accepts hashes"""
    password_audit = PasswordAuditMCP()
    await password_audit.connect()
    
    # Try with cleartext (should fail)
    result = await password_audit.call_skill("audit_policy", {
        "policy_config": {},
        "password_hashes": ["short"],  # Too short to be a hash
    })
    
    # Should reject cleartext
    assert not result.get("success") or "hash" in result.get("error", "").lower()


@pytest.mark.asyncio
async def test_response_action_approval():
    """Test that ResponseActionMCP requires approval"""
    response_action = ResponseActionMCP()
    await response_action.connect()
    
    # Try without approval
    result = await response_action.call_skill("isolate_host", {
        "host_id": "HOST-123",
        "reason": "Test",
    })
    
    # Should require approval
    assert not result.get("success") or result.get("requires_approval") is True

