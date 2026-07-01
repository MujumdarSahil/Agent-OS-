"""
Unit tests for security tools
"""

from agentos.mcp.security.tools.log_analyzer import LogAnalyzer
from agentos.mcp.security.tools.firewall_audit import FirewallAudit
from agentos.mcp.security.tools.permission_audit import PermissionAudit


def test_log_analyzer():
    """Test log analyzer"""
    log_entries = [
        {"content": "Failed login attempt from 192.168.1.100", "timestamp": "2024-01-01T10:00:00"},
        {"content": "Unauthorized access attempt detected", "timestamp": "2024-01-01T10:01:00"},
    ]
    
    result = LogAnalyzer.analyze_logs(log_entries)
    
    assert result["statistics"]["total_events"] > 0
    assert "safety_metadata" in result
    assert result["safety_metadata"]["operation"] == "read_only"


def test_firewall_audit():
    """Test firewall audit"""
    firewall_rules = [
        {
            "id": "rule1",
            "action": "allow",
            "source": "0.0.0.0/0",
            "port": 22,
        }
    ]
    
    result = FirewallAudit.audit_firewall_rules(firewall_rules)
    
    assert "security_score" in result
    assert "safety_metadata" in result
    assert len(result["vulnerable_rules"]) > 0


def test_permission_audit():
    """Test permission audit"""
    user_list = [
        {
            "id": "user1",
            "permissions": ["*"],
            "roles": ["admin"],
        }
    ]
    
    result = PermissionAudit.audit_permissions(user_list)
    
    assert "permission_issues" in result
    assert "safety_metadata" in result

