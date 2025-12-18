"""
Security MCP Registry Setup - Helper functions to register security MCPs in DMSG Registry

This module provides utilities to register the security MCP servers:
- PAT-MCP (Password Audit Tool MCP)
- Network Monitor MCP
- System Audit MCP
"""

from typing import Dict, Any
from agentos.tools.security.pat_mcp import PasswordAuditToolMCP
from agentos.tools.security.network_monitor_mcp import NetworkMonitorMCP
from agentos.tools.security.system_audit_mcp import SystemAuditMCP
from agentos.dmsg.registry import MCPRegistry


async def register_security_mcps(registry: MCPRegistry) -> Dict[str, str]:
    """
    Register all security MCP servers in the DMSG registry.
    
    Args:
        registry: MCPRegistry instance
        
    Returns:
        Dictionary mapping MCP names to their registered IDs
    """
    registered_ids = {}
    
    # Register PAT-MCP
    pat_mcp = PasswordAuditToolMCP()
    await pat_mcp.connect()
    pat_id = registry.register(pat_mcp.to_mcp_metadata())
    registered_ids["pat_mcp"] = pat_id
    print(f"Registered PAT-MCP with ID: {pat_id}")
    
    # Register Network Monitor MCP
    network_mcp = NetworkMonitorMCP()
    await network_mcp.connect()
    network_id = registry.register(network_mcp.to_mcp_metadata())
    registered_ids["network_monitor_mcp"] = network_id
    print(f"Registered Network Monitor MCP with ID: {network_id}")
    
    # Register System Audit MCP
    audit_mcp = SystemAuditMCP()
    await audit_mcp.connect()
    audit_id = registry.register(audit_mcp.to_mcp_metadata())
    registered_ids["audit_mcp"] = audit_id
    print(f"Registered System Audit MCP with ID: {audit_id}")
    
    return registered_ids


def get_security_mcp_connectors() -> Dict[str, Any]:
    """
    Get initialized security MCP connector instances.
    
    Returns:
        Dictionary mapping MCP names to connector instances
    """
    pat_mcp = PasswordAuditToolMCP()
    network_mcp = NetworkMonitorMCP()
    audit_mcp = SystemAuditMCP()
    
    return {
        "pat_mcp": pat_mcp,
        "network_monitor_mcp": network_mcp,
        "audit_mcp": audit_mcp,
    }

