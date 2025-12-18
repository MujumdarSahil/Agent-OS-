"""
Security Tools Demo - Quick demonstration of security MCPs and agents

Run this to verify the security tool layer is working correctly.
"""

import asyncio
from agentos.tools.security import PasswordAuditToolMCP, NetworkMonitorMCP, SystemAuditMCP
from agentos.core.security_agents import SecurityAgent, ScriptAuthorAgent
from agentos.core.governance import GovernanceEngine
from agentos.dmsg.registry import MCPRegistry
from agentos.tools.security.registry_setup import register_security_mcps


async def demo_security_mcps():
    """Demo the security MCP servers"""
    print("=== Security MCPs Demo ===\n")
    
    # PAT-MCP Demo
    print("1. PAT-MCP (Password Audit Tool)")
    pat_mcp = PasswordAuditToolMCP()
    await pat_mcp.connect()
    
    # Identify hash
    hash_result = await pat_mcp.call_skill("identify_hash", {
        "hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    })
    print(f"   Hash type: {hash_result.get('hash_type', 'unknown')}")
    print(f"   Algorithm: {hash_result.get('algorithm', 'unknown')}")
    
    # Evaluate policy
    policy_result = await pat_mcp.call_skill("evaluate_policy", {
        "policy": {
            "min_length": 8,
            "require_uppercase": True,
            "require_digits": True,
        }
    })
    print(f"   Policy compliance: {policy_result.get('compliance_score', 0):.2f}")
    print()
    
    # Network Monitor MCP Demo
    print("2. Network Monitor MCP")
    network_mcp = NetworkMonitorMCP()
    await network_mcp.connect()
    
    log_entries = [
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 80, "protocol": "tcp"},
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 443, "protocol": "tcp"},
    ]
    
    scan_result = await network_mcp.call_skill("detect_port_scan", {
        "log_entries": log_entries * 5
    })
    print(f"   Scan detected: {scan_result.get('scan_detected', False)}")
    print()
    
    # System Audit MCP Demo
    print("3. System Audit MCP")
    audit_mcp = SystemAuditMCP()
    await audit_mcp.connect()
    
    config_result = await audit_mcp.call_skill("audit_config", {
        "config_files": [{
            "path": "/etc/config",
            "content": "password = secret123\ndebug = true",
        }],
        "config_type": "generic",
    })
    print(f"   Issues found: {len(config_result.get('issues_found', []))}")
    print(f"   Risk level: {config_result.get('risk_level', 'unknown')}")
    print()


async def demo_security_agents():
    """Demo the security agents"""
    print("=== Security Agents Demo ===\n")
    
    # Get MCP connectors
    from agentos.tools.security.registry_setup import get_security_mcp_connectors
    mcps = get_security_mcp_connectors()
    for mcp in mcps.values():
        await mcp.connect()
    
    # SecurityAgent Demo
    print("1. SecurityAgent (auditor role)")
    auditor = SecurityAgent(
        name="Security Auditor",
        role="auditor",
        security_mcps={"pat_mcp": mcps["pat_mcp"]},
    )
    
    policy_result = await auditor._evaluate_password_policy({
        "policy": {"min_length": 8, "require_uppercase": True}
    })
    print(f"   Policy evaluation: {policy_result.get('success', False)}")
    print()
    
    # ScriptAuthorAgent Demo
    print("2. ScriptAuthorAgent")
    script_author = ScriptAuthorAgent(name="Script Author")
    
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    script_result = await script_author.generate_script(
        script_type="firewall_check",
        language="python",
        category="firewall_configuration",
        governance=governance,
    )
    print(f"   Script generated: {script_result.get('success', False)}")
    if script_result.get("success"):
        print(f"   Script ID: {script_result.get('script_metadata', {}).get('script_id')}")
    print()


async def demo_registry():
    """Demo MCP registry registration"""
    print("=== DMSG Registry Demo ===\n")
    
    registry = MCPRegistry()
    mcp_ids = await register_security_mcps(registry)
    
    print("Registered MCPs:")
    for name, mcp_id in mcp_ids.items():
        print(f"   {name}: {mcp_id}")
    
    print(f"\nTotal skills available: {len(registry.list_all_skills())}")
    print()


async def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("AgentOS Security Tools Layer Demo")
    print("="*60 + "\n")
    
    try:
        await demo_security_mcps()
        await demo_security_agents()
        await demo_registry()
        
        print("="*60)
        print("All demos completed successfully!")
        print("="*60)
    except Exception as e:
        print(f"Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())

