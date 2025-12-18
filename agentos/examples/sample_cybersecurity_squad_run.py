"""
Sample Cybersecurity Squad Run - Example cybersecurity mission execution

Demonstrates:
- SecurityAgent with cybersecurity tools
- Mission execution with governance
- Tool invocation with safety_metadata
- UMB storage of results
"""

import asyncio
import logging
from agentos.core.umb_adapter import UMBAdapter
from agentos.core.governance import GovernanceEngine
from agentos.core.squad import Squad, SquadRole
from agentos.agents.security_agent import SecurityAgent
from agentos.agents.script_author_agent import ScriptAuthorAgent
from agentos.mcp.security.pat_mcp import PasswordAuditToolMCP
from agentos.mcp.security.network_monitor_mcp import NetworkMonitorMCP
from agentos.mcp.security.system_audit_mcp import SystemAuditMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def sample_cybersecurity_squad_run():
    """Run sample cybersecurity squad mission"""
    logger.info("Starting sample cybersecurity squad run")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    pat_mcp = PasswordAuditToolMCP()
    network_mcp = NetworkMonitorMCP()
    audit_mcp = SystemAuditMCP()
    
    await pat_mcp.connect()
    await network_mcp.connect()
    await audit_mcp.connect()
    
    # Create security squad
    squad = Squad(name="Cybersecurity Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="Security Auditor",
        role="auditor",
        security_mcps={
            "pat_mcp": pat_mcp,
            "audit_mcp": audit_mcp,
        },
        memory_ref=umb,
    )
    
    # Create SecurityAgent (analyst role)
    analyst = SecurityAgent(
        name="Security Analyst",
        role="analyst",
        security_mcps={
            "network_monitor_mcp": network_mcp,
        },
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent
    script_author = ScriptAuthorAgent(
        name="Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(auditor, SquadRole.COMMANDER)
    squad.add_agent(analyst, SquadRole.LEADER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform comprehensive security audit",
        description="Audit passwords, network, and system configuration"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Password audit
    logger.info("Step 1: Password audit")
    policy = {"min_length": 8, "require_uppercase": True}
    policy_result = await pat_mcp.call_skill("password_policy_eval", {"policy": policy})
    logger.info(f"Policy compliance: {policy_result.get('compliance_score', 0):.2f}")
    
    # Step 2: Network analysis
    logger.info("Step 2: Network analysis")
    log_entries = [
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 80, "protocol": "tcp"},
    ] * 10
    network_result = await network_mcp.call_skill("detect_port_scans_behavior", {
        "log_entries": log_entries
    })
    logger.info(f"Port scan detected: {network_result.get('scan_detected', False)}")
    
    # Step 3: System audit
    logger.info("Step 3: System audit")
    config_files = [{"path": "/etc/config", "content": "password = secret123"}]
    config_result = await audit_mcp.call_skill("audit_config_security", {
        "config_files": config_files
    })
    logger.info(f"Config issues: {len(config_result.get('issues_found', []))}")
    
    # Step 4: Generate script
    logger.info("Step 4: Generate hardening script")
    script_result = await script_author.generate_script(
        script_type="config_audit",
        language="python",
        category="config_audit_automation",
        governance=governance,
    )
    logger.info(f"Script generated: {script_result.get('success', False)}")
    
    # Store results in UMB
    report = {
        "mission_id": mission.id,
        "policy_result": policy_result,
        "network_result": network_result,
        "config_result": config_result,
        "script_result": script_result,
    }
    
    await umb.upsert({
        "id": f"security_audit_report_{mission.id}",
        "text": f"Security Audit Report: {report}",
        "vector": [],
        "metadata": {
            "mission_id": mission.id,
            "report_type": "security_audit",
        }
    })
    
    logger.info("Sample cybersecurity squad run completed")
    return report


if __name__ == "__main__":
    asyncio.run(sample_cybersecurity_squad_run())

