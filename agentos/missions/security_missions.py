"""
Security Mission Examples - Demonstrates security-focused missions

Three new missions:
1. Enterprise Password Audit Mission
2. Network Health Check Mission
3. System Hardening Mission
"""

import logging
from typing import Dict, Any
from agentos.core.squad import Squad, SquadRole
from agentos.agents.security_agent import SecurityAgent
from agentos.agents.script_author_agent import ScriptAuthorAgent
from agentos.core.governance import GovernanceEngine
from agentos.core.umb_adapter import UMBAdapter
from agentos.mcp.security.pat_mcp import PasswordAuditToolMCP
from agentos.mcp.security.network_monitor_mcp import NetworkMonitorMCP
from agentos.mcp.security.system_audit_mcp import SystemAuditMCP

logger = logging.getLogger(__name__)


async def log_threat_analysis_mission():
    """
    Log Threat Analysis Mission
    
    Workflow:
    - SecurityAgent (analyst) → LogAnalyzer tool
    - Detect security events
    - Classify threats
    - Generate SIEM script
    """
    logger.info("Starting Log Threat Analysis Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    network_mcp = NetworkMonitorMCP()
    await network_mcp.connect()
    
    # Create security squad
    squad = Squad(name="Threat Analysis Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (analyst role)
    analyst = SecurityAgent(
        name="Threat Analyst",
        role="analyst",
        security_mcps={"network_monitor_mcp": network_mcp},
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent
    script_author = ScriptAuthorAgent(
        name="SIEM Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(analyst, SquadRole.COMMANDER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Analyze logs for security threats",
        description="Detect security events in logs and generate SIEM integration scripts"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Analyze logs using tool
    from agentos.mcp.security.tools.log_analyzer import LogAnalyzer
    
    log_entries = [
        {"content": "Failed login attempt from 192.168.1.100", "timestamp": "2024-01-01T10:00:00", "source": "syslog"},
        {"content": "Unauthorized access attempt", "timestamp": "2024-01-01T10:01:00", "source": "syslog"},
    ]
    
    log_result = await analyst.run_tool("analyze_logs", {
        "log_entries": log_entries,
        "log_type": "syslog"
    })
    logger.info(f"Security events found: {log_result.get('statistics', {}).get('total_events', 0)}")
    
    # Step 2: Generate SIEM script
    siem_result = await analyst.run_tool("build_siem_script", {
        "siem_type": "splunk",
        "log_sources": ["syslog"],
        "output_format": "python"
    })
    
    # Step 3: Save to UMB
    report = {
        "mission_id": mission.id,
        "log_result": log_result,
        "siem_result": siem_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"log_threat_analysis_{mission.id}",
            "text": f"Log Threat Analysis Report: {report}",
            "vector": [],
            "metadata": {"mission_id": mission.id, "report_type": "log_threat_analysis"}
        })
    
    logger.info("Log Threat Analysis Mission completed")
    return report


async def firewall_config_audit_mission():
    """
    Firewall Config Audit Mission
    
    Workflow:
    - SecurityAgent (auditor) → FirewallAudit tool
    - Validate firewall rules
    - Generate recommendations
    """
    logger.info("Starting Firewall Config Audit Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    audit_mcp = SystemAuditMCP()
    await audit_mcp.connect()
    
    # Create security squad
    squad = Squad(name="Firewall Audit Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="Firewall Auditor",
        role="auditor",
        security_mcps={"audit_mcp": audit_mcp},
        memory_ref=umb,
    )
    
    # Create mission
    mission = squad.create_mission(
        goal="Audit firewall configuration",
        description="Review firewall rules for security issues"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Audit firewall
    firewall_rules = [
        {"id": "rule1", "action": "allow", "source": "0.0.0.0/0", "port": 22},
    ]
    
    firewall_result = await auditor.run_tool("audit_firewall", {
        "firewall_rules": firewall_rules,
        "firewall_type": "iptables"
    })
    logger.info(f"Firewall security score: {firewall_result.get('security_score', 0):.2f}")
    
    # Step 2: Save to UMB
    report = {
        "mission_id": mission.id,
        "firewall_result": firewall_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"firewall_audit_{mission.id}",
            "text": f"Firewall Audit Report: {report}",
            "vector": [],
            "metadata": {"mission_id": mission.id, "report_type": "firewall_audit"}
        })
    
    logger.info("Firewall Config Audit Mission completed")
    return report


async def user_permission_audit_mission():
    """
    User & Permission Audit Mission
    
    Workflow:
    - SecurityAgent (auditor) → PermissionAudit tool
    - Check user permissions
    - Identify excessive permissions
    """
    logger.info("Starting User & Permission Audit Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security squad
    squad = Squad(name="Permission Audit Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="Permission Auditor",
        role="auditor",
        memory_ref=umb,
    )
    
    # Create mission
    mission = squad.create_mission(
        goal="Audit user permissions",
        description="Review user permissions and access controls"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Audit permissions
    user_list = [
        {"id": "user1", "permissions": ["*"], "roles": ["admin"]},
    ]
    
    permission_result = await auditor.run_tool("audit_permissions", {
        "user_list": user_list
    })
    logger.info(f"Permission issues: {len(permission_result.get('permission_issues', []))}")
    
    # Step 2: Save to UMB
    report = {
        "mission_id": mission.id,
        "permission_result": permission_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"permission_audit_{mission.id}",
            "text": f"Permission Audit Report: {report}",
            "vector": [],
            "metadata": {"mission_id": mission.id, "report_type": "permission_audit"}
        })
    
    logger.info("User & Permission Audit Mission completed")
    return report


async def system_hardening_score_mission():
    """
    System Hardening Score Mission
    
    Workflow:
    - SecurityAgent (auditor) → SystemHardening tool
    - Generate hardening recommendations
    - Calculate hardening score
    """
    logger.info("Starting System Hardening Score Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    audit_mcp = SystemAuditMCP()
    await audit_mcp.connect()
    
    # Create security squad
    squad = Squad(name="Hardening Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="Hardening Auditor",
        role="auditor",
        security_mcps={"audit_mcp": audit_mcp},
        memory_ref=umb,
    )
    
    # Create mission
    mission = squad.create_mission(
        goal="Generate system hardening score",
        description="Analyze system and generate hardening recommendations"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Collect audit results
    audit_results = {
        "firewall_result": {"security_score": 0.6, "vulnerable_rules": [{"rule_id": "rule1"}]},
        "config_result": {"issues_found": [{"issue": "plaintext password"}]},
    }
    
    # Step 2: Generate hardening recommendations
    hardening_result = await auditor.run_tool("generate_hardening", {
        "audit_results": audit_results,
        "system_info": {"hostname": "example-server"}
    })
    logger.info(f"Hardening score: {hardening_result.get('hardening_score', 0):.2f}")
    
    # Step 3: Save to UMB
    report = {
        "mission_id": mission.id,
        "hardening_result": hardening_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"hardening_score_{mission.id}",
            "text": f"System Hardening Score Report: {report}",
            "vector": [],
            "metadata": {"mission_id": mission.id, "report_type": "hardening_score"}
        })
    
    logger.info("System Hardening Score Mission completed")
    return report


async def enterprise_password_audit_mission():
    """
    Mission 1: Enterprise Password Audit
    
    Workflow:
    - SecurityAgent (auditor role) → PAT-MCP
    - Strength evaluation
    - Weak pattern detection
    - ScriptAuthorAgent → remediation scripts
    - Save report to UMB
    """
    logger.info("Starting Enterprise Password Audit Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    pat_mcp = PasswordAuditToolMCP()
    await pat_mcp.connect()
    
    # Create security squad
    squad = Squad(name="Password Audit Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="Password Auditor",
        role="auditor",
        security_mcps={"pat_mcp": pat_mcp},
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent
    script_author = ScriptAuthorAgent(
        name="Audit Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(auditor, SquadRole.COMMANDER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform enterprise password policy audit",
        description="Audit password policies, identify hash types, detect weak patterns, and generate remediation scripts"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Evaluate password policy
    policy = {
        "min_length": 8,
        "require_uppercase": True,
        "require_digits": True,
    }
    
    policy_result = await pat_mcp.call_skill("password_policy_eval", {"policy": policy})
    logger.info(f"Policy compliance: {policy_result.get('compliance_score', 0):.2f}")
    
    # Step 2: Identify hash types and evaluate strength
    sample_hashes = [
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    ]
    
    hash_results = []
    for hash_value in sample_hashes:
        hash_type_result = await pat_mcp.call_skill("hash_type", {"hash": hash_value})
        hash_strength_result = await pat_mcp.call_skill("hash_strength", {
            "hash": hash_value,
            "hash_type": hash_type_result.get("hash_type", "unknown")
        })
        hash_results.append({
            "hash": hash_value[:20] + "...",
            "type": hash_type_result.get("hash_type"),
            "strength": hash_strength_result.get("strength_score", 0),
        })
    
    # Step 3: Detect weak patterns
    password_samples = ["password123", "qwerty123", "admin123"]
    pattern_result = await pat_mcp.call_skill("ai_pattern_detector", {
        "password_samples": password_samples
    })
    logger.info(f"Weak patterns detected: {pattern_result.get('weak_patterns_detected', [])}")
    
    # Step 4: Generate remediation script
    script_result = await script_author.generate_script(
        script_type="config_audit",
        language="python",
        category="config_audit_automation",
        governance=governance,
    )
    
    # Step 5: Save report to UMB
    report = {
        "mission_id": mission.id,
        "policy_result": policy_result,
        "hash_results": hash_results,
        "pattern_result": pattern_result,
        "script_result": script_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"password_audit_report_{mission.id}",
            "text": f"Password Audit Report: {report}",
            "vector": [],
            "metadata": {
                "mission_id": mission.id,
                "report_type": "password_audit",
                "timestamp": mission.created_at,
            }
        })
    
    logger.info("Enterprise Password Audit Mission completed")
    return report


async def network_health_check_mission():
    """
    Mission 2: Network Health Check
    
    Workflow:
    - NetworkMonitorMCP → log analysis
    - Detect anomalies + port scan behavior
    - SecurityAgent (analyst role) → incident report
    - ScriptAuthorAgent → SIEM ingestion script
    """
    logger.info("Starting Network Health Check Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    network_mcp = NetworkMonitorMCP()
    await network_mcp.connect()
    
    # Create security squad
    squad = Squad(name="Network Monitoring Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (analyst role)
    analyst = SecurityAgent(
        name="Security Analyst",
        role="analyst",
        security_mcps={"network_monitor_mcp": network_mcp},
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent
    script_author = ScriptAuthorAgent(
        name="SIEM Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(analyst, SquadRole.COMMANDER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform network health check",
        description="Monitor network activity, detect anomalies, classify incidents, and generate SIEM scripts"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Analyze network logs
    log_entries = [
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 80, "protocol": "tcp"},
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 443, "protocol": "tcp"},
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 22, "protocol": "tcp"},
    ] * 10  # Simulate more activity
    
    # Step 2: Detect port scans
    scan_result = await network_mcp.call_skill("detect_port_scans_behavior", {
        "log_entries": log_entries
    })
    logger.info(f"Port scan detected: {scan_result.get('scan_detected', False)}")
    
    # Step 3: Detect anomalies
    anomaly_result = await network_mcp.call_skill("detect_network_anomalies", {
        "log_entries": log_entries,
        "baseline_period_days": 7,
    })
    logger.info(f"Anomaly score: {anomaly_result.get('anomaly_score', 0):.2f}")
    
    # Step 4: Classify incident
    incident_result = await network_mcp.call_skill("classify_incident", {
        "log_entries": log_entries,
        "incident_context": {"source": "network_monitor"},
    })
    logger.info(f"Incident type: {incident_result.get('incident_type', 'unknown')}")
    
    # Step 5: Generate SIEM ingestion script
    script_result = await script_author.generate_script(
        script_type="siem_ingestion",
        language="python",
        category="siem_ingestion",
        governance=governance,
    )
    
    # Step 6: Save report to UMB
    report = {
        "mission_id": mission.id,
        "scan_result": scan_result,
        "anomaly_result": anomaly_result,
        "incident_result": incident_result,
        "script_result": script_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"network_health_report_{mission.id}",
            "text": f"Network Health Check Report: {report}",
            "vector": [],
            "metadata": {
                "mission_id": mission.id,
                "report_type": "network_health",
                "timestamp": mission.created_at,
            }
        })
    
    logger.info("Network Health Check Mission completed")
    return report


async def system_hardening_mission():
    """
    Mission 3: System Hardening
    
    Workflow:
    - SystemAuditMCP → config audit
    - SecurityAgent (auditor role) → hardening report
    - ScriptAuthorAgent → config hardening script
    """
    logger.info("Starting System Hardening Mission")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    # Create security MCPs
    audit_mcp = SystemAuditMCP()
    await audit_mcp.connect()
    
    # Create security squad
    squad = Squad(name="System Hardening Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="System Auditor",
        role="auditor",
        security_mcps={"audit_mcp": audit_mcp},
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent
    script_author = ScriptAuthorAgent(
        name="Hardening Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(auditor, SquadRole.COMMANDER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform system hardening audit",
        description="Audit system configuration, validate firewall rules, and generate hardening scripts"
    )
    
    logger.info(f"Mission created: {mission.goal}")
    
    # Step 1: Audit firewall
    firewall_rules = [
        {
            "id": "rule1",
            "action": "allow",
            "protocol": "tcp",
            "port": 22,
            "source": "0.0.0.0/0",  # Vulnerable
        },
    ]
    
    firewall_result = await audit_mcp.call_skill("audit_firewall_status", {
        "firewall_rules": firewall_rules
    })
    logger.info(f"Firewall security score: {firewall_result.get('security_score', 0):.2f}")
    
    # Step 2: Audit configuration
    config_files = [{
        "path": "/etc/config",
        "content": "password = secret123\ndebug = true",
    }]
    
    config_result = await audit_mcp.call_skill("audit_config_security", {
        "config_files": config_files,
        "config_type": "generic",
    })
    logger.info(f"Config issues found: {len(config_result.get('issues_found', []))}")
    
    # Step 3: Generate hardening recommendations
    hardening_result = await audit_mcp.call_skill("generate_hardening_recommendations", {
        "audit_results": {
            "vulnerable_rules": firewall_result.get("vulnerable_rules", []),
            "issues_found": config_result.get("issues_found", []),
        },
        "system_info": {"hostname": "example-server"},
    })
    
    # Step 4: Generate hardening script
    script_result = await script_author.generate_script(
        script_type="firewall_check",
        language="python",
        category="firewall_config",
        governance=governance,
    )
    
    # Step 5: Save report to UMB
    report = {
        "mission_id": mission.id,
        "firewall_result": firewall_result,
        "config_result": config_result,
        "hardening_result": hardening_result,
        "script_result": script_result,
    }
    
    if umb:
        await umb.upsert({
            "id": f"system_hardening_report_{mission.id}",
            "text": f"System Hardening Report: {report}",
            "vector": [],
            "metadata": {
                "mission_id": mission.id,
                "report_type": "system_hardening",
                "timestamp": mission.created_at,
            }
        })
    
    logger.info("System Hardening Mission completed")
    return report

