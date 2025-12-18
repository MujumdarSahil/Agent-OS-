"""
Security Mission Examples - Demonstrates security-focused missions

This module provides example missions showing how SecurityAgents and
security MCPs work together:

1. Enterprise Password Audit Mission
2. Network Health Check Mission
3. System Hardening Mission
"""

from typing import Dict, Any, List
from agentos.core.squad import Squad, SquadRole
from agentos.core.security_agents import SecurityAgent, ScriptAuthorAgent
from agentos.core.governance import GovernanceEngine
from agentos.core.umb_adapter import UMBAdapter
from agentos.dmsg.registry import MCPRegistry
from agentos.tools.security.registry_setup import register_security_mcps, get_security_mcp_connectors


async def enterprise_password_audit_mission():
    """
    Enterprise Password Audit Mission
    
    Demonstrates:
    - SecurityAgent (auditor role) using PAT-MCP
    - Password policy evaluation
    - Hash identification and strength benchmarking
    - Weak pattern detection
    - Collaboration between agents
    """
    print("\n=== Enterprise Password Audit Mission ===")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    registry = MCPRegistry()
    mcp_ids = await register_security_mcps(registry)
    
    # Get MCP connectors
    mcps = get_security_mcp_connectors()
    for mcp in mcps.values():
        await mcp.connect()
    
    # Create security squad
    squad = Squad(name="Password Audit Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="Password Auditor",
        role="auditor",
        security_mcps={
            "pat_mcp": mcps["pat_mcp"],
        },
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent for generating audit scripts
    script_author = ScriptAuthorAgent(
        name="Audit Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(auditor, SquadRole.COMMANDER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform enterprise password policy audit",
        description="Audit password policies, identify hash types, and detect weak patterns"
    )
    
    print(f"Mission created: {mission.goal}")
    
    # Step 1: Evaluate password policy
    print("\nStep 1: Evaluating password policy...")
    policy = {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_digits": True,
        "require_special": False,
        "password_history": 5,
        "max_age_days": 90,
    }
    
    policy_result = await auditor._evaluate_password_policy({"policy": policy})
    print(f"Policy compliance score: {policy_result.get('compliance_score', 0):.2f}")
    print(f"NIST compliant: {policy_result.get('nist_compliant', False)}")
    
    # Step 2: Identify hash types
    print("\nStep 2: Identifying hash types...")
    sample_hashes = [
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # SHA-256
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",  # SHA-1
    ]
    
    for hash_value in sample_hashes:
        hash_result = await auditor._identify_hash({"hash": hash_value})
        print(f"Hash: {hash_value[:20]}...")
        print(f"  Type: {hash_result.get('hash_type', 'unknown')}")
        print(f"  Algorithm: {hash_result.get('algorithm', 'unknown')}")
    
    # Step 3: Detect weak patterns
    print("\nStep 3: Detecting weak password patterns...")
    password_samples = [
        "password123",
        "qwerty123",
        "admin123",
        "Welcome1",
    ]
    
    pattern_result = await auditor._detect_weak_patterns({
        "password_samples": password_samples
    })
    print(f"Risk level: {pattern_result.get('risk_level', 'unknown')}")
    print(f"Weak patterns: {pattern_result.get('weak_patterns_detected', [])}")
    
    # Step 4: Generate audit script
    print("\nStep 4: Generating audit script...")
    script_result = await script_author.generate_script(
        script_type="config_audit",
        language="python",
        category="configuration_audit",
        governance=governance,
    )
    
    if script_result.get("success"):
        print("Script generated successfully")
        print(f"Script ID: {script_result.get('script_metadata', {}).get('script_id')}")
    
    # Mission summary
    print("\n=== Mission Summary ===")
    print("✓ Password policy evaluated")
    print("✓ Hash types identified")
    print("✓ Weak patterns detected")
    print("✓ Audit script generated")
    
    return {
        "mission_id": mission.id,
        "policy_result": policy_result,
        "hash_results": hash_result,
        "pattern_result": pattern_result,
        "script_result": script_result,
    }


async def network_health_check_mission():
    """
    Network Health Check Mission
    
    Demonstrates:
    - SecurityAgent (monitor role) using Network Monitor MCP
    - Port scan detection
    - Anomaly detection
    - Incident classification
    - Metadata analysis
    """
    print("\n=== Network Health Check Mission ===")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    registry = MCPRegistry()
    mcp_ids = await register_security_mcps(registry)
    
    # Get MCP connectors
    mcps = get_security_mcp_connectors()
    for mcp in mcps.values():
        await mcp.connect()
    
    # Create security squad
    squad = Squad(name="Network Monitoring Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (monitor role)
    monitor = SecurityAgent(
        name="Network Monitor",
        role="monitor",
        security_mcps={
            "network_monitor_mcp": mcps["network_monitor_mcp"],
        },
        memory_ref=umb,
    )
    
    # Create SecurityAgent (analyst role)
    analyst = SecurityAgent(
        name="Security Analyst",
        role="analyst",
        security_mcps={
            "network_monitor_mcp": mcps["network_monitor_mcp"],
        },
        memory_ref=umb,
    )
    
    squad.add_agent(monitor, SquadRole.COMMANDER)
    squad.add_agent(analyst, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform network health check",
        description="Monitor network activity, detect anomalies, and classify incidents"
    )
    
    print(f"Mission created: {mission.goal}")
    
    # Step 1: Analyze network metadata
    print("\nStep 1: Analyzing network metadata...")
    log_entries = [
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 80, "protocol": "tcp"},
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 443, "protocol": "tcp"},
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 22, "protocol": "tcp"},
        {"source_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "dest_port": 3389, "protocol": "tcp"},
        {"source_ip": "192.168.1.101", "dest_ip": "10.0.0.2", "dest_port": 80, "protocol": "tcp"},
    ]
    
    metadata_result = await monitor._analyze_network_metadata({"log_entries": log_entries})
    print(f"Top source IPs: {len(metadata_result.get('top_source_ips', []))}")
    print(f"Total connections: {metadata_result.get('traffic_patterns', {}).get('total_connections', 0)}")
    
    # Step 2: Detect port scans
    print("\nStep 2: Detecting port scans...")
    scan_logs = log_entries * 10  # Simulate more activity
    scan_result = await monitor._detect_port_scan({"log_entries": scan_logs})
    print(f"Scan detected: {scan_result.get('scan_detected', False)}")
    if scan_result.get("scan_detected"):
        print(f"Scan type: {scan_result.get('scan_type', 'unknown')}")
        print(f"Source IPs: {scan_result.get('source_ips', [])}")
    
    # Step 3: Detect anomalies
    print("\nStep 3: Detecting network anomalies...")
    anomaly_result = await monitor._detect_network_anomalies({
        "log_entries": scan_logs,
        "baseline_period_days": 7,
    })
    print(f"Anomaly score: {anomaly_result.get('anomaly_score', 0):.2f}")
    print(f"Severity: {anomaly_result.get('severity', 'unknown')}")
    print(f"Anomalies found: {len(anomaly_result.get('anomalies_detected', []))}")
    
    # Step 4: Classify incident
    print("\nStep 4: Classifying security incident...")
    incident_result = await analyst._classify_security_incident({
        "log_entries": scan_logs,
        "incident_context": {"source": "network_monitor"},
    })
    print(f"Incident type: {incident_result.get('incident_type', 'unknown')}")
    print(f"Severity: {incident_result.get('severity', 'unknown')}")
    print(f"Recommended response: {incident_result.get('recommended_response', 'N/A')}")
    
    # Step 5: Generate incident report
    print("\nStep 5: Generating incident report...")
    incident_report = await analyst.generate_incident_report(
        incident_data={
            "log_entries": scan_logs,
            "scan_result": scan_result,
            "anomaly_result": anomaly_result,
            "classification": incident_result,
        },
        include_recommendations=True,
    )
    print(f"Incident report ID: {incident_report.get('incident_id')}")
    
    # Mission summary
    print("\n=== Mission Summary ===")
    print("✓ Network metadata analyzed")
    print("✓ Port scans detected")
    print("✓ Anomalies identified")
    print("✓ Incident classified")
    print("✓ Incident report generated")
    
    return {
        "mission_id": mission.id,
        "metadata_result": metadata_result,
        "scan_result": scan_result,
        "anomaly_result": anomaly_result,
        "incident_result": incident_result,
        "incident_report": incident_report,
    }


async def system_hardening_mission():
    """
    System Hardening Mission
    
    Demonstrates:
    - SecurityAgent (auditor role) using System Audit MCP
    - Configuration auditing
    - Firewall rule validation
    - Log scanning
    - Vulnerability advisory generation
    """
    print("\n=== System Hardening Mission ===")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    governance.initialize_security_policies()
    
    registry = MCPRegistry()
    mcp_ids = await register_security_mcps(registry)
    
    # Get MCP connectors
    mcps = get_security_mcp_connectors()
    for mcp in mcps.values():
        await mcp.connect()
    
    # Create security squad
    squad = Squad(name="System Hardening Squad", shared_memory_ref=umb)
    
    # Create SecurityAgent (auditor role)
    auditor = SecurityAgent(
        name="System Auditor",
        role="auditor",
        security_mcps={
            "audit_mcp": mcps["audit_mcp"],
        },
        memory_ref=umb,
    )
    
    # Create SecurityAgent (policy-advisor role)
    advisor = SecurityAgent(
        name="Policy Advisor",
        role="policy-advisor",
        security_mcps={
            "audit_mcp": mcps["audit_mcp"],
        },
        memory_ref=umb,
    )
    
    # Create ScriptAuthorAgent
    script_author = ScriptAuthorAgent(
        name="Hardening Script Author",
        memory_ref=umb,
    )
    
    squad.add_agent(auditor, SquadRole.COMMANDER)
    squad.add_agent(advisor, SquadRole.LEADER)
    squad.add_agent(script_author, SquadRole.WORKER)
    
    # Create mission
    mission = squad.create_mission(
        goal="Perform system hardening audit",
        description="Audit system configuration, validate firewall rules, scan logs, and generate hardening recommendations"
    )
    
    print(f"Mission created: {mission.goal}")
    
    # Step 1: Audit system configuration
    print("\nStep 1: Auditing system configuration...")
    config_files = [
        {
            "path": "/etc/security/config",
            "content": "password = secret123\ndebug = true\nssl = false",
        },
        {
            "path": "/etc/app/config.json",
            "content": '{"api_key": "sk-1234567890", "permission": 777}',
        },
    ]
    
    config_result = await auditor._audit_system_config({
        "config_files": config_files,
        "config_type": "generic",
    })
    print(f"Compliance score: {config_result.get('compliance_score', 0):.2f}")
    print(f"Risk level: {config_result.get('risk_level', 'unknown')}")
    print(f"Issues found: {len(config_result.get('issues_found', []))}")
    
    # Step 2: Validate firewall rules
    print("\nStep 2: Validating firewall rules...")
    firewall_rules = [
        {
            "id": "rule1",
            "action": "allow",
            "protocol": "tcp",
            "port": 22,
            "source": "0.0.0.0/0",  # Vulnerable rule
        },
        {
            "id": "rule2",
            "action": "allow",
            "protocol": "tcp",
            "port": 80,
            "source": "192.168.1.0/24",
            "log": True,
        },
    ]
    
    firewall_result = await auditor._validate_firewall({
        "firewall_rules": firewall_rules,
    })
    print(f"Security score: {firewall_result.get('security_score', 0):.2f}")
    print(f"Vulnerable rules: {len(firewall_result.get('vulnerable_rules', []))}")
    
    # Step 3: Scan security logs
    print("\nStep 3: Scanning security logs...")
    log_files = [
        {
            "path": "/var/log/security.log",
            "content": "2024-01-01 10:00:00 failed login attempt from 192.168.1.100\n"
                      "2024-01-01 10:01:00 unauthorized access attempt\n"
                      "2024-01-01 10:02:00 root login detected\n"
                      "2024-01-01 10:03:00 error: connection refused\n",
        },
    ]
    
    log_result = await auditor._scan_security_logs({
        "log_files": log_files,
        "log_type": "security",
    })
    print(f"Security events: {log_result.get('summary', {}).get('total_events', 0)}")
    print(f"High severity: {log_result.get('summary', {}).get('high_severity', 0)}")
    print(f"Anomalies: {log_result.get('summary', {}).get('anomalies_count', 0)}")
    
    # Step 4: Generate vulnerability advisory
    print("\nStep 4: Generating vulnerability advisory...")
    advisory_result = await advisor._generate_vulnerability_advisory({
        "audit_results": {
            "issues_found": config_result.get("issues_found", []),
            "vulnerable_rules": firewall_result.get("vulnerable_rules", []),
            "security_events": log_result.get("security_events", []),
        },
        "system_info": {
            "hostname": "example-server",
            "os": "Linux",
        },
    })
    print(f"Advisory severity: {advisory_result.get('severity', 'unknown')}")
    print(f"Affected components: {advisory_result.get('affected_components', [])}")
    print(f"Remediation steps: {len(advisory_result.get('remediation_steps', []))}")
    
    # Step 5: Generate hardening script
    print("\nStep 5: Generating hardening script...")
    script_result = await script_author.generate_script(
        script_type="firewall_check",
        language="python",
        category="firewall_configuration",
        governance=governance,
    )
    
    if script_result.get("success"):
        print("Hardening script generated successfully")
    
    # Mission summary
    print("\n=== Mission Summary ===")
    print("✓ System configuration audited")
    print("✓ Firewall rules validated")
    print("✓ Security logs scanned")
    print("✓ Vulnerability advisory generated")
    print("✓ Hardening script created")
    
    return {
        "mission_id": mission.id,
        "config_result": config_result,
        "firewall_result": firewall_result,
        "log_result": log_result,
        "advisory_result": advisory_result,
        "script_result": script_result,
    }


async def run_all_security_missions():
    """Run all security mission examples"""
    print("\n" + "="*60)
    print("Running All Security Mission Examples")
    print("="*60)
    
    results = {}
    
    try:
        results["password_audit"] = await enterprise_password_audit_mission()
    except Exception as e:
        print(f"Error in password audit mission: {e}")
        results["password_audit"] = {"error": str(e)}
    
    try:
        results["network_health"] = await network_health_check_mission()
    except Exception as e:
        print(f"Error in network health mission: {e}")
        results["network_health"] = {"error": str(e)}
    
    try:
        results["system_hardening"] = await system_hardening_mission()
    except Exception as e:
        print(f"Error in system hardening mission: {e}")
        results["system_hardening"] = {"error": str(e)}
    
    print("\n" + "="*60)
    print("All Security Missions Completed")
    print("="*60)
    
    return results

