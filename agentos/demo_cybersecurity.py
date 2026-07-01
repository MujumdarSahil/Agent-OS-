"""
AgentOS Cybersecurity Demo - Showcase security workflows
"""

import asyncio
from agentos.core.squad import Squad, SquadRole
from agentos.core.umb_adapter import UMBAdapter
from agentos.core.governance import GovernanceEngine
from agentos.core.cybersecurity_agents import (
    TriageAgent,
    InvestigatorAgent,
    SandboxAnalystAgent,
    ComplianceAgent,
    ResponderAgent,
    ThreatHuntingAgent,
    ReviewerAgent,
)
from agentos.mcp_connectors.security_mcp import (
    AlertIngestMCP,
    LogAnalysisMCP,
    ThreatIntelMCP,
    SandboxMCP,
    PasswordAuditMCP,
    ResponseActionMCP,
    ModelHubMCP,
)


async def demo_alert_triage_workflow():
    """Demo: Alert -> Triage -> Investigation workflow"""
    print("\n=== Demo: Alert Triage Workflow ===")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    
    # Create MCPs
    alert_ingest = AlertIngestMCP()
    await alert_ingest.connect()
    
    threat_intel = ThreatIntelMCP()
    await threat_intel.connect()
    
    model_hub = ModelHubMCP()
    await model_hub.connect()
    
    log_analysis = LogAnalysisMCP()
    await log_analysis.connect()
    
    # Create agents
    triage_agent = TriageAgent(
        name="TriageAgent",
        memory_ref=umb,
        alert_ingest_mcp=alert_ingest,
        threat_intel_mcp=threat_intel,
        model_hub_mcp=model_hub,
    )
    
    investigator_agent = InvestigatorAgent(
        name="InvestigatorAgent",
        memory_ref=umb,
        log_analysis_mcp=log_analysis,
        threat_intel_mcp=threat_intel,
    )
    
    # Create squad
    squad = Squad(name="Security Squad", shared_memory_ref=umb)
    squad.add_agent(triage_agent, SquadRole.WORKER)
    squad.add_agent(investigator_agent, SquadRole.WORKER)
    
    print(f"Created squad: {squad.name}")
    print(f"Agents: {[a.name for a in squad.agents.values()]}")
    
    # Simulate alert
    alert = {
        "title": "Suspicious network activity detected",
        "source_ip": "192.0.2.100",
        "dest_ip": "203.0.113.50",
        "port": 443,
        "severity": "high",
        "source": "IDS",
        "type": "network_anomaly",
    }
    
    print(f"\nReceived alert: {alert['title']}")
    
    # Triage alert
    triage_result = await triage_agent.triage_alert(alert)
    if triage_result.get("success"):
        triage_data = triage_result["triage_result"]
        print("\nTriage completed:")
        print(f"  Alert ID: {triage_data['alert_id']}")
        print(f"  Severity: {triage_data['severity']}")
        print(f"  Recommended action: {triage_data['recommended_action']}")
        print(f"  Enriched IOCs: {len(triage_data.get('enriched_iocs', []))}")
    
    # Investigate
    if triage_result.get("success"):
        alert_id = triage_result["triage_result"]["alert_id"]
        investigation = await investigator_agent.investigate(
            alert_id=alert_id,
            query="suspicious network activity"
        )
        
        if investigation.get("success"):
            inv_data = investigation["investigation"]
            print("\nInvestigation completed:")
            print(f"  Log results: {inv_data['log_results_count']}")
            print(f"  Enriched IOCs: {len(inv_data.get('enriched_iocs', []))}")
            print(f"  Hypothesis: {inv_data.get('hypothesis', 'N/A')}")


async def demo_sandbox_analysis():
    """Demo: Sandbox malware analysis"""
    print("\n=== Demo: Sandbox Analysis ===")
    
    umb = UMBAdapter(backend="simple")
    
    # Create sandbox MCP
    sandbox = SandboxMCP()
    await sandbox.connect()
    
    # Create analyst agent
    analyst = SandboxAnalystAgent(
        name="SandboxAnalyst",
        memory_ref=umb,
        sandbox_mcp=sandbox,
    )
    
    print(f"Created analyst: {analyst.name}")
    
    # Analyze artifact
    artifact_hash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    print(f"\nAnalyzing artifact: {artifact_hash[:16]}...")
    
    analysis = await analyst.analyze_artifact(
        artifact_hash=artifact_hash,
        artifact_type="file"
    )
    
    if analysis.get("success"):
        analysis_data = analysis["analysis"]
        print("\nAnalysis completed:")
        print(f"  Risk level: {analysis_data['risk_level']}")
        print(f"  Network indicators: {len(analysis_data.get('network_indicators', []))}")
        print(f"  Recommendation: {analysis_data.get('recommendation', 'N/A')}")


async def demo_password_audit():
    """Demo: Password policy audit"""
    print("\n=== Demo: Password Policy Audit ===")
    
    umb = UMBAdapter(backend="simple")
    
    # Create password audit MCP
    password_audit = PasswordAuditMCP()
    await password_audit.connect()
    
    # Create compliance agent
    compliance_agent = ComplianceAgent(
        name="ComplianceAgent",
        memory_ref=umb,
        password_audit_mcp=password_audit,
    )
    
    print(f"Created compliance agent: {compliance_agent.name}")
    
    # Define policy
    policy_config = {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special": False,
    }
    
    # Sample password hashes (never cleartext)
    password_hashes = [
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    ]
    
    print("\nAuditing password policy...")
    print(f"  Policy: min_length={policy_config['min_length']}")
    print(f"  Sample hashes: {len(password_hashes)}")
    
    # Audit
    audit_result = await compliance_agent.audit_password_policy(
        policy_config=policy_config,
        password_hashes=password_hashes
    )
    
    if audit_result.get("success"):
        audit_data = audit_result["audit"]
        print("\nAudit completed:")
        print(f"  Compliance score: {audit_data.get('compliance_score', 0):.2f}")
        print(f"  Violations: {len(audit_data.get('violations', []))}")
        print(f"  Recommendations: {len(audit_data.get('recommendations', []))}")
        
        for rec in audit_data.get("recommendations", []):
            print(f"    - {rec}")


async def demo_incident_response():
    """Demo: Incident response with containment"""
    print("\n=== Demo: Incident Response ===")
    
    umb = UMBAdapter(backend="simple")
    
    # Create governance
    governance = GovernanceEngine()
    
    # Create response action MCP
    response_action = ResponseActionMCP()
    await response_action.connect()
    
    # Create responder agent
    responder = ResponderAgent(
        name="ResponderAgent",
        memory_ref=umb,
        response_action_mcp=response_action,
        governance=governance,
    )
    
    print(f"Created responder: {responder.name}")
    
    # Simulate incident
    incident_id = "INC-2024-001"
    host_id = "HOST-12345"
    reason = "Malicious activity detected"
    
    print(f"\nIncident: {incident_id}")
    print(f"  Host: {host_id}")
    print(f"  Reason: {reason}")
    
    # Contain incident
    containment = await responder.contain_incident(
        incident_id=incident_id,
        host_id=host_id,
        reason=reason
    )
    
    if containment.get("success"):
        print("\nContainment completed:")
        print(f"  Actions taken: {len(containment.get('actions', []))}")
        for action in containment.get("actions", []):
            if action.get("success"):
                print(f"    - {action.get('action_id', 'N/A')}: {action.get('status', 'N/A')}")


async def demo_threat_hunting():
    """Demo: Proactive threat hunting"""
    print("\n=== Demo: Threat Hunting ===")
    
    umb = UMBAdapter(backend="simple")
    
    # Create log analysis MCP
    log_analysis = LogAnalysisMCP()
    await log_analysis.connect()
    
    # Create threat hunter
    hunter = ThreatHuntingAgent(
        name="ThreatHunter",
        memory_ref=umb,
        log_analysis_mcp=log_analysis,
    )
    
    print(f"Created hunter: {hunter.name}")
    
    # Hunt for pattern
    pattern = "suspicious_process_execution"
    print(f"\nHunting for pattern: {pattern}")
    
    hunt_result = await hunter.hunt(
        pattern=pattern,
        time_range={"start": "7d", "end": "now"}
    )
    
    if hunt_result.get("success"):
        print("\nHunt completed:")
        print(f"  Pattern: {hunt_result['pattern']}")
        print(f"  Anomalies found: {len(hunt_result.get('anomalies', []))}")
        summary = hunt_result.get("summary", {})
        print(f"  Risk level: {summary.get('risk_level', 'N/A')}")


async def demo_full_workflow():
    """Demo: Complete security workflow"""
    print("\n=== Demo: Complete Security Workflow ===")
    
    # Setup
    umb = UMBAdapter(backend="simple")
    governance = GovernanceEngine()
    
    # Create all MCPs
    alert_ingest = AlertIngestMCP()
    await alert_ingest.connect()
    
    threat_intel = ThreatIntelMCP()
    await threat_intel.connect()
    
    model_hub = ModelHubMCP()
    await model_hub.connect()
    
    log_analysis = LogAnalysisMCP()
    await log_analysis.connect()
    
    sandbox = SandboxMCP()
    await sandbox.connect()
    
    response_action = ResponseActionMCP()
    await response_action.connect()
    
    # Create security squad
    squad = Squad(name="Security Operations Squad", shared_memory_ref=umb)
    
    # Create agents
    triage = TriageAgent(
        name="TriageAgent",
        memory_ref=umb,
        alert_ingest_mcp=alert_ingest,
        threat_intel_mcp=threat_intel,
        model_hub_mcp=model_hub,
    )
    
    investigator = InvestigatorAgent(
        name="InvestigatorAgent",
        memory_ref=umb,
        log_analysis_mcp=log_analysis,
        threat_intel_mcp=threat_intel,
    )
    
    analyst = SandboxAnalystAgent(
        name="SandboxAnalyst",
        memory_ref=umb,
        sandbox_mcp=sandbox,
    )
    
    responder = ResponderAgent(
        name="ResponderAgent",
        memory_ref=umb,
        response_action_mcp=response_action,
        governance=governance,
    )
    
    reviewer = ReviewerAgent(
        name="ReviewerAgent",
        memory_ref=umb,
    )
    
    # Add to squad
    squad.add_agent(triage, SquadRole.WORKER)
    squad.add_agent(investigator, SquadRole.WORKER)
    squad.add_agent(analyst, SquadRole.WORKER)
    squad.add_agent(responder, SquadRole.WORKER)
    squad.add_agent(reviewer, SquadRole.REVIEWER)
    
    print(f"Created security squad: {squad.name}")
    print(f"Agents: {len(squad.agents)}")
    
    # Create mission
    mission = squad.create_mission(
        goal="Investigate and respond to security incident",
        description="End-to-end security incident response"
    )
    
    print(f"\nCreated mission: {mission.goal}")
    
    # Simulate workflow
    alert = {
        "title": "Potential malware detected",
        "source_ip": "192.0.2.100",
        "file_hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        "severity": "high",
        "source": "EDR",
        "type": "malware_detection",
    }
    
    print(f"\n1. Triage alert: {alert['title']}")
    triage_result = await triage.triage_alert(alert)
    
    if triage_result.get("success"):
        alert_id = triage_result["triage_result"]["alert_id"]
        print(f"   Alert ID: {alert_id}")
        
        print("\n2. Investigate alert")
        investigation = await investigator.investigate(alert_id, "malware detection")
        print("   Investigation completed")
        
        print("\n3. Analyze artifact in sandbox")
        artifact_hash = alert.get("file_hash", "")
        analysis = await analyst.analyze_artifact(artifact_hash, "file")
        print(f"   Risk level: {analysis.get('analysis', {}).get('risk_level', 'N/A')}")
        
        print("\n4. Review recommendation")
        recommendation = {
            "id": "rec-001",
            "risk_level": "high",
            "action": "isolate_host",
        }
        review = await reviewer.review_recommendation(recommendation, {"verified": True})
        print(f"   Approved: {review.get('review', {}).get('approved', False)}")
        
        if review.get("review", {}).get("approved"):
            print("\n5. Contain incident")
            containment = await responder.contain_incident(
                incident_id=alert_id,
                host_id="HOST-12345",
                reason="Malware detected"
            )
            print(f"   Containment completed: {containment.get('success', False)}")
    
    print("\nMission workflow completed!")


async def main():
    """Run all cybersecurity demos"""
    print("=" * 60)
    print("AgentOS Cybersecurity Extension Demo")
    print("=" * 60)
    
    await demo_alert_triage_workflow()
    await demo_sandbox_analysis()
    await demo_password_audit()
    await demo_incident_response()
    await demo_threat_hunting()
    await demo_full_workflow()
    
    print("\n" + "=" * 60)
    print("Cybersecurity demos complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

