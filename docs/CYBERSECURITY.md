# AgentOS Cybersecurity Extension

## Overview

The AgentOS Cybersecurity Extension provides safe, defensive, and enterprise-focused tools for security operations. All components are designed with safety, auditability, and compliance in mind.

## Safety Principles

1. **Defensive Only**: All tools are defensive and do not enable unauthorized access or exploitation
2. **Human-in-Loop**: Critical actions require human approval
3. **Audit Trail**: All actions are logged immutably
4. **Policy Enforcement**: Governance engine enforces safety policies
5. **Data Protection**: Sensitive data is encrypted and redacted

## MCP Connectors

### AlertIngestMCP
- **Purpose**: Ingest and normalize security alerts from SIEMs, IDS, firewalls
- **Skills**: `ingest_alert`, `normalize_alerts`
- **Data Sensitivity**: Confidential
- **Usage**: Entry point for security incidents

### LogAnalysisMCP
- **Purpose**: Secure log indexing and search
- **Skills**: `search_logs`, `analyze_pattern`
- **Data Sensitivity**: Confidential
- **Usage**: Historical log analysis and pattern detection

### ThreatIntelMCP
- **Purpose**: Enrich IOCs with threat intelligence
- **Skills**: `enrich_ioc`, `check_reputation`
- **Data Sensitivity**: Public (cached and scrubbed)
- **Usage**: IOC enrichment and reputation checking

### SandboxMCP
- **Purpose**: Isolated dynamic analysis of artifacts
- **Skills**: `analyze_artifact`, `get_analysis`
- **Data Sensitivity**: Confidential
- **Safety**: Only accepts hashes, never raw artifacts
- **Usage**: Malware analysis in isolated environment

### PasswordAuditMCP
- **Purpose**: Non-destructive password policy auditing
- **Skills**: `audit_policy`, `check_breach`
- **Data Sensitivity**: Confidential
- **Safety**: Only accepts hashed passwords, never cleartext
- **Usage**: Password policy compliance checking

### ResponseActionMCP
- **Purpose**: Execute pre-approved containment/remediation
- **Skills**: `isolate_host`, `revoke_credentials`, `create_ticket`
- **Data Sensitivity**: Confidential
- **Safety**: All actions require approval and are logged
- **Usage**: Incident response and containment

### ModelHubMCP
- **Purpose**: Proxy to LLMs with safety controls
- **Skills**: `call_llm`, `classify`
- **Data Sensitivity**: Confidential
- **Safety**: Redacts sensitive data, enforces quotas
- **Usage**: AI-assisted analysis and classification

## Agent Types

### TriageAgent
- **Role**: Alert triage and classification
- **Skills**: Alert analysis, classification, deduplication
- **Uses**: AlertIngestMCP, ThreatIntelMCP, ModelHubMCP
- **Output**: Triage results with severity and recommendations

### InvestigatorAgent
- **Role**: Deep investigation and correlation
- **Skills**: Log analysis, IOC enrichment, correlation
- **Uses**: LogAnalysisMCP, ThreatIntelMCP
- **Output**: Investigation results with hypotheses

### SandboxAnalystAgent
- **Role**: Malware and artifact analysis
- **Skills**: Behavior analysis, artifact analysis
- **Uses**: SandboxMCP
- **Output**: Analysis results with risk assessment

### ComplianceAgent
- **Role**: Policy compliance auditing
- **Skills**: Password audit, policy analysis
- **Uses**: PasswordAuditMCP
- **Output**: Compliance reports and recommendations

### ResponderAgent
- **Role**: Incident response and containment
- **Skills**: Containment, remediation orchestration
- **Uses**: ResponseActionMCP, Governance
- **Safety**: Requires policy checks and approval
- **Output**: Containment actions and tickets

### ThreatHuntingAgent
- **Role**: Proactive threat detection
- **Skills**: Pattern detection, anomaly detection
- **Uses**: LogAnalysisMCP, UMB memory
- **Output**: Threat hunting results

### ReviewerAgent
- **Role**: Independent verification
- **Skills**: Review, validation
- **Uses**: UMB memory
- **Output**: Review results with approval/rejection

## Workflows

### Alert → Triage → Investigation → Response

1. **TriageAgent** receives alert
2. Normalizes and enriches with threat intelligence
3. Classifies using AI model
4. **InvestigatorAgent** investigates
5. Queries logs and correlates IOCs
6. **SandboxAnalystAgent** analyzes artifacts if needed
7. **ReviewerAgent** reviews recommendations
8. **ResponderAgent** executes containment (with approval)

### Password Policy Audit

1. **ComplianceAgent** receives policy config and hashes
2. Audits policy compliance
3. Checks breach databases (k-anonymity safe)
4. Generates compliance report
5. Creates remediation tickets

### Threat Hunting

1. **ThreatHuntingAgent** defines hunting pattern
2. Searches historical logs
3. Analyzes patterns for anomalies
4. Correlates with UMB memory
5. Generates threat hunting report

## Safety Features

### Human-in-Loop Gates

Critical actions require human approval:
- Host isolation
- Credential revocation
- High-risk containment actions

### Policy Enforcement

All actions are checked against governance policies:
- Action policies (allow/deny)
- Resource policies (limits)
- Privacy policies (data sharing)

### Audit Trail

Every action is logged:
- Action type and parameters
- Agent ID and timestamp
- Approval status and approver
- Policy decisions

### Data Protection

- Encrypted vectors in UMB
- Sensitive data redaction in ModelHubMCP
- Hash-only inputs in PasswordAuditMCP
- Isolated execution in SandboxMCP

## Usage Examples

### Basic Triage

```python
from agentos.core.cybersecurity_agents import TriageAgent
from agentos.mcp_connectors.security_mcp import AlertIngestMCP, ThreatIntelMCP, ModelHubMCP

# Create MCPs
alert_ingest = AlertIngestMCP()
threat_intel = ThreatIntelMCP()
model_hub = ModelHubMCP()

# Create agent
triage = TriageAgent(
    alert_ingest_mcp=alert_ingest,
    threat_intel_mcp=threat_intel,
    model_hub_mcp=model_hub,
)

# Triage alert
alert = {
    "title": "Suspicious activity",
    "source_ip": "192.0.2.100",
    "severity": "high",
}
result = await triage.triage_alert(alert)
```

### Incident Response

```python
from agentos.core.cybersecurity_agents import ResponderAgent
from agentos.mcp_connectors.security_mcp import ResponseActionMCP
from agentos.core.governance import GovernanceEngine

# Create governance and MCP
governance = GovernanceEngine()
response_action = ResponseActionMCP()

# Create responder
responder = ResponderAgent(
    response_action_mcp=response_action,
    governance=governance,
)

# Contain incident (requires approval)
result = await responder.contain_incident(
    incident_id="INC-001",
    host_id="HOST-123",
    reason="Malware detected"
)
```

## Running the Demo

```bash
python agentos/demo_cybersecurity.py
```

This demonstrates:
- Alert triage workflow
- Sandbox analysis
- Password policy audit
- Incident response
- Threat hunting
- Complete security workflow

## Integration with AgentOS

The cybersecurity extension integrates seamlessly with AgentOS:

- **Squads**: Security agents work in hierarchical squads
- **UMB**: Shared memory for threat intelligence and findings
- **Governance**: Policy enforcement for all security actions
- **Planning**: MAGP for complex security workflows
- **Routing**: DMARP for intelligent agent assignment

## Best Practices

1. **Always use governance**: Enforce policies on all security actions
2. **Require approvals**: Enable human-in-loop for critical actions
3. **Audit everything**: Log all security operations
4. **Isolate sandboxes**: Deploy SandboxMCP in isolated network
5. **Protect data**: Encrypt and redact sensitive information
6. **Monitor resources**: Track API usage and costs
7. **Review regularly**: Use ReviewerAgent for validation

## Limitations

- **No exploitation tools**: Framework does not provide exploitation capabilities
- **No password cracking**: Only policy auditing, not cracking
- **Defensive only**: All tools are for defensive security operations
- **Requires approval**: Critical actions need human approval

## Future Enhancements

- Integration with commercial SIEMs
- Advanced ML models for classification
- Real-time threat intelligence feeds
- Automated playbook execution
- Integration with ITSM systems

