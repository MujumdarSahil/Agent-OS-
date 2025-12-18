# AgentOS CyberCore - Enterprise Cybersecurity Subsystem

## Overview

CyberCore is a complete enterprise-grade cybersecurity subsystem for AgentOS, providing safe, defensive, and production-ready security tools. All components are designed with safety, auditability, and compliance in mind.

## Safety Principles

✅ **Defensive Only** - All tools are defensive and do not enable unauthorized access  
✅ **No Password Cracking** - Only policy auditing and breach checks (k-anonymity)  
✅ **No Exploitation** - Red team agent is simulation-only  
✅ **Human-in-Loop** - Critical actions require human approval  
✅ **Full Audit Trail** - All actions are logged immutably  
✅ **Data Protection** - Sensitive data is encrypted and redacted  

## Architecture

```
cybercore/
├── mcp/              # MCP Servers
│   ├── password_audit_mcp.py
│   ├── threat_intel_mcp.py
│   ├── log_analysis_mcp.py
│   └── sandbox_mcp.py
├── agents/           # Cybersecurity Agents
│   ├── triage_agent.py
│   ├── investigator_agent.py
│   ├── sandbox_analysis_agent.py
│   ├── compliance_agent.py
│   ├── threat_hunt_agent.py
│   └── redteam_sim_agent.py
├── tools/            # Security Tools
│   ├── hash_identifier.py
│   ├── password_entropy_estimator.py
│   ├── breach_check_k_anonymity.py
│   ├── yara_scanner.py
│   ├── log_pattern_detector.py
│   └── ioc_normalizer.py
├── squads/           # Security Squads
│   ├── soc_squad.py
│   ├── incident_response_squad.py
│   ├── compliance_squad.py
│   └── redteam_sim_squad.py
├── missions/         # Security Missions
│   ├── alert_to_resolution.py
│   ├── password_audit_mission.py
│   └── redteam_lab_simulation.py
└── utils/            # Utilities
    ├── validation.py
    ├── crypto_utils.py
    ├── normalization.py
    └── log_parsers.py
```

## Components

### MCP Servers

1. **PasswordAuditMCP** - Safe password policy auditing
   - Hash type identification (20+ types)
   - Entropy estimation (mathematical only)
   - Breach checks using k-anonymity
   - NIST 800-63 policy evaluation

2. **ThreatIntelMCP** - IOC enrichment
   - IP, domain, URL, hash enrichment
   - Reputation checking
   - Threat scoring

3. **LogAnalysisMCP** - Log parsing and analysis
   - Windows Event Logs
   - Linux syslogs
   - Authentication logs
   - Pattern detection with MITRE ATT&CK tagging

4. **SandboxMCP** - Isolated malware analysis
   - File submission (hash-based)
   - Behavior reports
   - Network indicators
   - NO arbitrary command execution

### Agents

1. **TriageAgent** - Alert triage and classification
2. **InvestigatorAgent** - Deep investigation and correlation
3. **SandboxAnalysisAgent** - Malware behavior analysis
4. **ComplianceAgent** - Policy compliance auditing
5. **ThreatHuntAgent** - Proactive threat hunting
6. **RedTeamSimAgent** - Safe red team simulation (SIMULATION ONLY)

### Tools

1. **HashIdentifier** - Identify 20+ hash types
2. **PasswordEntropyEstimator** - Calculate entropy (mathematical only)
3. **BreachCheckKAnonymity** - Safe breach checking (k-anonymity)
4. **YARAScanner** - File scanning with YARA rules
5. **LogPatternDetector** - Detect suspicious patterns with MITRE ATT&CK
6. **IOCNormalizer** - Normalize and sanitize IOCs

### Squads

1. **SOCSquad** - Security Operations Center
2. **IncidentResponseSquad** - Incident response team
3. **ComplianceSquad** - Compliance auditing
4. **RedTeamSimSquad** - Red team simulation (SIMULATION ONLY)

### Missions

1. **AlertToResolutionMission** - End-to-end alert handling
2. **PasswordAuditMission** - Password policy audit
3. **RedTeamLabSimulationMission** - Safe red team simulation

## Usage Examples

### Password Policy Audit

```python
from agentos.cybercore.mcp.password_audit_mcp import PasswordAuditMCP
from agentos.cybercore.agents.compliance_agent import ComplianceAgent

# Create MCP
password_audit = PasswordAuditMCP()
await password_audit.connect()

# Create agent
compliance = ComplianceAgent(password_audit_mcp=password_audit)

# Audit policy
policy = {
    "min_length": 8,
    "require_uppercase": True,
    "require_digits": True,
}
hashes = ["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"]

result = await compliance.audit_password_policy(policy, hashes)
```

### Alert Triage

```python
from agentos.cybercore.agents.triage_agent import TriageAgent
from agentos.cybercore.mcp.threat_intel_mcp import ThreatIntelMCP

# Create MCPs
threat_intel = ThreatIntelMCP()
await threat_intel.connect()

# Create agent
triage = TriageAgent(threat_intel_mcp=threat_intel)

# Triage alert
alert = {
    "title": "Suspicious activity",
    "source_ip": "192.0.2.100",
    "severity": "high",
}

result = await triage.triage_alert(alert)
```

### SOC Squad

```python
from agentos.cybercore.squads.soc_squad import SOCSquad
from agentos.core.umb_adapter import UMBAdapter

# Create squad
umb = UMBAdapter()
squad = SOCSquad.create(
    shared_memory_ref=umb,
    triage_mcps={"threat_intel_mcp": threat_intel},
    investigator_mcps={"log_analysis_mcp": log_analysis},
    sandbox_mcp=sandbox,
)

# Create and start mission
mission = squad.create_mission(goal="Investigate security alert")
await squad.start_mission(mission.id)
```

## Safety Guarantees

- ✅ **No Password Cracking** - Only policy auditing and safe breach checks
- ✅ **No Exploitation** - Red team agent is simulation-only
- ✅ **Hash-Only Inputs** - Password tools only accept hashes, never cleartext
- ✅ **Isolated Sandbox** - Sandbox runs in isolated environment
- ✅ **Human Approval** - Critical actions require explicit approval
- ✅ **Full Logging** - All actions are logged immutably

## Integration

CyberCore integrates seamlessly with AgentOS:

- Uses AgentOS core (Agent, Squad, UMB, Governance)
- Follows AgentOS patterns and conventions
- Extends existing cybersecurity components
- Compatible with all AgentOS features

## Requirements

- Python 3.11+
- AgentOS core framework
- Optional: yara-python (for YARA scanner)
- Optional: python-dotenv (for ModelHub)

## License

MIT - Same as AgentOS

