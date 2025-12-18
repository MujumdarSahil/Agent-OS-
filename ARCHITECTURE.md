# AgentOS Architecture

## Overview

AgentOS is a production-grade multi-agent framework designed for enterprise use, research, and startup deployment. It provides a comprehensive platform for orchestrating autonomous agents with advanced team behaviors, memory sharing, governance, and skill management.

## Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  AgentOS Orchestration Layer                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Task Router  │  │   Planner    │  │  Governance  │     │
│  │   (DMARP)    │  │   (MAGP)     │  │   Engine     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │ UMB Adapter  │  │  Resource    │                         │
│  │              │  │  Monitor     │                         │
│  └──────────────┘  └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼──────┐   ┌───────▼──────┐   ┌───────▼──────┐
│   Squad A    │   │   Squad B    │   │  Federation  │
│ ┌──────────┐ │   │ ┌──────────┐ │   │    Layer     │
│ │Commander │ │   │ │Commander │ │   │              │
│ │  Leader  │ │   │ │  Leader  │ │   │              │
│ │  Agents  │ │   │ │  Agents  │ │   │              │
│ │  Memory  │ │   │ │  Memory  │ │   │              │
│ └──────────┘ │   │ └──────────┘ │   │              │
└──────────────┘   └──────────────┘   └──────────────┘
        │                   │
        └───────────────────┘
                    │
        ┌───────────▼───────────┐
        │   MCP Servers / DMSG   │
        │  ┌──────────────────┐  │
        │  │ File MCP         │  │
        │  │ Scraper MCP     │  │
        │  │ Build MCP       │  │
        │  │ PAT-MCP         │  │
        │  │ Network Monitor │  │
        │  │ System Audit    │  │
        │  │ Custom MCPs     │  │
        │  │ Custom MCPs     │  │
        │  └──────────────────┘  │
        └───────────────────────┘
```

## Component Details

### 1. Core Layer

#### Agent (`core/agent.py`)
- **Purpose**: Autonomous entity with skills, memory, and execution
- **Features**:
  - Identity management (personality, reputation)
  - Skill vectors and tool registry
  - Resource quota tracking
  - Planning and execution capabilities
  - Memory integration via UMB
  - Ability to load security tools into skill registry via `load_security_tools()`

#### Squad (`core/squad.py`)
- **Purpose**: Hierarchical team of agents
- **Features**:
  - Role hierarchy (Commander → Leader → Worker → Reviewer)
  - Shared memory access
  - Mission management
  - Agent assignment and coordination

#### Governance Engine (`core/governance.py`)
- **Purpose**: Policy enforcement and safety
- **Policy Types**:
  - Action policies (allow/deny tool usage)
  - Privacy policies (memory sharing)
  - Resource policies (limits)
  - Safety policies (constraints)
- **Features**:
  - Priority-based policy evaluation
  - Context-aware decisions
  - Audit trail support

#### Planner (`core/planner.py`)
- **Purpose**: Convert goals into task graphs (MAGP)
- **Features**:
  - Semantic task decomposition
  - Dependency graph creation
  - Critical path analysis
  - Parallelization optimization
  - Multi-agent negotiation support

#### Task Router (`core/router.py`)
- **Purpose**: Assign tasks to agents (DMARP)
- **Strategies**:
  - Skill matching
  - Reputation-based
  - Load balancing
  - Cost optimization
  - Hybrid (weighted combination)
- **Features**:
  - Multi-factor scoring
  - Constraint handling
  - Assignment reasoning

### 2. Memory Layer

#### UMB Adapter (`core/umb_adapter.py`)
- **Purpose**: Unified Memory Bus for semantic memory
- **Backends**:
  - Simple (in-memory, MVP)
  - FAISS (production)
  - Chroma (production)
  - PostgreSQL vector extension (enterprise)
- **Memory Layers**:
  - Squad Shared
  - Mission Scoped
  - Agent Private
  - Episodic
  - Autobiographical
- **Features**:
  - Semantic search
  - Scope-based filtering
  - Permission enforcement
  - GDPR-compliant revocation

### 3. Skill Layer

#### DMSG Registry (`dmsg/registry.py`)
- **Purpose**: Register and manage MCP servers
- **Features**:
  - MCP node registration
  - Skill indexing
  - Domain organization
  - Trust scoring
  - Auto-registration of security MCPs with domain="cybersecurity"
  - PAT-MCP, Network Monitor MCP, and System Audit MCP auto-registered on initialization

#### Pathfinder (`dmsg/pathfinder.py`)
- **Purpose**: Find optimal skill execution paths
- **Features**:
  - Greedy path finding
  - Cost optimization
  - Latency optimization
  - Trust-based filtering
  - Alternative path discovery

### 4. Cybersecurity Tool Layer

#### Security MCP Servers (`mcp/security/`)

The cybersecurity tool layer provides safe, ethical, and defensive security automation capabilities through specialized MCP servers.

##### Password Audit Tool MCP (PAT-MCP) (`mcp/security/pat_mcp.py`)
- **Purpose**: Safe password auditing and policy evaluation
- **Methods**:
  - `hash_type()`: Identify password hash type
  - `hash_strength()`: Benchmark hash strength (mathematical only)
  - `dictionary_strength_simulation()`: Simulate dictionary attack strength (no real cracking)
  - `password_policy_eval()`: Evaluate password policy against NIST 800-63
  - `ai_pattern_detector()`: AI-based weak pattern detection
- **Safety**: Mathematical evaluation only, NO real cracking

##### Network Monitor MCP (`mcp/security/network_monitor_mcp.py`)
- **Purpose**: Safe network monitoring and anomaly detection
- **Methods**:
  - `detect_open_ports_metadata()`: Detect open ports from metadata (no active scanning)
  - `detect_port_scans_behavior()`: Detect port scan patterns from log metadata
  - `detect_network_anomalies()`: Detect anomalies in network logs
  - `parse_logs_for_events()`: Parse logs for security events
  - `classify_incident()`: AI-based incident classification
- **Safety**: Read-only log analysis only. No active network probing.

##### System Audit MCP (`mcp/security/system_audit_mcp.py`)
- **Purpose**: Safe system configuration auditing
- **Methods**:
  - `audit_firewall_status()`: Audit firewall configuration
  - `audit_config_security()`: Audit system configuration files
  - `check_user_permissions()`: Check user permissions
  - `analyze_running_services()`: Analyze running services
  - `generate_hardening_recommendations()`: Generate hardening recommendations
  - `detect_misconfigurations()`: Detect security misconfigurations
- **Safety**: Read-only operations only. No system modifications.

#### Security Agents (`agents/`)

##### SecurityAgent (`agents/security_agent.py`)
- **Purpose**: Specialized agent for cybersecurity operations
- **Inherits from**: `core.agent.Agent` (BaseAgent)
- **Built-in Roles**:
  - `auditor`: Performs security audits and compliance checks
  - `monitor`: Monitors network and system activity
  - `analyst`: Analyzes security events and incidents
  - `policy-advisor`: Provides security policy recommendations
- **Features**:
  - Auto-bind security MCP servers (PAT-MCP, Network Monitor MCP, System Audit MCP)
  - Auto-store mission results into UMB
  - Support squad collaboration
  - Load security tools into skill registry

##### ScriptAuthorAgent (`agents/script_author_agent.py`)
- **Purpose**: Generates ONLY DEFENSIVE / EDUCATIONAL security scripts
- **Inherits from**: `core.agent.Agent` (BaseAgent)
- **Governance**: Enforces governance pre-check BEFORE script is returned
- **Supported Languages**: Bash, Python, PowerShell
- **Allowed Scripts**:
  - firewall config (ufw/iptables/windows)
  - log analysis
  - SIEM ingestion scripts
  - permission and user audits
  - network metadata inventory
  - config audit automation
- **Forbidden**:
  - exploits
  - malware
  - cracking scripts
  - payload generators
  - active scanning

#### Security Safety Layer (`core/governance.py`)

The Governance Engine includes a Security Safety Layer with explicit allow/deny lists:

- **Allow List**:
  - password auditing
  - metadata-based network monitoring
  - configuration auditing
  - defensive cybersecurity scripts

- **Deny List**:
  - exploit code
  - malware or payload generation
  - password cracking or brute-force attempts
  - intrusive/active scanning
  - privilege escalation automation

- **Pattern Scanning**: All ScriptAuthorAgent output is pattern-scanned before return
- **Security Tool Routing**: All security tools route through this layer

#### Security Mission Examples (`missions/security_missions.py`)

1. **Enterprise Password Audit Mission**
   - Workflow: SecurityAgent (auditor) → PAT-MCP
   - Strength evaluation using hash_strength()
   - Weak pattern detection using ai_pattern_detector()
   - ScriptAuthorAgent → remediation scripts
   - Save report to UMB

2. **Network Health Check Mission**
   - Workflow: NetworkMonitorMCP → log analysis
   - Detect anomalies using detect_network_anomalies()
   - Detect port scan behavior using detect_port_scans_behavior()
   - SecurityAgent (analyst) → incident report
   - ScriptAuthorAgent → SIEM ingestion script

3. **System Hardening Mission**
   - Workflow: SystemAuditMCP → config audit
   - Audit firewall using audit_firewall_status()
   - Audit config using audit_config_security()
   - SecurityAgent (auditor) → hardening report
   - ScriptAuthorAgent → config hardening script

### 5. Communication Layer

#### WebSocket Server (`comms/websocket_server.py`)
- **Purpose**: Real-time agent collaboration
- **Features**:
  - Per-agent channels
  - Per-squad channels
  - Per-mission channels
  - Event broadcasting
  - Handler registration

### 6. Resource Layer

#### Resource Monitor (`core/resource_monitor.py`)
- **Purpose**: Track and monitor resource usage
- **Metrics**:
  - Token usage
  - API calls
  - CPU percentage
  - Memory usage
  - Wall time
  - Cost estimates
- **Features**:
  - Real-time monitoring
  - Historical tracking
  - Snapshot capability

### 7. Advanced Features

#### Composite Agent (`core/composite_agent.py`)
- **Purpose**: Merge multiple agents temporarily
- **Merge Policies**:
  - Union (all skills)
  - Intersection (common skills)
  - Weighted (reputation-based)
- **Features**:
  - Skill merging
  - Personality merging
  - Memory reference merging
  - Tool aggregation
  - Temporary/permanent modes

## Data Flow

### Mission Execution Flow

```
1. Goal Input
   ↓
2. Planner creates TaskGraph (MAGP)
   ↓
3. Router assigns tasks to agents (DMARP)
   ↓
4. Governance checks policies
   ↓
5. Agents execute tasks
   ↓
6. Results stored in UMB
   ↓
7. WebSocket events broadcast
   ↓
8. Resource monitor tracks usage
   ↓
9. Mission completion
```

### Memory Access Flow

```
Agent Request
   ↓
UMB Adapter
   ↓
Scope Filter (Squad/Mission/Agent)
   ↓
Permission Check (Governance)
   ↓
Vector Search
   ↓
Results (filtered by permissions)
```

### Skill Execution Flow

```
Task requires skills
   ↓
Pathfinder finds MCP path (DMSG)
   ↓
Governance checks security policies
   ↓
MCP Connector calls skill
   ↓
Result returned to agent
   ↓
Stored in memory (UMB)
```

### Security Mission Flow

```
Security Mission Goal
   ↓
SecurityAgent requests security MCP tools
   ↓
Governance Engine validates (security policies)
   ↓
MCP executes defensive/audit operation
   ↓
Results analyzed and classified
   ↓
Incident report / Advisory generated
   ↓
Stored in UMB (mission-scoped)
```

#### PAT-MCP Workflow

```
Password Audit Request
   ↓
Hash Identification
   ↓
Strength Benchmarking (mathematical)
   ↓
Policy Evaluation (NIST 800-63)
   ↓
Weak Pattern Detection
   ↓
Audit Report Generated
```

#### Network Monitor MCP Workflow

```
Network Logs Input
   ↓
Metadata Analysis
   ↓
Port Scan Detection (pattern analysis)
   ↓
Anomaly Detection (statistical)
   ↓
Incident Classification (AI-based)
   ↓
Incident Report Generated
```

#### System Audit MCP Workflow

```
System Configuration Input
   ↓
Configuration Audit
   ↓
Firewall Rule Validation
   ↓
Log Scanning
   ↓
Vulnerability Advisory Generation
   ↓
Hardening Recommendations
```

## Security & Safety

### General Security

1. **Policy Enforcement**: All actions checked before execution
2. **Sandboxed Execution**: Tools run in isolated environments
3. **Audit Trail**: All decisions logged immutably
4. **Human-in-Loop**: Configurable approval gates
5. **Data Protection**: Encrypted vectors, PII redaction
6. **Access Control**: Per-agent, per-squad ACLs

### Cybersecurity Tool Layer Safety Constraints

#### Prohibited Operations

The cybersecurity tool layer **strictly prohibits**:

- ❌ **Exploit Code Generation**: No code that exploits vulnerabilities
- ❌ **Malware Creation**: No trojans, viruses, backdoors, or malicious software
- ❌ **Password Cracking**: No actual password cracking or brute-force attacks
- ❌ **Unauthorized Access**: No attempts to gain unauthorized system access
- ❌ **Active Scanning**: No active network probing or port scanning
- ❌ **System Modification**: No changes to system configurations (read-only)

#### Allowed Operations

The cybersecurity tool layer **safely allows**:

- ✅ **Password Auditing**: Policy evaluation, hash identification, strength benchmarking
- ✅ **Monitoring**: Log analysis, anomaly detection, metadata analysis
- ✅ **System Hardening**: Configuration checks, firewall validation, compliance auditing
- ✅ **Defensive Scripts**: Firewall configuration, log analysis, security monitoring
- ✅ **Educational Tools**: Security awareness, training, and best practices

#### Safety Guarantees

1. **Governance Engine Integration**: All security operations pass through governance checks
2. **Pattern Detection**: Scripts are scanned for prohibited patterns before execution
3. **Read-Only Operations**: System audit tools only read, never modify
4. **Hash-Only Inputs**: Password tools only accept hashes, never cleartext passwords
5. **Metadata Analysis**: Network monitoring analyzes logs only, no active probing
6. **Compliance Focus**: All tools designed for defensive, educational, and compliance purposes

#### Compliance Notes

- All security tools comply with ethical cybersecurity practices
- Designed for defensive security operations and compliance auditing
- Suitable for enterprise security teams, SOC operations, and security research
- No offensive security capabilities or attack tools

## Scalability

- **Horizontal**: Multiple squads, federation support
- **Vertical**: Resource monitoring, adaptive behavior
- **Memory**: Pluggable backends (FAISS, Chroma, PG)
- **Communication**: WebSocket for real-time, gRPC for high-throughput

## Extensibility

- **Plugin System**: Custom agents, MCPs, policies
- **Templates**: Agent, MCP connector templates
- **CLI Tools**: create-squad, start-mission, inspect-mission
- **API**: REST and gRPC interfaces (planned)

## Research Components

1. **DMARP**: Dynamic Multi-Agent Routing Protocol
   - Adaptive routing heuristics
   - Multi-factor optimization
   - Benchmarking against baselines

2. **DMSG**: Distributed MCP Skill Graph
   - Graph-based skill modeling
   - Optimal path discovery algorithms
   - Cost/latency trade-offs

3. **UMB**: Unified Memory Bus
   - Multi-layer memory architecture
   - Policy enforcement
   - Privacy guarantees

## Future Enhancements

- Full LLM integration for planning
- Advanced federation protocols
- UI dashboard and visualization
- Production deployment tools
- Benchmark suite
- Research paper publication

