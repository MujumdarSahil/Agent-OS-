"""
AgentOS - A production-grade multi-agent framework
"""

__version__ = "0.1.0"

from agentos.core.agent import Agent
from agentos.core.squad import Squad
from agentos.core.governance import GovernanceEngine, PolicyDecision
from agentos.core.router import TaskRouter
from agentos.core.planner import Planner, TaskGraph
from agentos.core.umb_adapter import UMBAdapter, MemoryEntry
from agentos.core.base import (
    BaseAgent,
    BaseTool,
    BaseMemory,
    BaseMCPPlugin,
    AgentRegistry,
    ToolRegistry,
)

# Cybersecurity extension (optional imports)
try:
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
    CYBERSECURITY_AVAILABLE = True
except ImportError:
    CYBERSECURITY_AVAILABLE = False

__all__ = [
    "Agent",
    "Squad",
    "GovernanceEngine",
    "PolicyDecision",
    "TaskRouter",
    "Planner",
    "TaskGraph",
    "UMBAdapter",
    "MemoryEntry",
    "BaseAgent",
    "BaseTool",
    "BaseMemory",
    "BaseMCPPlugin",
    "AgentRegistry",
    "ToolRegistry",
    "CYBERSECURITY_AVAILABLE",
]

# Add cybersecurity exports if available
if CYBERSECURITY_AVAILABLE:
    __all__.extend([
        "TriageAgent",
        "InvestigatorAgent",
        "SandboxAnalystAgent",
        "ComplianceAgent",
        "ResponderAgent",
        "ThreatHuntingAgent",
        "ReviewerAgent",
        "AlertIngestMCP",
        "LogAnalysisMCP",
        "ThreatIntelMCP",
        "SandboxMCP",
        "PasswordAuditMCP",
        "ResponseActionMCP",
        "ModelHubMCP",
    ])

