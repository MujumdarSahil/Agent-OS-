"""
Specialized Investigation Agents for AgentOS-SWE (M2).
"""

from agentos_swe.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.agents.bug_agent import BugAgent
from agentos_swe.agents.security_agent import SecurityAgent
from agentos_swe.agents.performance_agent import PerformanceAgent
from agentos_swe.agents.architecture_agent import ArchitectureAgent

__all__ = [
    "BaseInvestigatorAgent",
    "BugAgent",
    "SecurityAgent",
    "PerformanceAgent",
    "ArchitectureAgent",
]
