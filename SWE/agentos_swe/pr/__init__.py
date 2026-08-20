"""
PR Automation & Risk Governance Module for AgentOS-SWE (M5).
"""

from agentos_swe.pr.models import (
    RiskLevel,
    GovernanceDecision,
    RiskAssessment,
    PRResult,
)
from agentos_swe.pr.risk import RiskAnalyzer
from agentos_swe.pr.governance_gate import GovernanceGate
from agentos_swe.pr.provider import GitProvider, GitHubAdapter, redact_secrets
from agentos_swe.pr.pr_generator import PRDescriptionGenerator
from agentos_swe.pr.pipeline import PRPipeline

__all__ = [
    "RiskLevel",
    "GovernanceDecision",
    "RiskAssessment",
    "PRResult",
    "RiskAnalyzer",
    "GovernanceGate",
    "GitProvider",
    "GitHubAdapter",
    "redact_secrets",
    "PRDescriptionGenerator",
    "PRPipeline",
]
