"""
Production Security & Hardening Module for AgentOS-SWE (M6).
"""

from agentos_swe.security.limits import ResourceLimits, ExecutionMetrics
from agentos_swe.security.command_policy import CommandPolicy, ALLOWED_COMMAND_BINARIES, DENIED_COMMAND_PATTERNS
from agentos_swe.security.secret_protection import SecretProtection, SECRET_PATTERNS

__all__ = [
    "ResourceLimits",
    "ExecutionMetrics",
    "CommandPolicy",
    "ALLOWED_COMMAND_BINARIES",
    "DENIED_COMMAND_PATTERNS",
    "SecretProtection",
    "SECRET_PATTERNS",
]
