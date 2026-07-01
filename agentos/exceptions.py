"""
AgentOS Exceptions Taxonomy
"""

class AgentOSError(Exception):
    """Base exception for all errors raised by AgentOS."""
    pass

class AgentOSLLMError(AgentOSError):
    """Raised when LLM provider operations or router fallbacks fail."""
    pass

class AgentOSRegistryError(AgentOSError):
    """Raised when loading or registering agents, tools, or plugins fails."""
    pass

class AgentOSGovernanceError(AgentOSError):
    """Raised when a task or execution is blocked by governance/safety policies."""
    pass

class AgentOSPackagingError(AgentOSError):
    """Raised when package signing, verification, or installation fails."""
    pass
