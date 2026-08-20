"""
AgentOS-SWE Exceptions Taxonomy
Extends core AgentOSError with SWE domain-specific errors.
"""

from agentos.exceptions import AgentOSError


class AgentOSSWEError(AgentOSError):
    """Base exception for all AgentOS-SWE errors."""
    pass


class RepositoryError(AgentOSSWEError):
    """Raised when repository path validation or intake fails."""
    pass


class GraphProviderError(AgentOSSWEError):
    """Raised when code graph provider operations fail."""
    pass


class GraphBuildError(GraphProviderError):
    """Raised when building code graph fails."""
    pass


class RepositoryContextError(AgentOSSWEError):
    """Raised when constructing or querying RepositoryContext fails."""
    pass
