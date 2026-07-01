"""
my_custom_agents — minimal third-party AgentOS extension demo.

This package shows how an external developer can publish a pip-installable
package that registers a custom BaseAgent subclass with AgentOS using
Python entry points — no AgentOS source edits required.

Usage:
    pip install -e ./my_custom_agents/
    agentos list-agent-types   # "DataAnalystAgent" now appears
"""

from .analyst_agent import DataAnalystAgent

__all__ = ["DataAnalystAgent"]
