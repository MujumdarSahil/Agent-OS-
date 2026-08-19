"""
BaseInvestigatorAgent - Abstract base class for specialized investigation agents in AgentOS-SWE.
Inherits from core AgentOS Agent to leverage LLM client, routing, fallback, and governance.
"""

import os
import ast
import logging
from abc import abstractmethod
from typing import List, Dict, Any, Optional

from agentos.core.agent import Agent
from agentos.llm.llm_client import LLMClient
from agentos_swe.models import (
    Finding,
    Evidence,
    FindingStatus,
    EvidenceSource,
    EvidenceKind,
    CodeNode,
)
from agentos_swe.context import RepositoryContext

logger = logging.getLogger(__name__)


class BaseInvestigatorAgent(Agent):
    """
    Base class for specialized AgentOS-SWE investigation agents.
    Provides graph-aware context gathering, LLM querying via AgentOS LLMClient,
    and evidence-first finding generation.
    """

    def __init__(
        self,
        name: str = "InvestigatorAgent",
        role: str = "Code Investigator",
        goal: str = "Investigate repository for software defects",
        backstory: str = "An expert code analysis agent.",
        llm_client: Optional[LLMClient] = None,
        **kwargs: Any,
    ):
        if llm_client is None:
            llm_client = LLMClient()
        super().__init__(
            name=name,
            role=role,
            goal=goal,
            backstory=backstory,
            llm_client=llm_client,
            **kwargs,
        )

    @abstractmethod
    def investigate(self, context: RepositoryContext) -> List[Finding]:
        """
        Execute investigation over repository context.
        Must return list of typed Finding objects backed by Evidence.
        """
        pass

    def read_source_snippet(
        self, context: RepositoryContext, relative_path: str, max_lines: int = 150
    ) -> Optional[str]:
        """
        Safely read a snippet of source code from the repository without loading entire files into memory.
        """
        full_path = os.path.join(context.repository_path, relative_path)
        if not os.path.isfile(full_path):
            return None

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = [f.readline() for _ in range(max_lines)]
                return "".join(lines)
        except Exception as e:
            logger.debug(f"Failed reading snippet for {relative_path}: {e}")
            return None

    def query_llm_reasoning(
        self, prompt: str, system_message: Optional[str] = None
    ) -> Optional[str]:
        """
        Query LLM using the existing AgentOS LLMClient abstraction.
        Uses configured model router and automatic fallback chain via complete().
        """
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": prompt})

        try:
            response = self.llm_client.complete(messages=messages)
            if isinstance(response, dict):
                choices = response.get("choices", [])
                if choices and isinstance(choices[0], dict):
                    msg = choices[0].get("message", {})
                    if isinstance(msg, dict):
                        return msg.get("content", "")
            elif hasattr(response, "choices") and response.choices:
                return response.choices[0].message.content
            return str(response)
        except Exception as ex:
            logger.warning(f"[{self.name}] LLM call failed or caught error: {ex}")
            return None

    def create_finding(
        self,
        category: str,
        title: str,
        description: str,
        severity: str = "medium",
        file: Optional[str] = None,
        line_range: Optional[tuple] = None,
        symbol: Optional[str] = None,
        evidence: Optional[List[Evidence]] = None,
        graph_context: Optional[Dict[str, Any]] = None,
        confidence: float = 0.8,
    ) -> Finding:
        """
        Construct a typed Finding object with evidence and graph context.
        """
        ev_list = evidence or []
        g_ctx = graph_context or {}

        return Finding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            repository=os.path.basename(self.name),
            file=file,
            line_range=line_range,
            symbol=symbol,
            evidence=ev_list,
            graph_context=g_ctx,
            confidence=confidence,
            status=FindingStatus.DISCOVERED,
        )
