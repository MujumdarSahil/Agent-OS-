"""
InvestigationSquad - AgentOS Squad implementation orchestrating specialized investigation agents
(BugAgent, SecurityAgent, PerformanceAgent, ArchitectureAgent) under AgentOS governance and memory.
"""

import logging
from typing import List, Dict, Any, Optional

from agentos.core.squad import Squad, SquadRole, Mission
from agentos.core.governance import GovernanceEngine, Policy, PolicyType
from agentos.core.umb_adapter import UMBAdapter
from agentos_swe.agents.bug_agent import BugAgent
from agentos_swe.agents.security_agent import SecurityAgent
from agentos_swe.agents.performance_agent import PerformanceAgent
from agentos_swe.agents.architecture_agent import ArchitectureAgent
from agentos_swe.aggregator import FindingAggregator
from agentos_swe.models import Finding
from agentos_swe.context import RepositoryContext

logger = logging.getLogger(__name__)


class InvestigationSquad(Squad):
    """
    AgentOS Squad orchestrating read-only software quality & security investigation.
    """

    def __init__(
        self,
        name: str = "AgentOS-SWE Investigation Squad",
        governance: Optional[GovernanceEngine] = None,
        umb_adapter: Optional[UMBAdapter] = None,
        llm_client: Optional[Any] = None,
    ):
        gov = governance or GovernanceEngine()

        # Enforce read-only governance policy via AgentOS Policy class
        read_only_policy = Policy(
            id="swe_read_only_policy",
            policy_type=PolicyType.ACTION,
            name="Read-Only Policy",
            check_func=lambda agent_id, action, ctx: action not in ("write_file", "delete_file", "git_commit", "git_push", "create_pr"),
        )
        gov.register_policy(read_only_policy)

        super().__init__(
            name=name,
            governance=gov,
            shared_memory_ref=umb_adapter,
        )

        self.aggregator = FindingAggregator()
        self.umb_adapter = umb_adapter or UMBAdapter()

        # Instantiate specialized agents using LLM client abstraction
        self.bug_agent = BugAgent(llm_client=llm_client)
        self.security_agent = SecurityAgent(llm_client=llm_client)
        self.performance_agent = PerformanceAgent(llm_client=llm_client)
        self.architecture_agent = ArchitectureAgent(llm_client=llm_client)

        # Register agents into Squad hierarchy
        self.add_agent(self.bug_agent, role=SquadRole.WORKER)
        self.add_agent(self.security_agent, role=SquadRole.WORKER)
        self.add_agent(self.performance_agent, role=SquadRole.WORKER)
        self.add_agent(self.architecture_agent, role=SquadRole.WORKER)

    def analyze_repository(self, context: RepositoryContext) -> List[Finding]:
        """
        Execute read-only investigation mission across all specialized squad agents.
        Returns aggregated list of findings.
        """
        mission = self.create_mission(
            goal="Analyze repository for software defects, security flaws, performance issues, and structural coupling.",
            description=f"Investigation mission on repository '{context.name}' at path '{context.repository_path}'.",
        )
        mission.status = "active"

        raw_findings: List[Finding] = []

        # 1. Execute Bug Investigation
        logger.info("[InvestigationSquad] Running BugAgent...")
        bug_findings = self.bug_agent.investigate(context)
        raw_findings.extend(bug_findings)

        # 2. Execute Security Investigation
        logger.info("[InvestigationSquad] Running SecurityAgent...")
        sec_findings = self.security_agent.investigate(context)
        raw_findings.extend(sec_findings)

        # 3. Execute Performance Investigation
        logger.info("[InvestigationSquad] Running PerformanceAgent...")
        perf_findings = self.performance_agent.investigate(context)
        raw_findings.extend(perf_findings)

        # 4. Execute Architecture Investigation
        logger.info("[InvestigationSquad] Running ArchitectureAgent...")
        arch_findings = self.architecture_agent.investigate(context)
        raw_findings.extend(arch_findings)

        # 5. Aggregate Findings
        aggregated_findings = self.aggregator.aggregate(raw_findings)

        # 6. Record Mission Results & Memory Entry
        mission.status = "completed"
        mission.results = {
            "raw_findings_count": len(raw_findings),
            "aggregated_findings_count": len(aggregated_findings),
            "findings": [f.to_dict() for f in aggregated_findings],
        }

        # Save to UMB memory
        try:
            self.umb_adapter.save_memory(
                session_id=mission.id,
                content=f"Completed investigation for {context.name}. Found {len(aggregated_findings)} aggregated findings.",
                metadata={"findings_count": len(aggregated_findings)},
            )
        except Exception as e:
            logger.debug(f"UMB memory save note: {e}")

        return aggregated_findings
