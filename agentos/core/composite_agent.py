"""
Composite Agent - Role-merging and hybrid agents
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import uuid
from agentos.core.agent import Agent, AgentStatus


@dataclass
class MergePolicy:
    """Policy for merging agents"""
    skill_merge: str = "union"  # "union", "intersection", "weighted"
    memory_merge: str = "union"  # "union", "intersection", "filtered"
    personality_merge: str = "average"  # "average", "weighted", "max"


class CompositeAgent(Agent):
    """
    Composite agent created by merging multiple agents.
    Combines skills, memory, and execution context.
    """
    
    def __init__(
        self,
        id: Optional[str] = None,
        name: str = "CompositeAgent",
        source_agents: List[Agent] = None,
        merge_policy: MergePolicy = None,
        temporary: bool = True,
        mission_id: Optional[str] = None,
    ):
        source_agents = source_agents or []
        merge_policy = merge_policy or MergePolicy()
        
        # Merge skills
        merged_skills = self._merge_skills(source_agents, merge_policy.skill_merge)
        
        # Merge personality
        merged_personality = self._merge_personality(source_agents, merge_policy.personality_merge)
        
        # Initialize base agent
        super().__init__(
            id=id or str(uuid.uuid4()),
            name=name,
            roles=["composite"] + [role for agent in source_agents for role in agent.roles],
            skills=merged_skills,
            personality_vector=merged_personality,
        )
        
        # Store source agents
        self.source_agents = source_agents
        self.merge_policy = merge_policy
        self.temporary = temporary
        self.mission_id = mission_id
        
        # Merge memory references (filtered by policy)
        self.memory_refs = self._merge_memory_refs(source_agents, merge_policy.memory_merge)
        
        # Merge tools
        self._merge_tools(source_agents)
        
        # Update status
        self.status = AgentStatus.MERGED
    
    @classmethod
    def create(
        cls,
        agents: List[Agent],
        merge_policy: str = "union",
        temporary: bool = True,
        mission_id: Optional[str] = None
    ) -> 'CompositeAgent':
        """
        Create a composite agent from a list of agents.
        
        Args:
            agents: List of agents to merge
            merge_policy: Merge policy string ("union", "intersection", "weighted")
            temporary: Whether merge is temporary
            mission_id: Mission ID if temporary
            
        Returns:
            CompositeAgent instance
        """
        if not agents:
            raise ValueError("Cannot create composite agent from empty list")
        
        if len(agents) == 1:
            # Single agent - return as-is (wrapped)
            return cls(
                source_agents=agents,
                merge_policy=MergePolicy(),
                temporary=temporary,
                mission_id=mission_id,
            )
        
        # Create merge policy
        policy = MergePolicy(
            skill_merge=merge_policy,
            memory_merge=merge_policy,
        )
        
        # Generate name
        name = f"Composite({'+'.join([a.name for a in agents[:3]])})"
        if len(agents) > 3:
            name += f"+{len(agents)-3}more"
        
        return cls(
            name=name,
            source_agents=agents,
            merge_policy=policy,
            temporary=temporary,
            mission_id=mission_id,
        )
    
    def _merge_skills(self, agents: List[Agent], policy: str) -> List[str]:
        """Merge skills from source agents"""
        if not agents:
            return []
        
        if policy == "union":
            # Union of all skills
            all_skills = set()
            for agent in agents:
                all_skills.update(agent.skills)
            return list(all_skills)
        
        elif policy == "intersection":
            # Intersection of all skills
            if not agents:
                return []
            common_skills = set(agents[0].skills)
            for agent in agents[1:]:
                common_skills.intersection_update(agent.skills)
            return list(common_skills)
        
        elif policy == "weighted":
            # Weighted by reputation
            skill_scores = {}
            total_weight = 0.0
            for agent in agents:
                weight = agent.identity.reputation_score + 0.5  # Ensure positive
                total_weight += weight
                for skill in agent.skills:
                    if skill not in skill_scores:
                        skill_scores[skill] = 0.0
                    skill_scores[skill] += weight
            
            # Return skills above threshold
            threshold = total_weight * 0.3
            return [skill for skill, score in skill_scores.items() if score >= threshold]
        
        else:
            # Default: union
            return self._merge_skills(agents, "union")
    
    def _merge_personality(self, agents: List[Agent], policy: str) -> List[float]:
        """Merge personality vectors"""
        if not agents:
            return []
        
        personalities = [a.identity.personality_vector for a in agents if a.identity.personality_vector]
        if not personalities:
            return []
        
        if policy == "average":
            # Average personality
            if len(personalities[0]) == 0:
                return []
            dim = len(personalities[0])
            merged = [0.0] * dim
            for p in personalities:
                if len(p) == dim:
                    for i in range(dim):
                        merged[i] += p[i]
            return [v / len(personalities) for v in merged]
        
        elif policy == "weighted":
            # Weighted by reputation
            if len(personalities[0]) == 0:
                return []
            dim = len(personalities[0])
            merged = [0.0] * dim
            total_weight = 0.0
            for agent, p in zip(agents, personalities):
                weight = agent.identity.reputation_score + 0.5
                total_weight += weight
                if len(p) == dim:
                    for i in range(dim):
                        merged[i] += p[i] * weight
            return [v / total_weight for v in merged] if total_weight > 0 else merged
        
        elif policy == "max":
            # Max values
            if len(personalities[0]) == 0:
                return []
            dim = len(personalities[0])
            merged = [float('-inf')] * dim
            for p in personalities:
                if len(p) == dim:
                    for i in range(dim):
                        merged[i] = max(merged[i], p[i])
            return merged
        
        else:
            # Default: average
            return self._merge_personality(agents, "average")
    
    def _merge_memory_refs(self, agents: List[Agent], policy: str) -> List[Any]:
        """Merge memory references"""
        refs = []
        for agent in agents:
            if agent.memory_ref:
                refs.append(agent.memory_ref)
        
        # For now, use first memory ref (can be extended with filtering)
        if refs:
            self.memory_ref = refs[0]
        
        return refs
    
    def _merge_tools(self, agents: List[Agent]):
        """Merge tools from source agents"""
        for agent in agents:
            for tool_name, tool_func in agent.tools.items():
                if tool_name not in self.tools:
                    self.tools[tool_name] = tool_func
    
    async def execute(self, task_node: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute task - can delegate to source agents or use merged capabilities"""
        # Check if we should delegate to a specific source agent
        required_skills = set(task_node.get("required_skills", []))
        
        # Find best source agent for this task
        best_agent = None
        best_match = 0
        for agent in self.source_agents:
            agent_skills = set(agent.skills)
            match = len(required_skills.intersection(agent_skills))
            if match > best_match:
                best_match = match
                best_agent = agent
        
        # If we found a good match, delegate
        if best_agent and best_match > 0:
            # Execute with best agent but use composite context
            result = await best_agent.execute(task_node, context)
            # Update composite metrics
            self._update_resource_metrics(result)
            return result
        
        # Otherwise, use merged capabilities
        return await super().execute(task_node, context)
    
    def dissolve(self):
        """Dissolve composite agent (if temporary)"""
        if self.temporary:
            # Restore source agents to normal state
            for agent in self.source_agents:
                if agent.status == AgentStatus.MERGED:
                    agent.status = AgentStatus.IDLE
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize composite agent"""
        base_dict = super().to_dict()
        base_dict.update({
            "type": "composite",
            "source_agent_ids": [a.id for a in self.source_agents],
            "temporary": self.temporary,
            "mission_id": self.mission_id,
        })
        return base_dict

