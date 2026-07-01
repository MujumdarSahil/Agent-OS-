"""
Task Router (DMARP) - Dynamic Multi-Agent Routing Protocol for task assignment
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class AssignmentStrategy(Enum):
    """Task assignment strategies"""
    SKILL_MATCH = "skill_match"  # Match by skills
    REPUTATION = "reputation"  # Assign to highest reputation
    LOAD_BALANCE = "load_balance"  # Balance workload
    COST_OPTIMIZE = "cost_optimize"  # Minimize cost
    HYBRID = "hybrid"  # Combination of factors


@dataclass
class AssignmentPlan:
    """Task assignment plan"""
    assignments: Dict[str, str]  # task_id -> agent_id
    reasoning: Dict[str, str]  # task_id -> reasoning
    estimated_cost: float
    estimated_latency: float
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TaskRouter:
    """
    Task Router implementing DMARP (Dynamic Multi-Agent Routing Protocol).
    Routes tasks to agents based on skills, reputation, resources, and constraints.
    """
    
    def __init__(self, strategy: AssignmentStrategy = AssignmentStrategy.HYBRID):
        self.strategy = strategy
        self.assignment_history: List[AssignmentPlan] = []
    
    def assign(
        self,
        mission_graph: Any,  # TaskGraph from planner
        candidate_agents: List[Any],
        constraints: Optional[Dict[str, Any]] = None
    ) -> AssignmentPlan:
        """
        Assign tasks from mission graph to candidate agents.
        
        Args:
            mission_graph: TaskGraph with nodes (tasks) and edges (dependencies)
            candidate_agents: List of available agents
            constraints: Optional constraints (max_cost, max_latency, etc.)
            
        Returns:
            AssignmentPlan with task->agent mappings
        """
        constraints = constraints or {}
        
        # Extract tasks from graph
        tasks = self._extract_tasks(mission_graph)
        
        # Score each agent for each task
        assignments = {}
        reasoning = {}
        total_cost = 0.0
        max_latency = 0.0
        
        for task in tasks:
            task_id = task.get("id")
            best_agent, score, reason = self._select_agent(
                task, candidate_agents, constraints
            )
            
            if best_agent:
                assignments[task_id] = best_agent.id
                reasoning[task_id] = reason
                
                # Estimate cost and latency
                cost = self._estimate_task_cost(task, best_agent)
                latency = self._estimate_task_latency(task, best_agent)
                total_cost += cost
                max_latency = max(max_latency, latency)
            else:
                # No suitable agent found
                assignments[task_id] = None
                reasoning[task_id] = "No suitable agent found"
        
        plan = AssignmentPlan(
            assignments=assignments,
            reasoning=reasoning,
            estimated_cost=total_cost,
            estimated_latency=max_latency,
            metadata={
                "strategy": self.strategy.value,
                "task_count": len(tasks),
                "agent_count": len(candidate_agents),
            }
        )
        
        self.assignment_history.append(plan)
        return plan
    
    def _extract_tasks(self, mission_graph: Any) -> List[Dict[str, Any]]:
        """Extract task list from mission graph"""
        if hasattr(mission_graph, "nodes"):
            return mission_graph.nodes
        elif isinstance(mission_graph, dict):
            return mission_graph.get("nodes", [])
        elif isinstance(mission_graph, list):
            return mission_graph
        else:
            return []
    
    def _select_agent(
        self,
        task: Dict[str, Any],
        agents: List[Any],
        constraints: Dict[str, Any]
    ) -> tuple:
        """
        Select best agent for a task.
        
        Returns:
            (best_agent, score, reasoning)
        """
        if not agents:
            return None, 0.0, "No agents available"
        
        # Score each agent
        scores = []
        for agent in agents:
            score = self._score_agent(task, agent, constraints)
            scores.append((agent, score))
        
        # Sort by score (descending)
        scores.sort(key=lambda x: x[1], reverse=True)
        
        best_agent, best_score = scores[0]
        
        # Generate reasoning
        reason = self._generate_reasoning(task, best_agent, best_score, scores)
        
        return best_agent, best_score, reason
    
    def _score_agent(
        self,
        task: Dict[str, Any],
        agent: Any,
        constraints: Dict[str, Any]
    ) -> float:
        """Score an agent for a task"""
        score = 0.0
        
        if self.strategy == AssignmentStrategy.SKILL_MATCH:
            score = self._score_skill_match(task, agent)
        elif self.strategy == AssignmentStrategy.REPUTATION:
            score = agent.identity.reputation_score
        elif self.strategy == AssignmentStrategy.LOAD_BALANCE:
            score = self._score_load_balance(agent)
        elif self.strategy == AssignmentStrategy.COST_OPTIMIZE:
            score = self._score_cost_optimize(task, agent)
        elif self.strategy == AssignmentStrategy.HYBRID:
            # Weighted combination
            skill_score = self._score_skill_match(task, agent)
            rep_score = agent.identity.reputation_score
            load_score = self._score_load_balance(agent)
            cost_score = self._score_cost_optimize(task, agent)
            
            score = (
                0.4 * skill_score +
                0.3 * rep_score +
                0.2 * load_score +
                0.1 * cost_score
            )
        
        # Apply constraints
        if constraints.get("max_cost"):
            cost = self._estimate_task_cost(task, agent)
            if cost > constraints["max_cost"]:
                score *= 0.1  # Penalize
        
        if constraints.get("required_skills"):
            required = set(constraints["required_skills"])
            agent_skills = set(agent.skills)
            if not required.issubset(agent_skills):
                score *= 0.1  # Penalize
        
        return score
    
    def _score_skill_match(self, task: Dict[str, Any], agent: Any) -> float:
        """Score based on skill match"""
        task_skills = set(task.get("required_skills", []))
        agent_skills = set(agent.skills)
        
        if not task_skills:
            return 1.0  # No requirements = any agent can do it
        
        intersection = task_skills.intersection(agent_skills)
        return len(intersection) / len(task_skills) if task_skills else 0.0
    
    def _score_load_balance(self, agent: Any) -> float:
        """Score based on current load (lower load = higher score)"""
        # Count active tasks
        active_tasks = sum(1 for h in agent.execution_history if h.get("status") == "active")
        # Inverse: fewer active tasks = higher score
        return 1.0 / (1.0 + active_tasks)
    
    def _score_cost_optimize(self, task: Dict[str, Any], agent: Any) -> float:
        """Score based on cost (lower cost = higher score)"""
        cost = self._estimate_task_cost(task, agent)
        # Inverse: lower cost = higher score (normalize)
        return 1.0 / (1.0 + cost / 1000.0)
    
    def _estimate_task_cost(self, task: Dict[str, Any], agent: Any) -> float:
        """Estimate cost for agent to execute task"""
        # Simple heuristic based on task complexity and agent metrics
        base_cost = task.get("cost_estimate", {}).get("tokens", 1000)
        
        # Agent efficiency factor (based on reputation)
        efficiency = agent.identity.reputation_score if agent.identity.reputation_score > 0 else 0.5
        adjusted_cost = base_cost / (1.0 + efficiency)
        
        return adjusted_cost
    
    def _estimate_task_latency(self, task: Dict[str, Any], agent: Any) -> float:
        """Estimate latency for agent to execute task"""
        base_latency = task.get("cost_estimate", {}).get("wall_time", 5.0)
        
        # Agent speed factor
        speed = agent.identity.reputation_score if agent.identity.reputation_score > 0 else 0.5
        adjusted_latency = base_latency / (1.0 + speed)
        
        return adjusted_latency
    
    def _generate_reasoning(
        self,
        task: Dict[str, Any],
        agent: Any,
        score: float,
        all_scores: List[tuple]
    ) -> str:
        """Generate human-readable reasoning for assignment"""
        reasons = []
        
        # Skill match
        task_skills = set(task.get("required_skills", []))
        agent_skills = set(agent.skills)
        if task_skills:
            matched = task_skills.intersection(agent_skills)
            if matched:
                reasons.append(f"Matched {len(matched)}/{len(task_skills)} required skills")
        
        # Reputation
        if agent.identity.reputation_score > 0.7:
            reasons.append(f"High reputation ({agent.identity.reputation_score:.2f})")
        
        # Load
        active_tasks = sum(1 for h in agent.execution_history if h.get("status") == "active")
        if active_tasks == 0:
            reasons.append("Agent is idle")
        
        # Score
        reasons.append(f"Overall score: {score:.2f}")
        
        return "; ".join(reasons) if reasons else "Default assignment"

