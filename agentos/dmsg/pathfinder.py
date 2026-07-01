"""
DMSG Pathfinder - Find optimal paths through MCP skill graph
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from agentos.dmsg.registry import MCPRegistry, MCPNode


@dataclass
class SkillPath:
    """Path through skill graph"""
    steps: List[Dict[str, Any]]  # [{"mcp_id": ..., "skill": ..., "inputs": ..., "outputs": ...}]
    total_cost: float
    total_latency: float
    confidence: float  # 0-1, based on trust scores and accuracy


class Pathfinder:
    """
    Pathfinder for finding optimal sequences of MCP calls to achieve skill requirements.
    """
    
    def __init__(self, registry: MCPRegistry):
        self.registry = registry
    
    def find_path(
        self,
        skill_requirements: List[str],
        constraints: Optional[Dict[str, Any]] = None
    ) -> Optional[SkillPath]:
        """
        Find optimal path through MCP skill graph.
        
        Args:
            skill_requirements: List of required skill names
            constraints: Optional constraints (max_cost, max_latency, trust_threshold)
            
        Returns:
            SkillPath or None if no path found
        """
        constraints = constraints or {}
        
        # Find MCPs that provide each skill
        skill_mcps = {}
        for skill_name in skill_requirements:
            mcps = self.registry.find_mcps_by_skill(skill_name)
            if not mcps:
                # Skill not available
                return None
            skill_mcps[skill_name] = mcps
        
        # Build path (greedy algorithm for MVP)
        # In production, could use graph algorithms (Dijkstra, A*, etc.)
        path_steps = []
        total_cost = 0.0
        total_latency = 0.0
        min_confidence = 1.0
        
        for skill_name in skill_requirements:
            mcps = skill_mcps[skill_name]
            
            # Select best MCP for this skill
            best_mcp, best_skill = self._select_best_mcp(mcps, skill_name, constraints)
            
            if not best_mcp or not best_skill:
                return None
            
            # Add to path
            path_steps.append({
                "mcp_id": best_mcp.id,
                "mcp_name": best_mcp.name,
                "skill": best_skill.name,
                "skill_id": best_skill.id,
                "inputs": best_skill.inputs,
                "outputs": best_skill.outputs,
            })
            
            # Update metrics
            total_cost += best_skill.cost_estimate.get("cost", 0.0)
            total_latency += best_skill.latency_estimate
            min_confidence = min(min_confidence, best_mcp.trust_score * best_skill.accuracy_estimate)
        
        # Check constraints
        if constraints.get("max_cost") and total_cost > constraints["max_cost"]:
            return None
        if constraints.get("max_latency") and total_latency > constraints["max_latency"]:
            return None
        if constraints.get("min_trust") and min_confidence < constraints["min_trust"]:
            return None
        
        return SkillPath(
            steps=path_steps,
            total_cost=total_cost,
            total_latency=total_latency,
            confidence=min_confidence,
        )
    
    def _select_best_mcp(
        self,
        mcps: List[MCPNode],
        skill_name: str,
        constraints: Dict[str, Any]
    ) -> tuple:
        """
        Select best MCP for a skill.
        
        Returns:
            (best_mcp, best_skill) or (None, None)
        """
        if not mcps:
            return None, None
        
        best_mcp = None
        best_skill = None
        best_score = -1.0
        
        for mcp in mcps:
            if mcp.status != "active":
                continue
            
            # Find skill in MCP
            skill = None
            for s in mcp.skills:
                if s.name == skill_name:
                    skill = s
                    break
            
            if not skill:
                continue
            
            # Score MCP (higher is better)
            score = 0.0
            
            # Trust score
            score += mcp.trust_score * 0.4
            
            # Skill accuracy
            score += skill.accuracy_estimate * 0.3
            
            # Cost (inverse)
            cost = skill.cost_estimate.get("cost", 1.0)
            score += (1.0 / (1.0 + cost)) * 0.2
            
            # Latency (inverse)
            latency = skill.latency_estimate
            score += (1.0 / (1.0 + latency)) * 0.1
            
            if score > best_score:
                best_score = score
                best_mcp = mcp
                best_skill = skill
        
        return best_mcp, best_skill
    
    def find_alternative_paths(
        self,
        skill_requirements: List[str],
        constraints: Optional[Dict[str, Any]] = None,
        top_k: int = 3
    ) -> List[SkillPath]:
        """
        Find multiple alternative paths (for comparison).
        
        Args:
            skill_requirements: List of required skills
            constraints: Optional constraints
            top_k: Number of paths to return
            
        Returns:
            List of SkillPath (sorted by score)
        """
        # For MVP, return single path
        # In production, could enumerate multiple paths
        path = self.find_path(skill_requirements, constraints)
        if path:
            return [path]
        return []

