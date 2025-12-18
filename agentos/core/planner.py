"""
MAGP (Multi-Agent Planning Graph) - Planner for creating task graphs from goals
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid
from datetime import datetime


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class TaskNode:
    """Task node in planning graph"""
    id: str
    description: str
    type: str = "generic"
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    cost_estimate: Dict[str, float] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)  # Task IDs this depends on
    required_skills: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "type": self.type,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "cost_estimate": self.cost_estimate,
            "dependencies": self.dependencies,
            "required_skills": self.required_skills,
            "status": self.status.value,
            "assigned_agent": self.assigned_agent,
        }


@dataclass
class TaskGraph:
    """Planning graph with tasks and dependencies"""
    id: str
    goal: str
    nodes: List[TaskNode] = field(default_factory=list)
    edges: List[Dict[str, str]] = field(default_factory=list)  # [{"from": task_id, "to": task_id}]
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": self.edges,
            "created_at": self.created_at,
        }
    
    def get_node(self, node_id: str) -> Optional[TaskNode]:
        """Get a node by ID"""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None
    
    def get_ready_tasks(self) -> List[TaskNode]:
        """Get tasks that are ready to execute (dependencies satisfied)"""
        ready = []
        for node in self.nodes:
            if node.status == TaskStatus.PENDING:
                # Check if all dependencies are completed
                deps_completed = all(
                    self.get_node(dep_id).status == TaskStatus.COMPLETED
                    for dep_id in node.dependencies
                    if self.get_node(dep_id)
                )
                if not node.dependencies or deps_completed:
                    ready.append(node)
        return ready
    
    def is_complete(self) -> bool:
        """Check if all tasks are completed"""
        return all(node.status == TaskStatus.COMPLETED for node in self.nodes)
    
    def get_critical_path(self) -> List[str]:
        """Get critical path (longest path) through the graph"""
        # Simple implementation: topological sort with longest path
        # More sophisticated: use dynamic programming
        in_degree = {node.id: len(node.dependencies) for node in self.nodes}
        queue = [node.id for node in self.nodes if in_degree[node.id] == 0]
        distances = {node.id: node.cost_estimate.get("wall_time", 1.0) for node in self.nodes}
        
        while queue:
            current = queue.pop(0)
            current_node = self.get_node(current)
            
            # Find nodes that depend on current
            for node in self.nodes:
                if current in node.dependencies:
                    new_dist = distances[current] + node.cost_estimate.get("wall_time", 1.0)
                    if new_dist > distances[node.id]:
                        distances[node.id] = new_dist
                    in_degree[node.id] -= 1
                    if in_degree[node.id] == 0:
                        queue.append(node.id)
        
        # Find longest path
        max_node = max(distances.items(), key=lambda x: x[1])
        return [max_node[0]]  # Simplified - return node with longest path


class Planner:
    """
    Planner that converts mission goals into task graphs (MAGP).
    """
    
    def __init__(self, llm_func: Optional[callable] = None, rag_manager: Optional[Any] = None, enable_rag: bool = False):
        """
        Initialize planner.
        
        Args:
            llm_func: Optional LLM function for semantic decomposition
            rag_manager: Optional RAG manager for context-augmented planning
            enable_rag: Whether to enable RAG for node expansion
        """
        self.llm_func = llm_func
        self.rag_manager = rag_manager
        self.enable_rag = enable_rag
    
    def create_graph(self, goal_text: str, constraints: Optional[Dict[str, Any]] = None) -> TaskGraph:
        """
        Create a task graph from a goal.
        
        Args:
            goal_text: Mission goal description
            constraints: Optional constraints (max_tasks, parallelization, etc.)
            
        Returns:
            TaskGraph with nodes and edges
        """
        constraints = constraints or {}
        enable_rag = constraints.get("enable_rag", self.enable_rag)
        
        # Augment goal with RAG context if enabled
        if enable_rag and self.rag_manager:
            import asyncio
            try:
                rag_context = asyncio.run(self.rag_manager.create_retrieval_context(goal_text, top_k=5))
                if rag_context.get("context_docs"):
                    # Augment goal with context
                    context_text = "\n".join([doc.get("text", "")[:200] for doc in rag_context["context_docs"][:3]])
                    goal_text = f"{goal_text}\n\nContext from knowledge base:\n{context_text}"
            except Exception as e:
                import logging
                logging.warning(f"RAG context retrieval failed: {e}")
        
        # Use LLM if available, otherwise use simple decomposition
        if self.llm_func:
            return self._create_graph_llm(goal_text, constraints)
        else:
            return self._create_graph_simple(goal_text, constraints)
    
    async def expand_node_with_rag(self, node: TaskNode, rag_manager: Any) -> TaskNode:
        """
        Expand a node using RAG context.
        
        Args:
            node: TaskNode to expand
            rag_manager: RAG manager instance
            
        Returns:
            Expanded TaskNode
        """
        if not rag_manager:
            return node
        
        # Retrieve context for node description
        context = await rag_manager.create_retrieval_context(node.description, top_k=3)
        
        # Augment node description with context
        if context.get("context_docs"):
            context_text = "\n".join([doc.get("text", "")[:150] for doc in context["context_docs"]])
            node.description = f"{node.description}\n\nContext: {context_text}"
        
        return node
    
    def _create_graph_simple(self, goal_text: str, constraints: Dict[str, Any]) -> TaskGraph:
        """Simple graph creation (for MVP without LLM)"""
        graph_id = str(uuid.uuid4())
        
        # Simple decomposition: create a single task or a few tasks
        # In production, this would use LLM for semantic decomposition
        
        # Extract keywords to infer task type
        goal_lower = goal_text.lower()
        
        tasks = []
        
        # Heuristic-based decomposition
        if "process" in goal_lower or "analyze" in goal_lower:
            tasks = [
                TaskNode(
                    id=str(uuid.uuid4()),
                    description=f"Parse and extract data: {goal_text}",
                    type="parse",
                    required_skills=["parsing", "data_extraction"],
                    cost_estimate={"tokens": 500, "wall_time": 2.0},
                ),
                TaskNode(
                    id=str(uuid.uuid4()),
                    description=f"Analyze and summarize: {goal_text}",
                    type="analyze",
                    required_skills=["analysis", "summarization"],
                    dependencies=[tasks[0].id] if tasks else [],
                    cost_estimate={"tokens": 1000, "wall_time": 5.0},
                ),
            ]
        elif "build" in goal_lower or "create" in goal_lower:
            tasks = [
                TaskNode(
                    id=str(uuid.uuid4()),
                    description=f"Design: {goal_text}",
                    type="design",
                    required_skills=["design", "planning"],
                    cost_estimate={"tokens": 800, "wall_time": 3.0},
                ),
                TaskNode(
                    id=str(uuid.uuid4()),
                    description=f"Implement: {goal_text}",
                    type="implement",
                    required_skills=["implementation", "coding"],
                    dependencies=[tasks[0].id] if tasks else [],
                    cost_estimate={"tokens": 2000, "wall_time": 10.0},
                ),
                TaskNode(
                    id=str(uuid.uuid4()),
                    description=f"Test: {goal_text}",
                    type="test",
                    required_skills=["testing", "validation"],
                    dependencies=[tasks[1].id] if len(tasks) > 1 else [],
                    cost_estimate={"tokens": 500, "wall_time": 3.0},
                ),
            ]
        else:
            # Default: single task
            tasks = [
                TaskNode(
                    id=str(uuid.uuid4()),
                    description=goal_text,
                    type="generic",
                    cost_estimate={"tokens": 1000, "wall_time": 5.0},
                ),
            ]
        
        # Build edges from dependencies
        edges = []
        for task in tasks:
            for dep_id in task.dependencies:
                edges.append({"from": dep_id, "to": task.id})
        
        graph = TaskGraph(
            id=graph_id,
            goal=goal_text,
            nodes=tasks,
            edges=edges,
        )
        
        return graph
    
    def _create_graph_llm(self, goal_text: str, constraints: Dict[str, Any]) -> TaskGraph:
        """Create graph using LLM (placeholder for future implementation)"""
        # TODO: Implement LLM-based decomposition
        # For now, fall back to simple
        return self._create_graph_simple(goal_text, constraints)
    
    def optimize(
        self,
        graph: TaskGraph,
        constraints: Optional[Dict[str, Any]] = None
    ) -> TaskGraph:
        """
        Optimize a task graph (parallelization, critical path, etc.).
        
        Args:
            graph: TaskGraph to optimize
            constraints: Optimization constraints
            
        Returns:
            Optimized TaskGraph
        """
        constraints = constraints or {}
        
        # Identify parallelizable tasks
        self._identify_parallel_tasks(graph)
        
        # Optimize critical path
        if constraints.get("minimize_latency"):
            self._optimize_critical_path(graph)
        
        # Resource optimization
        if constraints.get("minimize_cost"):
            self._optimize_resources(graph)
        
        return graph
    
    def _identify_parallel_tasks(self, graph: TaskGraph):
        """Identify tasks that can run in parallel"""
        # Tasks with no dependencies or with completed dependencies can run in parallel
        for node in graph.nodes:
            if not node.dependencies:
                # Can start immediately
                pass
            else:
                # Check if dependencies allow parallelization
                pass
    
    def _optimize_critical_path(self, graph: TaskGraph):
        """Optimize critical path for latency"""
        critical_path = graph.get_critical_path()
        # Could reassign tasks on critical path to faster agents
        pass
    
    def _optimize_resources(self, graph: TaskGraph):
        """Optimize resource usage"""
        # Could merge tasks, reduce redundancy, etc.
        pass
    
    async def negotiate_decomposition(
        self,
        goal_text: str,
        agents: List[Any]
    ) -> TaskGraph:
        """
        Negotiate task decomposition with multiple agents (voting, proposals).
        
        Args:
            goal_text: Mission goal
            agents: Agents participating in negotiation
            
        Returns:
            TaskGraph from negotiated decomposition
        """
        # Collect proposals from agents
        proposals = []
        for agent in agents:
            proposal = await agent.plan({"goal": goal_text, "id": str(uuid.uuid4())})
            proposals.append(proposal)
        
        # Simple voting: use first proposal (can be extended with voting logic)
        if proposals:
            # Use the planner to create graph from best proposal
            best_proposal = proposals[0]
            return self.create_graph(goal_text)
        
        # Fallback
        return self.create_graph(goal_text)

