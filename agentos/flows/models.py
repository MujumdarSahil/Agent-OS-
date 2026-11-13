"""Flow graph data models and structural validation (DAG + bounded loops).

Flow definitions declare nodes, directed edges with argument mapping, and entrypoints.
The validator enforces that flows are acyclic graphs with explicit bounded loops only.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field, model_validator

from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec


class CyclicFlowError(ValueError):
    """Raised when a flow definition contains an illegal general cycle."""


class InvalidFlowConfigError(ValueError):
    """Raised when node configuration violates hardening or schema constraints."""


class NodeDefinition(BaseModel):
    """Definition of a single node in the flow graph."""

    id: str
    type: str
    config: dict[str, Any] = Field(default_factory=dict)
    # Pinned arguments configured by author (e.g. to="security@corp.local")
    # Pinned arguments carry trusted integrity and cannot be overridden by models.
    pinned_args: dict[str, Any] = Field(default_factory=dict)


class EdgeDefinition(BaseModel):
    """Directed edge connecting source node output to target node input."""

    source: str  # source node id
    target: str  # target node id
    # argument mapping: { "target_arg_name": "source_output_field" }
    arg_mapping: dict[str, str] = Field(default_factory=dict)


class FlowDefinition(BaseModel):
    """Declarative specification of an executable workflow graph."""

    id: str
    name: str = ""
    version: str = "2.0"
    entrypoint: str
    nodes: dict[str, NodeDefinition]  # keyed by node id
    edges: list[EdgeDefinition] = Field(default_factory=list)
    # Explicit bounded loop declarations: { "loop_node_id": {"max_iterations": 5, "body": [...]} }
    loops: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_structure(self) -> FlowDefinition:
        """Validate node specs, agent hardening, entrypoint, and DAG topology."""
        if self.entrypoint not in self.nodes:
            raise InvalidFlowConfigError(
                f"Entrypoint {self.entrypoint!r} is not defined in nodes"
            )

        # 1. Validate node specifications and hardening
        for node_id, node in self.nodes.items():
            spec = BUILTIN_NODE_SPECS.get(node.type)
            if not spec:
                raise InvalidFlowConfigError(f"Unknown node type {node.type!r} on node {node_id!r}")

            # Hardening rules for agent nodes
            if node.type == "agent":
                self._validate_agent_hardening(node_id, node)

        # 2. Validate edge references
        for edge in self.edges:
            if edge.source not in self.nodes:
                raise InvalidFlowConfigError(f"Edge references unknown source node: {edge.source!r}")
            if edge.target not in self.nodes:
                raise InvalidFlowConfigError(f"Edge references unknown target node: {edge.target!r}")

        # 3. Validate DAG topology (DAG + explicit bounded loops only)
        self._validate_dag_topology()

        return self

    def _validate_agent_hardening(self, node_id: str, node: NodeDefinition) -> None:
        """Enforce strict security hardening on agent nodes."""
        cfg = node.config
        # Reject configurations that attempt to enable unsafe CrewAI capabilities
        if cfg.get("cache", False) is True:
            raise InvalidFlowConfigError(
                f"Agent node {node_id!r}: cache must be False (cached tool executions bypass proxy auditing)"
            )
        if cfg.get("allow_delegation", False) is True:
            raise InvalidFlowConfigError(
                f"Agent node {node_id!r}: allow_delegation must be False"
            )
        if cfg.get("allow_code_execution", False) is True:
            raise InvalidFlowConfigError(
                f"Agent node {node_id!r}: allow_code_execution must be False (code execution must be an isolated sandbox node)"
            )

        # Reject configurations that pass raw MCP servers or unwrapped external tools directly
        if "mcp_servers" in cfg or "raw_tools" in cfg:
            raise InvalidFlowConfigError(
                f"Agent node {node_id!r}: raw MCP servers and unwrapped tools cannot be supplied directly to agent; tools must route via AgentOS Tool Proxy"
            )

    def _validate_dag_topology(self) -> None:
        """Verify that the flow graph has no general cycles outside explicit bounded loops."""
        # Build adjacency graph, excluding allowed back-edges managed by declared loops
        adj: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
        in_degree: dict[str, int] = {node_id: 0 for node_id in self.nodes}

        # Identify declared loop back-edges
        loop_back_edges: set[tuple[str, str]] = set()
        for loop_id, loop_info in self.loops.items():
            back_edge = loop_info.get("back_edge")
            if back_edge and isinstance(back_edge, (list, tuple)) and len(back_edge) == 2:
                loop_back_edges.add((str(back_edge[0]), str(back_edge[1])))

        for edge in self.edges:
            pair = (edge.source, edge.target)
            if pair in loop_back_edges:
                continue
            adj[edge.source].append(edge.target)
            in_degree[edge.target] += 1

        # Kahn's algorithm for cycle detection
        queue = [n for n, d in in_degree.items() if d == 0]
        visited_count = 0

        while queue:
            curr = queue.pop(0)
            visited_count += 1
            for neighbor in adj[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if visited_count != len(self.nodes):
            raise CyclicFlowError(
                "Flow definition contains an illegal general cycle. Only DAGs and explicit bounded loop nodes are permitted."
            )

    def get_node_spec(self, node_id: str) -> NodeSpec:
        node = self.nodes[node_id]
        spec = BUILTIN_NODE_SPECS.get(node.type)
        if not spec:
            raise ValueError(f"No NodeSpec registered for type {node.type!r}")
        return spec
