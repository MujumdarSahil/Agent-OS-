"""Flow graph data models and structural validation (DAG + bounded loops).

Flow definitions declare nodes, directed edges with argument mapping, and entrypoints.
The validator enforces that flows are acyclic graphs with explicit bounded loops only,
validates node configs against jsonschema, and rejects unknown tools.
"""

from __future__ import annotations

from typing import Any
import jsonschema
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
    # One canonical pinning syntax: node.pinned_args
    # Direct sinks use argument name (e.g. "to": "team@corp.local")
    # Agent tools use "tool.arg" (e.g. "send_email.to": "team@corp.local")
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
        """Validate node specs, agent hardening, schema validation, and DAG topology."""
        if self.entrypoint not in self.nodes:
            raise InvalidFlowConfigError(
                f"Entrypoint {self.entrypoint!r} is not defined in nodes"
            )

        # 1. Validate node specifications and schemas
        for node_id, node in self.nodes.items():
            spec = BUILTIN_NODE_SPECS.get(node.type)
            if not spec:
                raise InvalidFlowConfigError(f"Unknown node type {node.type!r} on node {node_id!r}")

            # Validate node config against spec.config_schema via jsonschema
            if spec.config_schema:
                try:
                    jsonschema.validate(instance=node.config, schema=spec.config_schema)
                except jsonschema.ValidationError as err:
                    raise InvalidFlowConfigError(
                        f"Node {node_id!r} config schema validation failed: {err.message}"
                    ) from err

            # Specific rules for agent nodes
            if node.type == "agent":
                self._validate_agent_node(node_id, node)

            # Specific rules for validator nodes
            if node.type == "validator":
                self._validate_validator_node(node_id, node)

            # Specific rules for approval nodes
            if node.type == "approval":
                self._validate_approval_node(node_id, node)

        # 2. Validate edge references and output fields (unknown source field is a publish error)
        for edge in self.edges:
            if edge.source not in self.nodes:
                raise InvalidFlowConfigError(f"Edge references unknown source node: {edge.source!r}")
            if edge.target not in self.nodes:
                raise InvalidFlowConfigError(f"Edge references unknown target node: {edge.target!r}")

            src_node = self.nodes[edge.source]
            src_spec = BUILTIN_NODE_SPECS.get(src_node.type)
            if src_spec and src_spec.output_schema.get("properties"):
                allowed_props = set(src_spec.output_schema["properties"].keys())
                if src_node.type == "validator" and "field" in src_node.config:
                    allowed_props.add(src_node.config["field"])
                for target_arg, src_field in edge.arg_mapping.items():
                    if src_field not in allowed_props:
                        raise InvalidFlowConfigError(
                            f"Edge from {edge.source!r} to {edge.target!r} references unknown source output field "
                            f"{src_field!r}. Source node {edge.source!r} (type: {src_node.type!r}) outputs: "
                            f"{sorted(allowed_props)}."
                        )

        # 3. Validate DAG topology (DAG + explicit bounded loops only)
        self._validate_dag_topology()

        return self

    def _validate_agent_node(self, node_id: str, node: NodeDefinition) -> None:
        """Enforce strict security hardening and tool spec verification on agent nodes."""
        cfg = node.config

        # Validate that all referenced tools exist (fail closed on unknown tools)
        tools = cfg.get("tools", [])
        for tool_name in tools:
            if tool_name not in BUILTIN_NODE_SPECS:
                raise InvalidFlowConfigError(
                    f"Agent node {node_id!r} references unknown tool {tool_name!r}. "
                    "Unknown tools are rejected at publish (fail closed)."
                )

    def _validate_validator_node(self, node_id: str, node: NodeDefinition) -> None:
        """Validate validator node configuration soundness."""
        field_type = node.config.get("field_type")
        if not field_type:
            raise InvalidFlowConfigError(
                f"Validator node {node_id!r} requires 'field_type' to be specified."
            )

        if field_type == "allowlist_match":
            allowlist = node.config.get("allowlist")
            allowlist_name = node.config.get("allowlist_name")
            if not allowlist and not allowlist_name:
                raise InvalidFlowConfigError(
                    f"Validator node {node_id!r} with field_type='allowlist_match' requires a non-empty allowlist or allowlist_name."
                )
            if allowlist is not None and len(allowlist) == 0:
                raise InvalidFlowConfigError(
                    f"Validator node {node_id!r} with field_type='allowlist_match' requires a non-empty allowlist."
                )

    def _validate_approval_node(self, node_id: str, node: NodeDefinition) -> None:
        """Validate approval node configuration targeting."""
        approves = node.config.get("approves", {})
        sink_node = approves.get("sink_node")
        args = approves.get("args")

        if not sink_node:
            raise InvalidFlowConfigError(f"Approval node {node_id!r} requires 'approves.sink_node'.")
        if sink_node not in self.nodes:
            raise InvalidFlowConfigError(
                f"Approval node {node_id!r} approves non-existent sink node {sink_node!r}."
            )
        target_node = self.nodes[sink_node]
        if target_node.type == "agent":
            raise InvalidFlowConfigError(
                f"Approval node {node_id!r} targets an agent node {sink_node!r}. "
                "Approval cannot declassify agent context in general; an approval node placed before an agent does not make the agent context trusted."
            )
        if not args or not isinstance(args, list) or len(args) == 0:
            raise InvalidFlowConfigError(
                f"Approval node {node_id!r} requires a non-empty list of approved 'args'."
            )

    def _validate_dag_topology(self) -> None:
        """Verify that the flow graph has no general cycles outside explicit bounded loops."""
        adj: dict[str, list[str]] = {node_id: [] for node_id in self.nodes}
        in_degree: dict[str, int] = {node_id: 0 for node_id in self.nodes}

        loop_back_edges: set[tuple[str, str]] = set()
        for loop_info in self.loops.values():
            back_edge = loop_info.get("back_edge")
            if back_edge and isinstance(back_edge, (list, tuple)) and len(back_edge) == 2:
                loop_back_edges.add((str(back_edge[0]), str(back_edge[1])))

        for edge in self.edges:
            pair = (edge.source, edge.target)
            if pair in loop_back_edges:
                continue
            adj[edge.source].append(edge.target)
            in_degree[edge.target] += 1

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
