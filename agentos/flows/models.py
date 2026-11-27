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
    # 2.3 control flow: "true"/"false" from a condition node, "on_error" into an error_handler.
    branch: str | None = None


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
            # 3.5: sandbox code tools run only as agent tools through the tool proxy (labels, limits, events)
            from agentos.flows.specs import SANDBOX_TOOL_TYPES

            if node.type in SANDBOX_TOOL_TYPES:
                raise InvalidFlowConfigError(
                    f"Node {node_id!r}: {node.type!r} is an agent tool, not a flow step; give it to an agent node "
                    f"(fail closed)")

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

        # 4. 2.3 control-flow and node-catalog rules
        self._validate_control_flow()

        return self

    def _validate_agent_node(self, node_id: str, node: NodeDefinition) -> None:
        """Enforce strict security hardening and tool spec verification on agent nodes."""
        cfg = node.config

        # Validate that all referenced tools exist (fail closed on unknown tools)
        tools = cfg.get("tools", [])
        for tool_name in tools:
            # 2.5a: a well-formed mcp.<server>.<tool> name is checked by the shared tool catalog instead
            # (approved, unchanged, enabled), at publish by the static analyzer and again at run time.
            from agentos.mcp.catalog import parse_name

            if tool_name not in BUILTIN_NODE_SPECS and parse_name(str(tool_name)) is None:
                raise InvalidFlowConfigError(
                    f"Agent node {node_id!r} references unknown tool {tool_name!r}. "
                    "Unknown tools are rejected at publish (fail closed)."
                )
            # 3.2 (0b): a flow step type is never an agent tool (same set as the picker and the catalog)
            from agentos.flows.specs import AGENT_TOOL_TYPES

            if parse_name(str(tool_name)) is None and tool_name not in AGENT_TOOL_TYPES:
                raise InvalidFlowConfigError(
                    f"Agent node {node_id!r}: {tool_name!r} is a flow step, not an agent tool (fail closed). "
                    f"Agent tools: {', '.join(AGENT_TOOL_TYPES)} or approved mcp.<server>.<tool>."
                )

    def _validate_validator_node(self, node_id: str, node: NodeDefinition) -> None:
        """Validate validator node configuration soundness."""
        field_type = node.config.get("field_type")
        if not field_type:
            raise InvalidFlowConfigError(
                f"Validator node {node_id!r} requires 'field_type' to be specified."
            )

        if field_type == "allowlist_match":
            allowlist_name = node.config.get("allowlist_name")
            if not allowlist_name:
                raise InvalidFlowConfigError(
                    f"Validator node {node_id!r} with field_type='allowlist_match' requires 'allowlist_name'."
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

    def ancestors(self, node_id: str) -> set[str]:
        """All nodes with a path to node_id (excluding loop back-edges)."""
        back = {
            (str(lp["back_edge"][0]), str(lp["back_edge"][1]))
            for lp in self.loops.values()
            if isinstance(lp.get("back_edge"), (list, tuple)) and len(lp["back_edge"]) == 2
        }
        result: set[str] = set()
        stack = [node_id]
        while stack:
            cur = stack.pop()
            for e in self.edges:
                if e.target == cur and (e.source, e.target) not in back and e.source not in result:
                    result.add(e.source)
                    stack.append(e.source)
        return result

    def _validate_control_flow(self) -> None:
        from agentos.flows.expressions import ExpressionError, validate as validate_expr

        for edge in self.edges:
            src, tgt = self.nodes[edge.source], self.nodes[edge.target]
            if edge.branch is None:
                if src.type == "condition":
                    raise InvalidFlowConfigError(
                        f"Edge {edge.source!r}->{edge.target!r} leaves a condition node and needs branch 'true' or 'false'."
                    )
                if tgt.type == "error_handler":
                    raise InvalidFlowConfigError(
                        f"Edge {edge.source!r}->{edge.target!r} enters an error_handler and needs branch 'on_error'."
                    )
            elif edge.branch in ("true", "false"):
                if src.type != "condition":
                    raise InvalidFlowConfigError(f"Branch {edge.branch!r} is only allowed on edges from a condition node.")
            elif edge.branch == "on_error":
                if tgt.type != "error_handler":
                    raise InvalidFlowConfigError("Branch 'on_error' must target an error_handler node.")
                if src.type in ("webhook_trigger", "manual_trigger", "error_handler"):
                    raise InvalidFlowConfigError(f"Node {edge.source!r} of type {src.type!r} cannot have an on_error branch.")
            else:
                raise InvalidFlowConfigError(f"Unknown edge branch {edge.branch!r}.")

        for node_id, node in self.nodes.items():
            if node.type == "error_handler":
                inbound = [e for e in self.edges if e.target == node_id]
                if len(inbound) != 1:
                    raise InvalidFlowConfigError(f"error_handler {node_id!r} needs exactly one inbound on_error edge.")
            upstream = self.ancestors(node_id)
            try:
                if node.type == "condition":
                    validate_expr(node.config["expression"], template=False, upstream=upstream)
                if node.type == "http_request":
                    for key in ("url", "body"):
                        if isinstance(node.config.get(key), str):
                            validate_expr(node.config[key], template=True, upstream=upstream)
                    for val in (node.config.get("query") or {}).values():
                        validate_expr(val, template=True, upstream=upstream)
            except ExpressionError as err:
                raise InvalidFlowConfigError(f"Node {node_id!r}: invalid expression: {err}") from err
            if node.type == "http_request":
                self._validate_http_credentials(node_id, node)
            if node.type == "wait":
                max_delay = float(__import__("os").environ.get("AGENTOS_WAIT_MAX_SECONDS", "86400"))
                if float(node.config.get("delay_seconds", 0)) > max_delay:
                    raise InvalidFlowConfigError(
                        f"wait node {node_id!r}: delay_seconds exceeds the configured maximum ({max_delay:g}s)."
                    )

    def _validate_http_credentials(self, node_id: str, node: NodeDefinition) -> None:
        """Vault credential headers are bound to an author-pinned URL with no data references."""
        from agentos.flows.expressions import references

        vault_headers = [k for k, v in (node.config.get("headers") or {}).items() if isinstance(v, dict)]
        if not vault_headers:
            return
        pinned_url = node.pinned_args.get("url")
        cfg_url = node.config.get("url")
        url_is_static = isinstance(pinned_url, str) or (isinstance(cfg_url, str) and not references(cfg_url, template=True))
        url_from_edge = any(e.target == node_id and "url" in e.arg_mapping for e in self.edges)
        if not url_is_static or (url_from_edge and not isinstance(pinned_url, str)):
            raise InvalidFlowConfigError(
                f"http_request {node_id!r}: vault credential headers {vault_headers} require a pinned URL "
                "(config.url without {{ }} references, or pinned_args.url)."
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
