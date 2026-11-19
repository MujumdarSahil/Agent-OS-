"""Static flow graph analyzer and Information Flow Control verification.

The StaticFlowAnalyzer inspects declarative flow definitions before execution,
over-approximates security labels from sources through joins and declassification
nodes, iterates over loop back-edges to a fixpoint, and rejects any flow where
untrusted data reaches sensitive sink arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentos.flows.labels import Confidentiality, Label
from agentos.flows.models import FlowDefinition, NodeDefinition
from agentos.flows.policy import SecurityPolicy
from typing import Any

from agentos.flows.calculator import calculator_output_labels
from agentos.flows.expressions import label_of, references
from agentos.flows.extraction import config_errors as extraction_config_errors
from agentos.flows.extraction import (
    extraction_output_labels, is_approval_gated, validator_config_errors, validator_output_labels,
)
from agentos.flows.rules import RuleViolation, evaluate_control_dependency, evaluate_sink_argument_rule
from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec, SideEffectClass, effective_side_effect, is_checked_sink
from agentos.flows.tool_catalog import (
    BUILTIN_CATALOG,
    ToolCatalog,
    ToolEntry,
    ToolLookupError,
    agent_initial_context,
    context_after_tool_output,
)
from agentos.mcp.catalog import is_mcp_name

# Backwards compatibility alias
Violation = RuleViolation


@dataclass
class PublishVerificationResult:
    """Outcome of publish-time static flow verification."""

    is_valid: bool
    violations: list[RuleViolation] = field(default_factory=list)

    @property
    def error_message(self) -> str:
        if self.is_valid:
            return ""
        lines = ["Flow verification failed with security violations:"]
        for v in self.violations:
            path_str = " -> ".join(v.path)
            lines.append(f"  - [{v.node_id}:{v.target_arg}] {v.reason} (Path: {path_str})")
        return "\n".join(lines)


class StaticFlowAnalyzer:
    """Analyzes flow graphs for Information Flow Control (IFC) and sink policy compliance."""

    def __init__(
        self,
        flow: FlowDefinition,
        policy: SecurityPolicy | None = None,
        subflow_summaries: dict[tuple[str, int], dict[str, Any] | None] | None = None,
        tool_catalog: ToolCatalog | None = None,
    ) -> None:
        self.flow = flow
        self.policy = policy or SecurityPolicy()
        # 2.5a: one tool-spec lookup shared with the runtime proxy (built-ins + approved MCP tools)
        self.tool_catalog = tool_catalog or BUILTIN_CATALOG
        # (flow_id, version) -> published analysis summary of a subflow (None/missing = unknown).
        self.subflow_summaries = subflow_summaries or {}
        self._labels: dict[str, dict[str, Label]] = {}

    # ------------------------------------------------------------------ 2.3 helpers

    def _descendants(self, start: str) -> set[str]:
        back = {
            (str(lp["back_edge"][0]), str(lp["back_edge"][1]))
            for lp in self.flow.loops.values()
            if isinstance(lp.get("back_edge"), (list, tuple)) and len(lp["back_edge"]) == 2
        }
        seen = {start}
        stack = [start]
        while stack:
            cur = stack.pop()
            for e in self.flow.edges:
                if e.source == cur and (e.source, e.target) not in back and e.target not in seen:
                    seen.add(e.target)
                    stack.append(e.target)
        return seen

    def control_labels(self, node_output_labels: dict[str, dict[str, Label]]) -> dict[str, Label]:
        """Join of every condition predicate (and failure path) that decides whether a node runs."""
        ctrl: dict[str, Label] = {}
        for e in self.flow.edges:
            if e.branch in ("true", "false"):
                lbl = label_of(self.flow.nodes[e.source].config.get("expression", ""), node_output_labels)
            elif e.branch == "on_error":
                # A failure can be induced by attacker-controlled input or responses: untrusted.
                lbl = Label.untrusted(sources={e.source})
            else:
                continue
            for n in self._descendants(e.target):
                ctrl[n] = ctrl[n].join(lbl) if n in ctrl else lbl
        return ctrl

    def http_arg_labels_and_context(
        self,
        node_id: str,
        node: NodeDefinition,
        arg_labels: dict[str, Label],
        labels: dict[str, dict[str, Label]],
    ) -> tuple[dict[str, Label], dict[str, Any]]:
        """Static labels of http_request url/body/query/headers and the sink context for the rules."""
        cfg = node.config
        out = dict(arg_labels)
        for key in ("url", "body"):
            if isinstance(cfg.get(key), str) and key not in node.pinned_args:
                out[key] = label_of(cfg[key], labels, template=True)
        cfg_query = cfg.get("query") or {}
        if cfg_query and "query" not in node.pinned_args:
            q_lbls = [label_of(v, labels, template=True) for v in cfg_query.values()]
            if "query" in out:
                q_lbls.append(out["query"])
            out["query"] = Label.join_all(q_lbls, default=Label.trusted())
        plain_headers = {k: v for k, v in (cfg.get("headers") or {}).items() if isinstance(v, str)}
        if plain_headers and "headers" not in out:
            out["headers"] = Label.trusted(sources={node_id})
        static_url = node.pinned_args.get("url")
        if not isinstance(static_url, str):
            cfg_url = cfg.get("url")
            url_mapped = any(e.target == node_id and "url" in e.arg_mapping for e in self.flow.edges)
            if isinstance(cfg_url, str) and not references(cfg_url, template=True) and not url_mapped:
                static_url = cfg_url
            else:
                static_url = None
        query_from_data = any(e.target == node_id and "query" in e.arg_mapping for e in self.flow.edges) or any(
            references(v, template=True) for v in cfg_query.values()
        )
        from agentos.flows.net_guard import url_host

        ctx = {
            "method": str(cfg.get("method") or "GET").upper(),
            "host": url_host(static_url) if static_url else None,
            "host_allowlisted": bool(static_url) and self.policy.is_http_allowlisted(static_url),
            "query_from_data": query_from_data,
        }
        return out, ctx

    def summary(self) -> dict[str, Any]:
        """Analysis summary stored with a published version (reused when called as a subflow)."""
        labels, _, _ = self._propagate_labels_fixpoint()
        terminals = [n for n in self.flow.nodes if not any(e.source == n for e in self.flow.edges)]
        out = Label.join_all([lbl for t in terminals for lbl in labels.get(t, {}).values()], default=Label.trusted())
        has_waiting = any(n.type in ("approval", "wait") for n in self.flow.nodes.values())
        refs = []
        for n in self.flow.nodes.values():
            if n.type == "subflow":
                key = (n.config["flow_id"], int(n.config["version"]))
                refs.append(list(key))
                child = self.subflow_summaries.get(key) or {}
                has_waiting = has_waiting or bool(child.get("has_waiting"))
        mcp_names = [t for n in self.flow.nodes.values() if n.type == "agent" for t in (n.config.get("tools") or [])]
        return {
            "output_label": out.model_dump(mode="json"), "has_waiting": has_waiting, "subflows": refs,
            # 2.5a: hashes of the approved MCP tools this version uses; a run fails closed if one changed
            "mcp_tools": self.tool_catalog.mcp_hashes(mcp_names),
        }

    # ------------------------------------------------------------------ 2.5a agent tools

    def _agent_tools(self, node: NodeDefinition) -> tuple[list[ToolEntry], list[ToolLookupError]]:
        """Resolved tools of an agent node; unresolved MCP tools are returned as errors (unknown bare
        names are skipped here as before; the runtime proxy rejects them)."""
        entries: list[ToolEntry] = []
        errors: list[ToolLookupError] = []
        for name in node.config.get("tools", []) or []:
            try:
                entries.append(self.tool_catalog.resolve(name))
            except ToolLookupError as e:
                if is_mcp_name(name):
                    errors.append(e)
        return entries, errors

    def _agent_context(self, node: NodeDefinition, inbound: Label) -> Label:
        """Same rule as the runtime proxy: an unreplaced MCP description makes the context untrusted from
        the start; MCP tool outputs are untrusted with their configured confidentiality."""
        entries, _ = self._agent_tools(node)
        ctx = agent_initial_context(inbound, entries)
        for e in entries:
            # Outputs the model can read before calling a sink: read tools (same rule as built-ins). A sink's
            # own output only exists after it ran; the proxy then makes the context untrusted for later calls.
            if e.spec.type in ("fetch_url", "tool") or e.spec.side_effect == SideEffectClass.READ:
                ctx = context_after_tool_output(ctx, e)
        return ctx

    def verify(self) -> PublishVerificationResult:
        """Statically inspect flow graph and verify that sink arguments satisfy security policies."""
        violations: list[RuleViolation] = []

        # 1. Propagate labels across graph edges (including back-edges) to a fixpoint
        node_output_labels, node_effective_inbound, node_paths = self._propagate_labels_fixpoint()
        control = self.control_labels(node_output_labels)

        # 2. Verify all sink policies on the stabilized label environment
        for node_id, node in self.flow.nodes.items():
            spec = BUILTIN_NODE_SPECS.get(node.type) or NodeSpec(type=node.type)
            current_path = node_paths.get(node_id, [node_id])
            effective_inbound = node_effective_inbound.get(node_id, Label.trusted())

            # Collect arriving argument labels
            inbound_edges = [e for e in self.flow.edges if e.target == node_id]
            arg_labels: dict[str, Label] = {}
            for edge in inbound_edges:
                src_labels = node_output_labels.get(edge.source, {})
                for target_arg, src_field in edge.arg_mapping.items():
                    if src_field in src_labels:
                        arg_labels[target_arg] = src_labels[src_field]

            # Direct sink nodes check (effective side effect: http_request depends on its method)
            eff = effective_side_effect(node.type, node.config)
            if is_checked_sink(node.type, node.config):
                eff_spec = spec.model_copy(update={"side_effect": eff})
                sink_ctx = None
                if node.type == "http_request":
                    arg_labels, sink_ctx = self.http_arg_labels_and_context(
                        node_id, node, arg_labels, node_output_labels
                    )
                self._check_node_sinks(
                    node_id, node, eff_spec, arg_labels, effective_inbound, current_path, violations, sink_ctx
                )

            # 2.3: destructive sinks need a trusted control dependency
            # 2.5b: a predicate trusted only through a declassification needs an approval-gated sink
            violations.extend(
                evaluate_control_dependency(
                    node_id, eff, control.get(node_id), current_path,
                    approval_gated=is_approval_gated(self.flow, node_id), policy=self.policy,
                )
            )

            # 2.5b: semantic config checks of quarantined extraction (the JSON Schema ran in FlowDefinition)
            if node.type == "quarantined_extraction":
                for err in extraction_config_errors(node.config, self.policy.allowlists):
                    violations.append(
                        RuleViolation(node_id=node_id, target_arg="(config)", path=current_path, reason=err)
                    )
            # 2.5b hardening: a validator must use a constrained type with its constraint (same code as extraction)
            if node.type == "validator":
                for err in validator_config_errors(node.config, self.policy.allowlists):
                    violations.append(
                        RuleViolation(node_id=node_id, target_arg="(config)", path=current_path, reason=err)
                    )

            # 2.3: subflows containing approval/wait are not supported yet (decision C)
            if node.type == "subflow":
                key = (node.config["flow_id"], int(node.config["version"]))
                if (self.subflow_summaries.get(key) or {}).get("has_waiting"):
                    violations.append(
                        RuleViolation(
                            node_id=node_id,
                            target_arg="(subflow)",
                            path=current_path,
                            reason=f"Subflow {key[0]!r} v{key[1]} contains approval or wait nodes; not supported in subflows yet.",
                        )
                    )

            # Agent nodes with attached tools check
            if node.type == "agent":
                self._check_agent_tool_sinks(
                    node_id, node, effective_inbound, current_path, violations
                )

        return PublishVerificationResult(
            is_valid=len(violations) == 0,
            violations=violations,
        )

    def _propagate_labels_fixpoint(
        self,
    ) -> tuple[dict[str, dict[str, Label]], dict[str, Label], dict[str, list[str]]]:
        """Iteratively propagate security labels across all edges to a fixpoint.

        Handles loops and back-edges correctly: if untrusted data enters only
        through a back-edge, it will degrade downstream labels to untrusted.
        """
        node_output_labels: dict[str, dict[str, Label]] = {}
        self._labels = node_output_labels  # read by expression label computation (condition nodes)
        node_effective_inbound: dict[str, Label] = {}
        node_paths: dict[str, list[str]] = {self.flow.entrypoint: [self.flow.entrypoint]}

        # Initialize entrypoint: entrypoint inputs are treated as untrusted when checking publish
        # (any flow can be bound to a webhook later)
        entry_node = self.flow.nodes[self.flow.entrypoint]
        entry_spec = BUILTIN_NODE_SPECS.get(entry_node.type) or NodeSpec(type=entry_node.type)
        init_inbound = Label.untrusted(sources={self.flow.entrypoint})

        node_effective_inbound[self.flow.entrypoint] = init_inbound
        node_output_labels[self.flow.entrypoint] = self._compute_output_labels(
            self.flow.entrypoint, entry_node, entry_spec, init_inbound, {}
        )

        max_iterations = (len(self.flow.nodes) + 1) * 4
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            changed = False

            for node_id, node in self.flow.nodes.items():
                spec = BUILTIN_NODE_SPECS.get(node.type) or NodeSpec(type=node.type)
                inbound_edges = [e for e in self.flow.edges if e.target == node_id]

                inbound_labels: list[Label] = []
                arg_labels: dict[str, Label] = {}

                for edge in inbound_edges:
                    src_labels = node_output_labels.get(edge.source, {})
                    if not src_labels:
                        continue

                    # Every edge carries the join of all source output labels, mapped or not
                    src_join_all = Label.join_all(list(src_labels.values()), default=Label.trusted())
                    inbound_labels.append(src_join_all)

                    # Update path
                    src_path = node_paths.get(edge.source, [edge.source])
                    if node_id not in node_paths:
                        node_paths[node_id] = src_path + [node_id]

                    # Map individual arguments
                    for target_arg, src_field in edge.arg_mapping.items():
                        if src_field in src_labels:
                            arg_labels[target_arg] = src_labels[src_field]

                if not inbound_labels and node_id == self.flow.entrypoint:
                    effective_inbound = node_effective_inbound.get(
                        node_id,
                        Label.untrusted(sources={node_id}),
                    )
                elif inbound_labels:
                    effective_inbound = Label.join_all(inbound_labels, default=Label.trusted())
                else:
                    effective_inbound = Label.trusted(sources={node_id})

                # Check if inbound changed
                prev_inbound = node_effective_inbound.get(node_id)
                if prev_inbound != effective_inbound:
                    node_effective_inbound[node_id] = effective_inbound
                    changed = True

                # Compute output labels
                new_outputs = self._compute_output_labels(
                    node_id, node, spec, effective_inbound, arg_labels
                )
                prev_outputs = node_output_labels.get(node_id, {})
                if prev_outputs != new_outputs:
                    node_output_labels[node_id] = new_outputs
                    changed = True

            if not changed:
                break

        return node_output_labels, node_effective_inbound, node_paths

    def _check_node_sinks(
        self,
        node_id: str,
        node: NodeDefinition,
        spec: NodeSpec,
        arg_labels: dict[str, Label],
        effective_inbound: Label,
        current_path: list[str],
        violations: list[RuleViolation],
        sink_context: dict[str, Any] | None = None,
    ) -> None:
        """Verify sink arguments on direct sink nodes using the shared rule engine."""
        pinned_args = node.pinned_args

        # Confidentiality check for unmapped wildcard inputs
        if spec.side_effect == SideEffectClass.EXTERNAL_SEND:
            if effective_inbound.confidentiality == Confidentiality.SECRET.value:
                violations.append(
                    RuleViolation(
                        node_id=node_id,
                        target_arg="*",
                        path=current_path,
                        reason=(
                            f"Confidentiality violation: secret-labeled data cannot be passed "
                            f"to EXTERNAL_SEND sink {node_id!r}."
                        ),
                    )
                )

        # Evaluate rules using shared engine
        for arg_name, rule in spec.sink_rules.items():
            is_pinned = arg_name in pinned_args
            arriving_label = (
                Label.trusted(sources={node_id})
                if is_pinned
                else arg_labels.get(arg_name, effective_inbound)
            )

            # Part 0.a: Argument is approved only if mapped on edge from approval node
            is_approved = False
            for edge in self.flow.edges:
                if edge.target == node_id and arg_name in edge.arg_mapping:
                    src_node = self.flow.nodes.get(edge.source)
                    if src_node and src_node.type == "approval":
                        approves_cfg = src_node.config.get("approves", {})
                        if (
                            approves_cfg.get("sink_node") == node_id
                            and arg_name in approves_cfg.get("args", [])
                        ):
                            is_approved = True
                            break

            arg_violations = evaluate_sink_argument_rule(
                node_id=node_id,
                spec=spec,
                arg_name=arg_name,
                rule=rule,
                arriving_label=arriving_label,
                effective_inbound_label=effective_inbound,
                is_pinned=is_pinned,
                is_approved=is_approved,
                pinned_to_val=pinned_args.get("to"),
                policy=self.policy,
                path=current_path,
                sink_context=sink_context,
                approval_gated=is_approval_gated(self.flow, node_id),
            )
            violations.extend(arg_violations)

    def _check_agent_tool_sinks(
        self,
        node_id: str,
        node: NodeDefinition,
        agent_input_label: Label,
        current_path: list[str],
        violations: list[RuleViolation],
    ) -> None:
        """Verify sink tools attached to agent nodes using the shared rule engine."""
        pinned_args = node.pinned_args
        entries, lookup_errors = self._agent_tools(node)
        # 2.5a: unknown, unreviewed, changed, missing or disabled MCP tools refuse publish (fail closed)
        for err in lookup_errors:
            violations.append(RuleViolation(node_id=node_id, target_arg=err.name, path=current_path + [err.name],
                                            reason=str(err)))

        # Accumulate agent context (shared rule with the runtime proxy, see tool_catalog)
        agent_context_label = self._agent_context(node, agent_input_label)

        for entry in entries:
            tool_name = entry.name
            tool_spec = entry.spec

            # Confidentiality check for agent sink tools
            if tool_spec.side_effect == SideEffectClass.EXTERNAL_SEND:
                if agent_context_label.confidentiality == Confidentiality.SECRET.value:
                    violations.append(
                        RuleViolation(
                            node_id=node_id,
                            target_arg=tool_name,
                            path=current_path + [tool_name],
                            reason=(
                                f"Confidentiality violation: secret-labeled data cannot be passed "
                                f"to EXTERNAL_SEND tool {tool_name!r} attached to agent {node_id!r}."
                            ),
                        )
                    )

            if not tool_spec.sink_rules:
                continue

            for arg_name, rule in tool_spec.sink_rules.items():
                canonical_pinned_key = f"{tool_name}.{arg_name}"
                is_pinned = canonical_pinned_key in pinned_args or arg_name in pinned_args
                arriving_label = (
                    Label.trusted(sources={node_id})
                    if is_pinned
                    else agent_context_label
                )
                to_val = (
                    pinned_args.get(f"{tool_name}.to")
                    or pinned_args.get("to")
                )

                arg_violations = evaluate_sink_argument_rule(
                    node_id=node_id,
                    spec=tool_spec,
                    arg_name=canonical_pinned_key,
                    rule=rule,
                    arriving_label=arriving_label,
                    effective_inbound_label=agent_context_label,
                    is_pinned=is_pinned,
                    is_approved=False,  # Approval cannot declassify agent context in general
                    pinned_to_val=to_val,
                    policy=self.policy,
                    path=current_path + [tool_name],
                )
                violations.extend(arg_violations)

    def _compute_output_labels(
        self,
        node_id: str,
        node: NodeDefinition,
        spec: NodeSpec,
        effective_inbound: Label,
        arg_labels: dict[str, Label],
    ) -> dict[str, Label]:
        """Compute output labels for a node based on its type and declassification semantics."""
        # 1. Webhook trigger produces untrusted output explicitly
        if node.type == "webhook_trigger":
            lbl = Label.untrusted(sources={node_id})
            return {"payload": lbl, "headers": lbl, "*": lbl}

        # 2. Tool nodes produce untrusted output explicitly
        # 3.1 calculator: untrusted tool output, keeps the inbound confidentiality (engine uses the same function)
        if node.type == "calculator":
            return calculator_output_labels(node_id, effective_inbound)

        if node.type in ("tool", "fetch_url"):
            lbl = Label.untrusted(sources={node_id})
            return {"result": lbl, "content": lbl, "*": lbl}

        # 3. Approval node: human approval declassifies only approved args on approved sink node directly
        if node.type == "approval":
            approved_flag = Label.trusted(
                confidentiality=effective_inbound.confidentiality,
                sources=effective_inbound.sources | {node_id},
            )
            return {
                "approved": approved_flag,
                "data": effective_inbound,
                "*": effective_inbound,
            }

        # 3b. 2.5b quarantined extraction: the shared label function (the engine calls the same one).
        if node.type == "quarantined_extraction":
            return extraction_output_labels(node_id, node.config.get("fields") or [], effective_inbound)

        # 4. Validator node (2.5b hardening): the shared label function (the engine calls the same one). An
        #    unconstrained or incomplete config declassifies nothing (untrusted) and is refused in verify().
        if node.type == "validator":
            return validator_output_labels(node_id, node.config, effective_inbound, self.policy.allowlists)

        # 5. Agent node inherits inbound label and joins with tools producing untrusted output
        if node.type == "agent":
            agent_ctx = self._agent_context(node, effective_inbound)
            out_lbl = Label(
                integrity=agent_ctx.integrity,
                confidentiality=agent_ctx.confidentiality,
                sources=agent_ctx.sources | {node_id},
            )
            return {"output": out_lbl, "*": out_lbl}

        # 6. LLM node inherits input label join
        if node.type == "llm":
            out_lbl = Label(
                integrity=effective_inbound.integrity,
                confidentiality=effective_inbound.confidentiality,
                sources=effective_inbound.sources | {node_id},
            )
            return {"completion": out_lbl, "*": out_lbl}

        # 7. 2.3 node catalog
        if node.type == "http_request":
            lbl = Label.untrusted(confidentiality=effective_inbound.confidentiality, sources={node_id})
            return {k: lbl for k in ("status", "headers", "body", "final_url", "truncated", "*")}
        if node.type == "condition":
            pred = label_of(node.config.get("expression", ""), self._labels)
            return {"branch": pred, "result": pred, "*": effective_inbound.join(pred)}
        if node.type == "error_handler":
            lbl = Label.untrusted(sources={node_id})
            return {k: lbl for k in ("failed_node", "error_type", "message", "*")}
        if node.type == "subflow":
            summary = self.subflow_summaries.get((node.config["flow_id"], int(node.config["version"])))
            if summary and summary.get("output_label"):
                sub = Label.model_validate(summary["output_label"])
                lbl = Label(integrity=sub.integrity, confidentiality=sub.confidentiality,
                            sources=sub.sources | effective_inbound.sources | {node_id})
                lbl = lbl.join(effective_inbound) if effective_inbound.integrity == "untrusted" else lbl
            else:
                lbl = Label.untrusted(confidentiality=effective_inbound.confidentiality, sources={node_id})
            return {"outputs": lbl, "*": lbl}

        # Default fallback: inherit effective inbound label
        out_lbl = Label(
            integrity=effective_inbound.integrity,
            confidentiality=effective_inbound.confidentiality,
            sources=effective_inbound.sources | {node_id},
        )
        return {"*": out_lbl}
