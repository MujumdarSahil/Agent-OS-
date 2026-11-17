"""
Read-only node spec catalogue (/api/v2/node-specs).

The visual flow builder generates its palette, config forms and argument-mapping
editor from this list, so the UI never hard-codes node types.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter

from agentos.flows.specs import BUILTIN_NODE_SPECS, NodeSpec

router = APIRouter(prefix="/node-specs", tags=["v2-node-specs"])


def _spec_to_dict(spec: NodeSpec) -> Dict[str, Any]:
    return {
        "type": spec.type,
        "side_effect": spec.side_effect.value,
        "idempotent": spec.idempotent,
        "timeout_seconds": spec.timeout_seconds,
        "config_schema": spec.config_schema,
        "input_schema": spec.input_schema,
        "output_schema": spec.output_schema,
        "sink_rules": {arg: rule.model_dump() for arg, rule in spec.sink_rules.items()},
        "constrained_fields": list(spec.constrained_fields),
    }


@router.get("")
async def list_node_specs() -> List[Dict[str, Any]]:
    """Return every built-in NodeSpec, sorted by type. Read-only."""
    from agentos.llm.provider_registry import enabled_model_ids
    from agentos.llm.router_factory import get_fallback_policy_cache

    models = sorted(enabled_model_ids(get_fallback_policy_cache()))
    out = []
    for t in sorted(BUILTIN_NODE_SPECS):
        d = _spec_to_dict(BUILTIN_NODE_SPECS[t])
        props = d["config_schema"].get("properties", {})
        if t in ("llm", "agent") and "model" in props and models:
            # 2.3: the builder offers only models served by enabled providers (checked again on save/publish)
            d["config_schema"] = {**d["config_schema"], "properties": {**props, "model": {**props["model"], "enum": models}}}
        out.append(d)
    return out
