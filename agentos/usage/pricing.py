"""Model prices (3.2). Order: admin override (agentos.config.yaml usage.prices) -> explicit registry price ->
free-tier / local providers ($0, explicit) -> LiteLLM's bundled model_cost map -> unknown (never guessed).

Prices are per 1M tokens (USD). They are estimates from these tables; the provider's bill is the truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

FREE_TAGS = {"free-tier", "free"}
LOCAL_TAGS = {"local"}


@dataclass(frozen=True)
class Price:
    input_per_1m: Optional[float]
    output_per_1m: Optional[float]
    source: str  # override | registry | free_tier | local | litellm | unknown

    @property
    def known(self) -> bool:
        return self.input_per_1m is not None and self.output_per_1m is not None

    @property
    def free(self) -> bool:
        return self.known and self.input_per_1m == 0 and self.output_per_1m == 0


UNKNOWN = Price(None, None, "unknown")


def _registry_entry(provider: Optional[str]) -> Optional[dict[str, Any]]:
    from agentos.llm.provider_registry import PROVIDER_REGISTRY

    for p in PROVIDER_REGISTRY:
        if p.get("name") == provider:
            return p
    return None


def _override(overrides: dict[str, Any], provider: Optional[str], model: Optional[str]) -> Optional[Price]:
    for key in (provider, model):
        o = (overrides or {}).get(key) if key else None
        if isinstance(o, dict) and "input_per_1m" in o and "output_per_1m" in o:
            return Price(float(o["input_per_1m"]), float(o["output_per_1m"]), "override")
    return None


def _litellm(model: Optional[str]) -> Optional[Price]:
    if not model:
        return None
    try:
        import litellm

        table = getattr(litellm, "model_cost", None) or {}
    except Exception:
        return None
    candidates = [model]
    if "/" in model:
        candidates.append(model.split("/", 1)[1])
    for c in candidates:
        row = table.get(c)
        if isinstance(row, dict):
            i, o = row.get("input_cost_per_token"), row.get("output_cost_per_token")
            if isinstance(i, (int, float)) and isinstance(o, (int, float)):
                return Price(float(i) * 1e6, float(o) * 1e6, "litellm")
    return None


def price_for(provider: Optional[str], model: Optional[str], overrides: Optional[dict[str, Any]] = None,
              local: bool = False) -> Price:
    o = _override(overrides or {}, provider, model)
    if o is not None:
        return o
    entry = _registry_entry(provider)
    if entry is not None:
        p = entry.get("price")
        if isinstance(p, dict) and "input_per_1m" in p and "output_per_1m" in p:
            return Price(float(p["input_per_1m"]), float(p["output_per_1m"]), "registry")
        tags = set(entry.get("tags") or [])
        if tags & LOCAL_TAGS:
            return Price(0.0, 0.0, "local")
        if tags & FREE_TAGS:
            return Price(0.0, 0.0, "free_tier")
    if local:
        return Price(0.0, 0.0, "local")
    return _litellm(model) or UNKNOWN


def cost_usd(price: Price, prompt_tokens: int, completion_tokens: int) -> Optional[float]:
    if not price.known:
        return None
    return round((prompt_tokens or 0) * price.input_per_1m / 1e6 + (completion_tokens or 0) * price.output_per_1m / 1e6, 8)
