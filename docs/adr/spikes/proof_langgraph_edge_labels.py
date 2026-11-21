"""Proof / Spike: Evaluating LangGraph for Security Label Propagation and Join on Edges.

LangGraph operates on state dictionaries or Pydantic models where nodes return
partial state updates merged via channel reducers.
This snippet demonstrates the friction of enforcing Information Flow Control (IFC):
1. Every state key must be explicitly wrapped in a custom Labeled[T] container.
2. Custom channel reducers must be authored to implement join logic (most restrictive integrity/confidentiality).
3. LangGraph has no native concept of edge labels or per-argument sink contracts;
   static analysis cannot easily trace data flow because edge transitions are opaque Python functions.
"""
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")

@dataclass(frozen=True)
class SecurityLabel:
    integrity: str  # "trusted" | "untrusted"
    confidentiality: str  # "public" | "internal" | "confidential" | "secret"
    sources: frozenset[str] = field(default_factory=frozenset)

    def join(self, other: "SecurityLabel") -> "SecurityLabel":
        conf_ranks = {"public": 0, "internal": 1, "confidential": 2, "secret": 3}
        inv_conf = {v: k for k, v in conf_ranks.items()}
        new_integrity = "untrusted" if "untrusted" in (self.integrity, other.integrity) else "trusted"
        new_conf = inv_conf[max(conf_ranks[self.confidentiality], conf_ranks[other.confidentiality])]
        return SecurityLabel(integrity=new_integrity, confidentiality=new_conf, sources=self.sources | other.sources)

@dataclass
class Labeled(Generic[T]):
    value: T
    label: SecurityLabel

def label_reducer(a: Labeled[Any] | None, b: Labeled[Any] | None) -> Labeled[Any]:
    """Custom reducer needed for every single key in a LangGraph state graph."""
    if a is None:
        return b  # type: ignore
    if b is None:
        return a
    return Labeled(value=b.value, label=a.label.join(b.label))

# Finding:
# In LangGraph, enforcing this requires user-defined state annotations for EVERY field:
# class State(TypedDict):
#     email_body: Annotated[Labeled[str], label_reducer]
#     email_to: Annotated[Labeled[str], label_reducer]
# This leaks security plumbing into application state schemas and does not permit
# graph-level static analysis of edge connections prior to execution.
print("LangGraph IFC evaluation: High friction, requires custom reducers on all state channels.")
