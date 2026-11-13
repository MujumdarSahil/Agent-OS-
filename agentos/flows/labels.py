"""Information Flow Control (IFC) labels and Labeled value wrapper.

Every value moving between workflow nodes carries a security label:
- Integrity: 'trusted' | 'untrusted'
- Confidentiality: 'public' < 'internal' < 'confidential' < 'secret'
- Sources: frozenset of event references / source node run identifiers
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class Integrity(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Confidentiality(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


_CONFIDENTIALITY_ORDER: dict[str, int] = {
    Confidentiality.PUBLIC.value: 0,
    Confidentiality.INTERNAL.value: 1,
    Confidentiality.CONFIDENTIAL.value: 2,
    Confidentiality.SECRET.value: 3,
}

_ORDER_TO_CONFIDENTIALITY: dict[int, str] = {
    v: k for k, v in _CONFIDENTIALITY_ORDER.items()
}


@dataclass(frozen=True)
class Label:
    """Security label representing Information Flow Control metadata."""

    integrity: str = Integrity.UNTRUSTED.value
    confidentiality: str = Confidentiality.INTERNAL.value
    sources: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.integrity not in (Integrity.TRUSTED.value, Integrity.UNTRUSTED.value):
            raise ValueError(f"Invalid integrity: {self.integrity!r}")
        if self.confidentiality not in _CONFIDENTIALITY_ORDER:
            raise ValueError(f"Invalid confidentiality: {self.confidentiality!r}")

    @classmethod
    def trusted(
        cls,
        confidentiality: str = Confidentiality.INTERNAL.value,
        sources: frozenset[str] | set[str] | None = None,
    ) -> Label:
        return cls(
            integrity=Integrity.TRUSTED.value,
            confidentiality=confidentiality,
            sources=frozenset(sources or ()),
        )

    @classmethod
    def untrusted(
        cls,
        confidentiality: str = Confidentiality.INTERNAL.value,
        sources: frozenset[str] | set[str] | None = None,
    ) -> Label:
        return cls(
            integrity=Integrity.UNTRUSTED.value,
            confidentiality=confidentiality,
            sources=frozenset(sources or ()),
        )

    def join(self, other: Label) -> Label:
        """Compute the lattice join (most restrictive labels, union of sources)."""
        new_integrity = (
            Integrity.UNTRUSTED.value
            if (self.integrity == Integrity.UNTRUSTED.value or other.integrity == Integrity.UNTRUSTED.value)
            else Integrity.TRUSTED.value
        )
        max_rank = max(
            _CONFIDENTIALITY_ORDER[self.confidentiality],
            _CONFIDENTIALITY_ORDER[other.confidentiality],
        )
        new_conf = _ORDER_TO_CONFIDENTIALITY[max_rank]
        new_sources = self.sources | other.sources
        return Label(
            integrity=new_integrity,
            confidentiality=new_conf,
            sources=new_sources,
        )

    @classmethod
    def join_all(cls, labels: list[Label], default: Label | None = None) -> Label:
        if not labels:
            return default or cls.trusted()
        result = labels[0]
        for lbl in labels[1:]:
            result = result.join(lbl)
        return result


@dataclass(frozen=True)
class Labeled(Generic[T]):
    """Wrapper encapsulating a value and its Information Flow Control label."""

    value: T
    label: Label

    def unwrap(self) -> T:
        return self.value

    @classmethod
    def of(
        cls,
        value: T,
        integrity: str = Integrity.UNTRUSTED.value,
        confidentiality: str = Confidentiality.INTERNAL.value,
        sources: frozenset[str] | set[str] | None = None,
    ) -> Labeled[T]:
        return cls(
            value=value,
            label=Label(
                integrity=integrity,
                confidentiality=confidentiality,
                sources=frozenset(sources or ()),
            ),
        )
