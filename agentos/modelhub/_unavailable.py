"""
Marks ModelHub training/performance classes as NOT AVAILABLE in AgentOS 2.0 (rule 4).

These classes previously returned success-shaped results without doing any work (for example
LoRAUtils.apply_lora returned {"success": True}). ML Studio / training was removed from 2.0 (see
docs/SPEC_2.0.md); the import paths stay so existing imports do not break, but constructing the
class or calling any of its methods raises NotImplementedError.
"""

from __future__ import annotations

from typing import Any, Callable, TypeVar

T = TypeVar("T", bound=type)


def unavailable_message(feature: str) -> str:
    return (
        f"{feature} is not available in AgentOS 2.0; see docs/SPEC_2.0.md "
        "(ML Studio/training removed from 2.0, tracked on the 2.1 backlog)."
    )


def not_available(feature: str) -> Callable[[T], T]:
    """Class decorator: constructor and every method raise NotImplementedError."""
    msg = unavailable_message(feature)

    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise NotImplementedError(msg)

    def _new(_cls: type, *_args: Any, **_kwargs: Any) -> Any:
        raise NotImplementedError(msg)

    def decorate(cls: T) -> T:
        for name, value in list(vars(cls).items()):
            if name.startswith("__") and name.endswith("__"):
                continue
            if isinstance(value, (staticmethod, classmethod)) or callable(value):
                setattr(cls, name, staticmethod(_raise))
        cls.__new__ = _new  # type: ignore[assignment]
        cls.__doc__ = f"NOT AVAILABLE in AgentOS 2.0. {cls.__doc__ or ''}".strip()
        return cls

    return decorate
