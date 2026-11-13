"""Shared sink rule evaluation engine and recipient validation.

Both the publish-time StaticFlowAnalyzer and the runtime tool proxy / flow engine
call this exact evaluation code, ensuring Information Flow Control (IFC) policy
logic is never duplicated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agentos.flows.labels import Confidentiality, Integrity, Label
from agentos.flows.policy import SecurityPolicy
from agentos.flows.specs import NodeSpec, SideEffectClass, SinkArgumentRule


@dataclass
class RuleViolation:
    """Represents an IFC rule violation detected statically or at runtime."""

    node_id: str
    target_arg: str
    path: list[str]
    reason: str


class SinkRuleViolationError(Exception):
    """Raised at runtime when a tool call or sink invocation violates IFC policies."""

    def __init__(self, violation: RuleViolation):
        self.violation = violation
        super().__init__(f"[{violation.node_id}:{violation.target_arg}] {violation.reason}")


class PinnedArgumentOverrideError(Exception):
    """Raised at runtime when an LLM attempts to override an author-pinned argument."""


def normalize_and_validate_recipients(to_value: Any) -> list[str]:
    """Validate and normalize email recipient(s).

    Enforces:
    - `to` must be one address (str) or a list of addresses (list[str])
    - Rejects comma-joined strings (e.g. 'alice@corp.local, bob@corp.local')
    - Rejects display-name forms (e.g. 'Alice <alice@corp.local>')
    - Normalises case before policy checks
    """
    if to_value is None:
        raise ValueError("Recipient address 'to' cannot be None.")

    raw_recipients: list[str] = []
    if isinstance(to_value, str):
        raw_recipients = [to_value]
    elif isinstance(to_value, (list, tuple)):
        for item in to_value:
            if not isinstance(item, str):
                raise ValueError(f"Recipient entry must be a string, got {type(item).__name__}: {item!r}")
            raw_recipients.append(item)
    else:
        raise ValueError(f"Recipient must be a string or list of strings, got {type(to_value).__name__}: {to_value!r}")

    normalized: list[str] = []
    for addr in raw_recipients:
        addr_clean = addr.strip()
        # Reject comma-joined strings
        if "," in addr_clean:
            raise ValueError(
                f"Comma-joined email addresses are rejected; pass a list of addresses instead: {addr!r}"
            )
        # Reject display-name forms (e.g. 'Alice <alice@corp.local>' or '"Alice" <alice@corp.local>')
        if "<" in addr_clean or ">" in addr_clean or '"' in addr_clean:
            raise ValueError(
                f"Display-name formatted emails are rejected; pass bare email addresses: {addr!r}"
            )
        if "@" not in addr_clean:
            raise ValueError(f"Invalid email address (missing '@'): {addr!r}")

        normalized.append(addr_clean.lower())

    return normalized


def evaluate_sink_argument_rule(
    node_id: str,
    spec: NodeSpec,
    arg_name: str,
    rule: SinkArgumentRule,
    arriving_label: Label,
    effective_inbound_label: Label,
    is_pinned: bool,
    is_approved: bool,
    pinned_to_val: Any | None,
    policy: SecurityPolicy,
    path: list[str],
) -> list[RuleViolation]:
    """Evaluate IFC rules for a single sink argument.

    Shared between publish-time StaticFlowAnalyzer and runtime proxy / monitor.
    """
    violations: list[RuleViolation] = []

    # 1. Confidentiality check: Any secret-labeled argument to an EXTERNAL_SEND sink is forbidden
    if spec.side_effect == SideEffectClass.EXTERNAL_SEND:
        if arriving_label.confidentiality == Confidentiality.SECRET.value:
            violations.append(
                RuleViolation(
                    node_id=node_id,
                    target_arg=arg_name,
                    path=path,
                    reason=(
                        f"Confidentiality violation: secret-labeled data cannot be passed "
                        f"to EXTERNAL_SEND sink {node_id!r} (arg: {arg_name!r})."
                    ),
                )
            )

    # 2. Required integrity check
    if rule.required_integrity == Integrity.TRUSTED.value and not is_pinned and not is_approved:
        if arriving_label.integrity == Integrity.UNTRUSTED.value:
            violations.append(
                RuleViolation(
                    node_id=node_id,
                    target_arg=arg_name,
                    path=path,
                    reason=(
                        f"Sink node {node_id!r} requires trusted argument {arg_name!r}, "
                        f"but received untrusted data from source(s) {sorted(arriving_label.sources)}."
                    ),
                )
            )

    # 3. Conditional rule: body_internal_recipients_only
    if rule.condition == "body_internal_recipients_only":
        recipient_is_internal = False
        if pinned_to_val:
            try:
                recipients = normalize_and_validate_recipients(pinned_to_val)
                recipient_is_internal = len(recipients) > 0 and all(
                    policy.is_internal_email(r) for r in recipients
                )
            except ValueError:
                recipient_is_internal = False

        body_is_approved = is_approved

        if (
            arriving_label.integrity == Integrity.UNTRUSTED.value
            and not recipient_is_internal
            and not body_is_approved
        ):
            violations.append(
                RuleViolation(
                    node_id=node_id,
                    target_arg=arg_name,
                    path=path,
                    reason=(
                        f"Untrusted body cannot be sent to external recipient {pinned_to_val!r}. "
                        "Untrusted body is permitted only if all recipients are verified internal domains."
                    ),
                )
            )

    return violations
