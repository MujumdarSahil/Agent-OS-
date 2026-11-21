"""Shared sink rule evaluation engine and recipient validation.

Both the publish-time StaticFlowAnalyzer and the runtime tool proxy / flow engine
call this exact evaluation code, ensuring Information Flow Control (IFC) policy
logic is never duplicated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agentos.flows.extraction import RECIPIENT_ARGS, declassification_markers, enabled_by_declassification
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


class SinkArgumentRejected(ValueError):
    """3.3: a real channel refused a send's arguments before any intent (header injection, size caps, a From
    override, an unknown or disabled channel). The message is AgentOS-written."""


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
    sink_context: dict[str, Any] | None = None,
    approval_gated: bool = False,
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
                        (
                            f"Untrusted body cannot be sent to external recipient {pinned_to_val!r}. "
                            if pinned_to_val
                            else "Untrusted body cannot be sent: the recipient is not fixed (not pinned). "
                        )
                        + "Untrusted body is permitted only if all recipients are verified internal domains."
                    ),
                )
            )

    # 3.3: send_slack. The channel must be one the admin configured (checked when the value is known: pinned at
    #      publish, always at runtime). Untrusted text only to a channel the admin marked internal.
    if rule.condition == "slack_channel_configured" and pinned_to_val is not None:
        if not (isinstance(pinned_to_val, str) and pinned_to_val in policy.slack_channels):
            violations.append(RuleViolation(
                node_id=node_id, target_arg=arg_name, path=path,
                reason=f"Slack channel {pinned_to_val!r} is not a configured Slack notification channel.",
            ))
    if rule.condition == "text_internal_channel_only":
        if (
            arriving_label.integrity == Integrity.UNTRUSTED.value
            and not is_approved
            and not policy.is_internal_slack_channel(pinned_to_val)
        ):
            violations.append(RuleViolation(
                node_id=node_id, target_arg=arg_name, path=path,
                reason=(
                    "Untrusted text can be sent only to a Slack channel the admin marked internal"
                    + (f"; {pinned_to_val!r} is not." if pinned_to_val else " (the channel is not fixed).")
                ),
            ))

    # 4. Conditional rule (http_request): untrusted or secret data only to admin-allowlisted hosts.
    #    Applies to body/headers for non-GET methods, and to the query for non-GET methods or when
    #    the query is built from flow data.
    if rule.condition == "untrusted_only_to_allowlisted_hosts":
        ctx = sink_context or {}
        method = str(ctx.get("method") or "GET").upper()
        read_only = method in ("GET", "HEAD")
        applies = (not read_only) or (arg_name == "query" and bool(ctx.get("query_from_data")))
        sensitive = (
            arriving_label.integrity == Integrity.UNTRUSTED.value
            or arriving_label.confidentiality == Confidentiality.SECRET.value
        )
        if applies and sensitive and not ctx.get("host_allowlisted"):
            host = ctx.get("host") or "an unknown host"
            violations.append(
                RuleViolation(
                    node_id=node_id,
                    target_arg=arg_name,
                    path=path,
                    reason=(
                        f"Untrusted or secret data in {arg_name!r} of a {method} request may only be sent to "
                        f"admin-allowlisted internal hosts, not {host}."
                    ),
                )
            )

    # 5. 2.5b: a DESTRUCTIVE sink must not be enabled solely by a declassified value (quarantined extraction
    #    or validator). Both constrain WHAT can come out, not WHICH allowed value: an attacker can steer the
    #    choice. ``approval_gated``: an approval upstream names this sink, so a human releases the whole call.
    if (
        spec.side_effect == SideEffectClass.DESTRUCTIVE
        and not is_pinned
        and not is_approved
        and not approval_gated
        and enabled_by_declassification(arriving_label)
        and not policy.allow_declassified_for_destructive
    ):
        violations.append(
            RuleViolation(
                node_id=node_id,
                target_arg=arg_name,
                path=path,
                reason=(
                    f"Destructive sink {node_id!r} argument {arg_name!r} comes from a declassified value "
                    f"({_marker_names(arriving_label)}); a validated or extracted value can still be chosen by "
                    "the input, so a destructive action needs an approval."
                ),
            )
        )

    # 6. 2.5b: an EXTERNAL_SEND recipient may come from a declassified value only through an `allowlist`
    #    field (validator or extraction). An enum (or any other constrained type) must never become a recipient.
    if spec.side_effect == SideEffectClass.EXTERNAL_SEND and arg_name in RECIPIENT_ARGS and not is_pinned:
        bad = [m for m in declassification_markers(arriving_label) if m[3] != "allowlist"]
        if bad:
            violations.append(
                RuleViolation(
                    node_id=node_id,
                    target_arg=arg_name,
                    path=path,
                    reason=(
                        f"Recipient {arg_name!r} of {node_id!r} comes from declassified field(s) "
                        f"{sorted(f'{k} {n}.{f} ({t})' for k, n, f, t in bad)}; only an 'allowlist' field "
                        "may choose a recipient."
                    ),
                )
            )

    return violations


def _marker_names(label: Label) -> str:
    return ", ".join(sorted(f"{k} {n}.{f}" for k, n, f, _ in declassification_markers(label)))


def evaluate_control_dependency(
    node_id: str,
    side_effect: SideEffectClass,
    control_label: Label | None,
    path: list[str],
    *,
    approval_gated: bool = False,
    policy: SecurityPolicy | None = None,
) -> list[RuleViolation]:
    """DESTRUCTIVE sinks require a TRUSTED control dependency (2.3).

    The control label is the join of every condition predicate (and failure path) that decides
    whether the node runs. EXTERNAL_SEND sinks keep their per-argument rules instead.

    2.5b: a predicate that is trusted only through a declassification (extraction or validator) does not suffice;
    the sink must be approval-gated (an approval node names it) unless the admin policy allows it.
    """
    if side_effect != SideEffectClass.DESTRUCTIVE or control_label is None:
        return []
    if control_label.integrity == Integrity.TRUSTED.value:
        if (
            enabled_by_declassification(control_label)
            and not approval_gated
            and not (policy is not None and policy.allow_declassified_for_destructive)
        ):
            return [
                RuleViolation(
                    node_id=node_id,
                    target_arg="(control)",
                    path=path,
                    reason=(
                        f"Destructive sink {node_id!r} is reached through a branch decided by a declassified "
                        f"value ({_marker_names(control_label)}); a validated or extracted value can still be "
                        "chosen by the input, so a destructive action needs an approval."
                    ),
                )
            ]
        return []
    return [
        RuleViolation(
            node_id=node_id,
            target_arg="(control)",
            path=path,
            reason=(
                f"Destructive sink {node_id!r} is reached through a branch decided by untrusted data "
                f"(control dependency from {sorted(control_label.sources)}); destructive sinks need a "
                "trusted control dependency."
            ),
        )
    ]
