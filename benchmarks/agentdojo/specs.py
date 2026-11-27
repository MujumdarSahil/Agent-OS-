"""4.1b D4: AgentOS NodeSpecs for AgentDojo's tools (suites workspace, slack, travel, banking; benchmark v1.2.2).

Sinks get side-effect classes and sink rules; every argument listed must be trusted (pinned or from the trusted
user task), so injected instructions read from the environment cannot drive it. Every tool not listed is READ.
The reason for each choice is in docs/evidence/4.1b.md (D4).
"""

from __future__ import annotations

from typing import Any

from agentos.flows.specs import NodeSpec, SideEffectClass, SinkArgumentRule

ES, DE, WR = SideEffectClass.EXTERNAL_SEND, SideEffectClass.DESTRUCTIVE, SideEffectClass.WRITE
_INTERNAL_ONLY = SinkArgumentRule(required_integrity="untrusted", condition="body_internal_recipients_only")

# tool -> (side effect, args that must be trusted, recipient arg, extra rules)
SINKS: dict[str, tuple[SideEffectClass, tuple[str, ...], str, dict[str, SinkArgumentRule]]] = {
    # workspace / travel
    "send_email": (ES, ("recipients", "cc", "bcc"), "recipients",
                   {"subject": _INTERNAL_ONLY, "body": _INTERNAL_ONLY, "attachments": _INTERNAL_ONLY}),
    "share_file": (ES, ("email", "file_id"), "email", {}),
    "create_calendar_event": (ES, ("participants",), "participants", {}),
    "add_calendar_event_participants": (ES, ("participants", "event_id"), "participants", {}),
    "delete_email": (DE, ("email_id",), "to", {}),
    "delete_file": (DE, ("file_id",), "to", {}),
    "cancel_calendar_event": (DE, ("event_id",), "to", {}),
    "create_file": (WR, ("filename",), "to", {}),
    "append_to_file": (WR, ("file_id",), "to", {}),
    "reschedule_calendar_event": (WR, ("event_id", "new_start_time", "new_end_time"), "to", {}),
    # travel
    "reserve_hotel": (WR, ("hotel", "start_day", "end_day"), "to", {}),
    "reserve_car_rental": (WR, ("company", "start_time", "end_time"), "to", {}),
    "reserve_restaurant": (WR, ("restaurant", "start_time"), "to", {}),
    # slack
    "send_direct_message": (ES, ("recipient", "body"), "recipient", {}),
    "send_channel_message": (ES, ("channel", "body"), "channel", {}),
    "post_webpage": (ES, ("url", "content"), "url", {}),
    "get_webpage": (ES, ("url",), "url", {}),
    "invite_user_to_slack": (ES, ("user", "user_email"), "user_email", {}),
    "remove_user_from_slack": (DE, ("user",), "to", {}),
    "add_user_to_channel": (WR, ("user", "channel"), "to", {}),
    # banking
    "send_money": (ES, ("recipient", "amount"), "recipient", {}),
    "schedule_transaction": (ES, ("recipient", "amount"), "recipient", {}),
    "update_scheduled_transaction": (ES, ("id", "recipient", "amount"), "recipient", {}),
    "update_password": (DE, ("password",), "to", {}),
    "update_user_info": (WR, ("first_name", "last_name", "street", "city"), "to", {}),
}


def node_spec(name: str, input_schema: dict[str, Any]) -> NodeSpec:
    if name not in SINKS:
        return NodeSpec(type=name, input_schema=input_schema, side_effect=SideEffectClass.READ)
    effect, trusted, recipient, extra = SINKS[name]
    rules = {a: SinkArgumentRule(required_integrity="trusted") for a in trusted}
    rules.update(extra)
    return NodeSpec(type=name, input_schema=input_schema, side_effect=effect, sink_rules=rules,
                    recipient_arg=recipient)
