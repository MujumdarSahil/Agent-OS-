"""Roles and capabilities for 3.4 (deny by default). Design: docs/evidence/3.4.md, "Roles and permission matrix".

Every /api route declares exactly one capability (agentos_server/permissions_table.py). A principal may use a
route only if its role grants that capability. ``public`` needs no login; ``self`` needs any logged-in user.
"""

from __future__ import annotations

from typing import Optional

ROLES = ("viewer", "approver", "builder", "admin")
CAPABILITIES = ("public", "self", "read", "approve", "build", "admin")

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "viewer": frozenset({"self", "read"}),
    "approver": frozenset({"self", "read", "approve"}),
    "builder": frozenset({"self", "read", "build"}),
    "admin": frozenset({"self", "read", "approve", "build", "admin"}),
}

ROLE_DESCRIPTIONS = {
    "viewer": "Read dashboards, flows, runs (with labelled values), metrics and alerts. No secrets, no audit export.",
    "approver": "Viewer, plus approve or reject runs waiting for approval.",
    "builder": "Viewer, plus create and edit flows, agents, squads and triggers, start runs and publish.",
    "admin": "Everything: models and keys, vault, MCP servers, notifications, alerts, budgets, policies, users, audit.",
}


def allows(role: Optional[str], capability: Optional[str]) -> bool:
    """True if a principal with ``role`` may use a route that needs ``capability`` (unknown -> False)."""
    if capability == "public":
        return True
    if role is None or capability is None:
        return False
    return capability in ROLE_CAPABILITIES.get(role, frozenset())


def capabilities_of(role: Optional[str]) -> list[str]:
    return sorted(ROLE_CAPABILITIES.get(role or "", frozenset()))
