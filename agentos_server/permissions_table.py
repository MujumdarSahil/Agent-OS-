"""3.4: the capability every /api route needs (deny by default). Design: docs/evidence/3.4.md.

Key: (METHOD, route template) exactly as the route table prints it (``WS`` for WebSocket routes). A route that is
not listed here is refused (403) for every caller, admins included; agentos_server/tests/test_access_api_3_4.py
fails if any route of the app is missing. Capabilities: public, self, read, approve, build, admin
(agentos/access/permissions.py says which role has which).
"""

from __future__ import annotations

from typing import Optional

_V1 = "/api"
_V2 = "/api/v2"

PERMISSIONS: dict[tuple[str, str], str] = {
    # ------------------------------------------------------------------ v1 (/api)
    ("GET", f"{_V1}/health"): "public",
    ("GET", f"{_V1}/agent-types"): "read",
    ("GET", f"{_V1}/agents"): "read",
    ("POST", f"{_V1}/agents"): "build",
    ("GET", f"{_V1}/agents/{{name}}"): "read",
    ("PUT", f"{_V1}/agents/{{name}}"): "build",
    ("DELETE", f"{_V1}/agents/{{name}}"): "build",
    ("POST", f"{_V1}/builder/agent"): "build",
    ("POST", f"{_V1}/builder/agent/confirm"): "build",
    ("POST", f"{_V1}/builder/crew"): "build",
    ("POST", f"{_V1}/builder/crew/confirm"): "build",
    ("POST", f"{_V1}/builder/tool"): "build",
    ("POST", f"{_V1}/builder/tool/confirm"): "build",
    ("GET", f"{_V1}/checkpoints"): "read",
    ("GET", f"{_V1}/checkpoints/{{mission_name}}"): "read",
    ("GET", f"{_V1}/crews"): "read",
    ("POST", f"{_V1}/crews"): "build",
    ("GET", f"{_V1}/crews/{{name}}"): "read",
    ("GET", f"{_V1}/federation/missions"): "read",
    ("POST", f"{_V1}/federation/missions"): "build",
    ("POST", f"{_V1}/federation/missions/{{name}}/run"): "build",
    ("GET", f"{_V1}/federation/runs/{{run_id}}/status"): "read",
    ("GET", f"{_V1}/governance/policies"): "read",
    ("POST", f"{_V1}/governance/policies"): "admin",
    ("DELETE", f"{_V1}/governance/policies/{{policy_id}}"): "admin",
    ("GET", f"{_V1}/mcp-plugins"): "read",
    ("POST", f"{_V1}/mcp-plugins"): "admin",
    ("GET", f"{_V1}/missions"): "read",
    ("POST", f"{_V1}/missions"): "build",
    ("GET", f"{_V1}/missions/{{name}}"): "read",
    ("POST", f"{_V1}/missions/{{name}}/run"): "build",
    ("POST", f"{_V1}/packaging/build"): "build",
    ("POST", f"{_V1}/packaging/verify"): "build",
    ("POST", f"{_V1}/packaging/sign"): "admin",
    ("POST", f"{_V1}/packaging/install"): "admin",
    ("GET", f"{_V1}/providers"): "read",
    ("GET", f"{_V1}/providers/fallback-chain"): "read",
    ("POST", f"{_V1}/providers/keys"): "admin",
    ("DELETE", f"{_V1}/providers/keys/{{provider_name}}"): "admin",
    ("POST", f"{_V1}/providers/test/{{provider_name}}"): "admin",
    ("GET", f"{_V1}/runs/{{run_id}}/status"): "read",
    ("WS", f"{_V1}/runs/{{run_id}}/stream"): "read",
    ("GET", f"{_V1}/templates"): "read",
    ("POST", f"{_V1}/templates/{{name}}/install"): "build",
    ("GET", f"{_V1}/tool-types"): "read",
    ("GET", f"{_V1}/tools"): "read",
    ("POST", f"{_V1}/tools"): "build",
    # ------------------------------------------------------------------ v2 core resources
    ("GET", f"{_V2}/agents"): "read",
    ("POST", f"{_V2}/agents"): "build",
    ("GET", f"{_V2}/agents/tool-options"): "read",
    ("GET", f"{_V2}/agents/{{name}}"): "read",
    ("DELETE", f"{_V2}/agents/{{name}}"): "build",
    ("GET", f"{_V2}/squads"): "read",
    ("POST", f"{_V2}/squads"): "build",
    ("GET", f"{_V2}/squads/{{name}}"): "read",
    ("DELETE", f"{_V2}/squads/{{name}}"): "build",
    ("GET", f"{_V2}/tools"): "read",
    ("POST", f"{_V2}/tools"): "build",
    ("GET", f"{_V2}/tools/{{name}}"): "read",
    ("DELETE", f"{_V2}/tools/{{name}}"): "build",
    ("GET", f"{_V2}/node-specs"): "read",
    ("GET", f"{_V2}/overview"): "read",
    # flows, versions, runs, approvals
    ("GET", f"{_V2}/flows"): "read",
    ("POST", f"{_V2}/flows"): "build",
    ("GET", f"{_V2}/flows/{{flow_id}}"): "read",
    ("PUT", f"{_V2}/flows/{{flow_id}}"): "build",
    ("DELETE", f"{_V2}/flows/{{flow_id}}"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/archive"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/publish"): "build",
    ("GET", f"{_V2}/flows/{{flow_id}}/versions"): "read",
    ("GET", f"{_V2}/flows/{{flow_id}}/versions/{{version}}"): "read",
    ("GET", f"{_V2}/flows/{{flow_id}}/runs"): "read",
    ("POST", f"{_V2}/flows/{{flow_id}}/runs"): "build",
    ("GET", f"{_V2}/flows/{{flow_id}}/runs/{{run_id}}"): "read",
    ("POST", f"{_V2}/flows/{{flow_id}}/runs/{{run_id}}/approve"): "approve",
    ("GET", f"{_V2}/flows/{{flow_id}}/runs/{{run_id}}/events"): "read",
    ("WS", f"{_V2}/flows/{{flow_id}}/runs/{{run_id}}/events"): "read",
    ("GET", f"{_V2}/flows/{{flow_id}}/runs/{{run_id}}/usage"): "read",
    # 4.0 natural-language builder: drafts only (never saved or published here); model calls cost money
    ("POST", f"{_V2}/flows/generate"): "build",
    ("POST", f"{_V2}/flows/check"): "build",
    # 4.1 "Attack my flow": isolated copy, adversarial MOCK model, fake sinks; nothing saved or sent
    ("POST", f"{_V2}/flows/{{flow_id}}/attack-test"): "build",
    # 4.2 flow test cases: viewers read cases/results; builders create, edit, run, compare and set the gate. The
    # admin-only options (live tools, include secret values) are checked in the handlers and audited.
    ("GET", f"{_V2}/flows/{{flow_id}}/tests"): "read",
    ("POST", f"{_V2}/flows/{{flow_id}}/tests"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/tests/from-run"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/tests/from-review"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/tests/security"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/tests/run"): "build",
    ("POST", f"{_V2}/flows/{{flow_id}}/tests/compare"): "build",
    ("GET", f"{_V2}/flows/{{flow_id}}/tests/runs"): "read",
    ("GET", f"{_V2}/flows/{{flow_id}}/tests/runs/{{suite_run_id}}"): "read",
    ("GET", f"{_V2}/flows/{{flow_id}}/tests/settings"): "read",
    ("PUT", f"{_V2}/flows/{{flow_id}}/tests/settings"): "build",
    ("GET", f"{_V2}/flows/{{flow_id}}/tests/{{case_id}}"): "read",
    ("PUT", f"{_V2}/flows/{{flow_id}}/tests/{{case_id}}"): "build",
    ("DELETE", f"{_V2}/flows/{{flow_id}}/tests/{{case_id}}"): "build",
    ("GET", f"{_V2}/flow-tests/summary"): "read",
    # triggers
    ("GET", f"{_V2}/schedules"): "read",
    ("POST", f"{_V2}/schedules"): "build",
    ("GET", f"{_V2}/schedules/{{schedule_id}}"): "read",
    ("PUT", f"{_V2}/schedules/{{schedule_id}}"): "build",
    ("DELETE", f"{_V2}/schedules/{{schedule_id}}"): "build",
    ("GET", f"{_V2}/webhooks"): "read",
    ("POST", f"{_V2}/webhooks"): "build",
    ("GET", f"{_V2}/webhooks/{{webhook_id}}"): "read",
    ("PUT", f"{_V2}/webhooks/{{webhook_id}}"): "build",
    ("DELETE", f"{_V2}/webhooks/{{webhook_id}}"): "build",
    ("POST", f"{_V2}/webhooks/{{webhook_id}}/rotate"): "build",
    # usage, alerts
    ("GET", f"{_V2}/usage"): "read",
    ("GET", f"{_V2}/budgets"): "read",
    ("PUT", f"{_V2}/budgets"): "admin",
    ("GET", f"{_V2}/alerts"): "read",
    ("GET", f"{_V2}/alerts/rules"): "read",
    ("PUT", f"{_V2}/alerts/rules/{{rule_id}}"): "admin",
    ("POST", f"{_V2}/alerts/{{alert_id}}/acknowledge"): "approve",
    # models and keys
    ("GET", f"{_V2}/providers"): "read",
    ("GET", f"{_V2}/providers/fallback"): "read",
    ("PUT", f"{_V2}/providers/fallback"): "admin",
    ("POST", f"{_V2}/providers/test-connection"): "admin",
    ("PUT", f"{_V2}/providers/{{name}}/billing-plan"): "admin",
    ("GET", f"{_V2}/vault/keys"): "admin",
    ("POST", f"{_V2}/vault/keys"): "admin",
    ("DELETE", f"{_V2}/vault/keys/{{name}}"): "admin",
    # MCP servers and tool review (GET shows commands and env names: admin)
    ("GET", f"{_V2}/mcp-servers"): "admin",
    ("POST", f"{_V2}/mcp-servers"): "admin",
    ("GET", f"{_V2}/mcp-servers/{{name}}"): "admin",
    ("DELETE", f"{_V2}/mcp-servers/{{name}}"): "admin",
    ("POST", f"{_V2}/mcp-servers/{{name}}/discover"): "admin",
    ("POST", f"{_V2}/mcp-servers/{{name}}/enable"): "admin",
    ("GET", f"{_V2}/mcp-servers/{{name}}/launch-preview"): "admin",
    ("POST", f"{_V2}/mcp-servers/{{name}}/tools/{{tool}}/approve"): "admin",
    ("POST", f"{_V2}/mcp-servers/{{name}}/tools/{{tool}}/revoke"): "admin",
    # notification channels
    ("GET", f"{_V2}/notify/channels"): "admin",
    ("POST", f"{_V2}/notify/channels"): "admin",
    ("PUT", f"{_V2}/notify/channels/{{name}}"): "admin",
    ("DELETE", f"{_V2}/notify/channels/{{name}}"): "admin",
    ("POST", f"{_V2}/notify/channels/{{name}}/test"): "admin",
    # audit log
    ("GET", f"{_V2}/audit"): "admin",
    ("GET", f"{_V2}/audit/verify"): "admin",
    ("GET", f"{_V2}/audit/export"): "admin",
    # ------------------------------------------------------------------ 3.4 access
    ("GET", f"{_V2}/auth/status"): "public",
    ("POST", f"{_V2}/auth/setup"): "public",   # only while no user exists, and only with the local API token
    ("POST", f"{_V2}/auth/login"): "public",
    ("POST", f"{_V2}/auth/logout"): "self",
    ("GET", f"{_V2}/auth/me"): "self",
    ("POST", f"{_V2}/auth/password"): "self",
    ("GET", f"{_V2}/auth/tokens"): "self",
    ("POST", f"{_V2}/auth/tokens"): "self",
    ("DELETE", f"{_V2}/auth/tokens/{{token_id}}"): "self",
    ("GET", f"{_V2}/users"): "admin",
    ("POST", f"{_V2}/users"): "admin",
    ("PUT", f"{_V2}/users/{{user_id}}"): "admin",
    ("POST", f"{_V2}/users/{{user_id}}/password"): "admin",
    ("GET", f"{_V2}/users/{{user_id}}/tokens"): "admin",
    ("DELETE", f"{_V2}/users/{{user_id}}/tokens/{{token_id}}"): "admin",
    ("GET", f"{_V2}/access/legacy-token"): "admin",
    ("PUT", f"{_V2}/access/legacy-token"): "admin",
    ("POST", f"{_V2}/access/legacy-token/rotate"): "admin",
    # ------------------------------------------------------------------ 3.5 sandbox (settings changes are audited)
    ("GET", f"{_V2}/sandbox/status"): "read",
    ("GET", f"{_V2}/sandbox/settings"): "admin",
    ("PUT", f"{_V2}/sandbox/settings"): "admin",
    ("POST", f"{_V2}/sandbox/test"): "admin",
    ("POST", f"{_V2}/sandbox/wasm/install"): "admin",
    # ------------------------------------------------------------------ 3.6a review queue
    ("GET", f"{_V2}/review/items"): "read",
    ("GET", f"{_V2}/review/items/{{item_id}}"): "read",
    ("POST", f"{_V2}/review/items/{{item_id}}/verdict"): "review",
    ("POST", f"{_V2}/review/items/{{item_id}}/skip"): "review",
    ("GET", f"{_V2}/review/sampling/{{flow_id}}"): "read",
    ("PUT", f"{_V2}/review/sampling/{{flow_id}}"): "build",
    ("POST", f"{_V2}/review/send-to-review"): "build",
    ("GET", f"{_V2}/review/metrics/{{flow_id}}"): "read",
    ("GET", f"{_V2}/review/export"): "admin",
}


def permission_for(method: str, template: Optional[str]) -> Optional[str]:
    """The capability for this route, or None (= not declared: refused for everyone)."""
    if template is None:
        return None
    m = "GET" if method == "HEAD" else method
    return PERMISSIONS.get((m, template))
