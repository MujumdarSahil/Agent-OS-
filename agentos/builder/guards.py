"""Builder guards (4.0 D6, D7): no invented recipients or targets, no secrets.

- ``looks_like_secret``: the audit-chain credential patterns (3.1), the router's key-like pattern (2.4c/3.4) and the
  3.4 API token prefix. Used on the user's input (refused before any model call) and on the model's output.
- ``invented_targets``: every email address, URL/host, Slack channel and allowlist name in a draft must appear
  verbatim in what the user wrote (or in the flow being edited), or be an admin-configured name. Otherwise it is
  reported, and the service turns it into a question instead of guessing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from agentos.access.service import TOKEN_PREFIX
from agentos.audit.chain import _SECRET_PATTERNS
from agentos.flows.policy import SecurityPolicy
from agentos.llm.router_llm import _KEYLIKE

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)


def looks_like_secret(text: str) -> bool:
    if not text:
        return False
    if TOKEN_PREFIX in text:
        return True
    if any(p.search(text) for p in _SECRET_PATTERNS):
        return True
    return bool(_KEYLIKE.search(text))


def emails_in(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(0).rstrip(".").lower() for m in EMAIL_RE.finditer(text or "")))


def urls_in(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(0).rstrip(".,;:") for m in URL_RE.finditer(text or "")))


@dataclass(frozen=True)
class Invented:
    node_id: str
    kind: str        # "email" | "url" | "slack_channel" | "allowlist"
    where: str       # "pinned_args.to", "config.url", ...
    node_type: str

    def question(self, policy: SecurityPolicy) -> str:
        if self.kind == "email":
            what = "email" if self.node_type == "send_email" else "message"
            return f"Who should receive the {what} sent by step '{self.node_id}'? Give the exact email address."
        if self.kind == "url":
            return f"Which exact URL should step '{self.node_id}' call?"
        if self.kind == "slack_channel":
            names = ", ".join(sorted(policy.slack_channels)) or "none configured yet (an admin adds them)"
            return f"Which Slack channel should step '{self.node_id}' post to? Configured channels: {names}."
        names = ", ".join(sorted(policy.allowlists)) or "none configured yet (an admin adds them)"
        return f"Which allowlist should step '{self.node_id}' use? Existing allowlists: {names}."


def _strings(value: Any, where: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{where}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{where}[{i}]")


def _url_ok(url: str, source: str, policy: SecurityPolicy) -> bool:
    if url.lower() in source:
        return True
    try:
        return policy.is_http_allowlisted(url)
    except Exception:
        return False


def invented_targets(flow: dict[str, Any], source_text: str, policy: SecurityPolicy) -> list[Invented]:
    """Targets in the draft that the user did not state and that are not admin-configured names.

    ``source_text``: the description, answers and change request, plus (edit mode) the JSON of the flow being
    edited, whose values the author already chose.
    """
    src = (source_text or "").lower()
    found: list[Invented] = []
    seen: set[tuple[str, str, str]] = set()

    def add(nid: str, kind: str, where: str, ntype: str) -> None:
        key = (nid, kind, where)
        if key not in seen:
            seen.add(key)
            found.append(Invented(nid, kind, where, ntype))

    for nid, node in (flow.get("nodes") or {}).items():
        ntype = node.get("type", "")
        for part in ("config", "pinned_args"):
            for where, text in _strings(node.get(part) or {}, part):
                for email in emails_in(text):
                    if email not in src:
                        add(nid, "email", where, ntype)
                for url in urls_in(text):
                    if not _url_ok(url, src, policy):
                        add(nid, "url", where, ntype)
        cfg, pinned = node.get("config") or {}, node.get("pinned_args") or {}
        if ntype == "http_request":
            for where, val in (("pinned_args.url", pinned.get("url")), ("config.url", cfg.get("url"))):
                if isinstance(val, str) and val.strip() and "{{" not in val and not urls_in(val):
                    add(nid, "url", where, ntype)  # a bare host or relative path the user never gave
        channel_keys = [("pinned_args.channel", pinned.get("channel"))] if ntype == "send_slack" else []
        channel_keys += [(f"pinned_args.{k}", v) for k, v in pinned.items() if k.endswith("send_slack.channel")]
        for where, ch in channel_keys:
            # stated by the user but not configured: not a guess; the static check reports it
            if isinstance(ch, str) and ch not in policy.slack_channels and ch.lower().lstrip("#") not in src:
                add(nid, "slack_channel", where, ntype)
        names: list[tuple[str, Any]] = []
        if ntype == "validator":
            names.append(("config.allowlist_name", cfg.get("allowlist_name")))
        if ntype == "quarantined_extraction":
            for i, f in enumerate(cfg.get("fields") or []):
                if isinstance(f, dict):
                    names.append((f"config.fields[{i}].allowlist_name", f.get("allowlist_name")))
        for where, name in names:
            if isinstance(name, str) and name not in policy.allowlists:
                add(nid, "allowlist", where, ntype)
    return found


def flow_text(flow: dict[str, Any] | None) -> str:
    return json.dumps(flow or {}, sort_keys=True, default=str)
