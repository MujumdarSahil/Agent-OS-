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
    return list(dict.fromkeys(m.group(0).rstrip(".,;:!?") for m in URL_RE.finditer(text or "")))


# A bare host name the user wrote ("api.example.com"): labels joined by dots, alphabetic TLD. Lookarounds keep it from
# starting or ending inside a longer token, so "api.example.com.evil.net" is one host, never "api.example.com".
HOST_RE = re.compile(r"(?<![A-Za-z0-9@._-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})"
                     r"(?![A-Za-z0-9_-])")
WORD_RE = re.compile(r"#?([A-Za-z0-9][A-Za-z0-9_.-]*)")
_DEFAULT_PORTS = {"http": 80, "https": 443}

CanonicalUrl = tuple[str, str, "int | None", str]


def canonical_url(url: str) -> CanonicalUrl | None:
    """(scheme, host, port, path): scheme and host lower-cased, a default port dropped, an empty path is "/".
    None for anything that is not a plain http(s) URL (no host, bad port, or user info such as user:pass@host)."""
    from urllib.parse import urlsplit

    try:
        p = urlsplit(url.strip().rstrip(".,;:!?"))
        port = p.port
    except ValueError:
        return None
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower().rstrip(".")
    if scheme not in _DEFAULT_PORTS or not host or p.username is not None or p.password is not None:
        return None
    if port == _DEFAULT_PORTS[scheme]:
        port = None
    return (scheme, host, port, p.path or "/")


@dataclass(frozen=True)
class StatedTargets:
    """The exact emails, URLs, bare hosts and words the user wrote. Membership is EXACT (never a substring): emails
    compared lower-cased; URLs by (scheme, host, port, path) with host lower-cased and default ports stripped; a bare
    host matches a URL only when the URL has exactly that host."""

    emails: frozenset[str]
    urls: frozenset[CanonicalUrl]
    hosts: frozenset[str]
    words: frozenset[str]

    @classmethod
    def from_text(cls, text: str) -> "StatedTargets":
        text = text or ""
        emails = frozenset(emails_in(text))
        urls = frozenset(c for c in (canonical_url(u) for u in urls_in(text)) if c is not None)
        rest = URL_RE.sub(" ", EMAIL_RE.sub(" ", text))  # a host inside an email or URL is not a stated bare host
        hosts = frozenset(m.group(1).lower() for m in HOST_RE.finditer(rest))
        words = frozenset(w.lower().rstrip(".") for w in WORD_RE.findall(text))
        return cls(emails, urls, hosts, words)

    def has_email(self, email: str) -> bool:
        return email.strip().lower() in self.emails

    def has_url(self, url: str) -> bool:
        c = canonical_url(url)
        return c is not None and (c in self.urls or c[1] in self.hosts)

    def has_word(self, word: str) -> bool:
        return word.strip().lower().lstrip("#") in self.words


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


def _url_ok(url: str, stated: StatedTargets, policy: SecurityPolicy) -> bool:
    if stated.has_url(url):
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
    stated = StatedTargets.from_text(source_text)
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
                    if not stated.has_email(email):
                        add(nid, "email", where, ntype)
                for url in urls_in(text):
                    if not _url_ok(url, stated, policy):
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
            if isinstance(ch, str) and ch not in policy.slack_channels and not stated.has_word(ch):
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
