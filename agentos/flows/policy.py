"""Security policy configuration for Information Flow Control (IFC).

Allowlists, approved internal domains, and declassification policies are defined
in the admin SecurityPolicy object rather than hardcoded in node specifications.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SecurityPolicy(BaseModel):
    """Admin-configured security policies governing sinks, allowlists, and domains."""

    # Default policy has internal_domains: set() (no domains trusted by default)
    internal_domains: set[str] = Field(default_factory=set)
    allowlists: dict[str, list[str]] = Field(default_factory=dict)

    def is_internal_email(self, email: str) -> bool:
        """Check whether an email address belongs to one of the configured internal domains."""
        if not email or "@" not in email:
            return False
        domain = email.split("@", 1)[1].lower().strip()
        allowed = {d.lower().lstrip("@").strip() for d in self.internal_domains}
        return domain in allowed

    # Admin allowlist for http_request: hostnames, '*.suffix' wildcards or IP/CIDR ranges.
    # Default empty: no internal host is reachable and untrusted data goes nowhere via HTTP.
    http_allowlist: list[str] = Field(default_factory=list)

    # 2.5b: may a DESTRUCTIVE sink be enabled solely by a quarantined-extraction value (as an argument or
    # as the deciding predicate) without an approval? Admin-only (config/env, never a flow). Default: no.
    allow_extraction_for_destructive: bool = False

    def is_http_allowlisted(self, url: str, ips: list[str] | None = None) -> bool:
        """True if the URL's host matches the admin http_allowlist."""
        from agentos.flows.net_guard import host_matches_allowlist, url_host

        host = url_host(url) if "://" in str(url) else str(url).strip().lower()
        return bool(host) and host_matches_allowlist(host, ips or [], self.http_allowlist)

    def is_in_allowlist(self, allowlist_name: str, value: str) -> bool:
        """Check if a value is present in an admin allowlist.

        ``http_allowlist`` matches a URL by host (so a validator can declassify data-derived URLs).
        """
        if allowlist_name == "http_allowlist":
            return isinstance(value, str) and self.is_http_allowlisted(value)
        allowed_values = self.allowlists.get(allowlist_name, [])
        return value in allowed_values
