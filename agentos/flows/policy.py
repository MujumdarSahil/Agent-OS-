"""Security policy configuration for Information Flow Control (IFC).

Allowlists, approved internal domains, and declassification policies are defined
in the admin SecurityPolicy object rather than hardcoded in node specifications.
"""

from __future__ import annotations

from pydantic import AliasChoices, BaseModel, Field


class SecurityPolicy(BaseModel):
    """Admin-configured security policies governing sinks, allowlists, and domains."""

    # Default policy has internal_domains: set() (no domains trusted by default)
    internal_domains: set[str] = Field(default_factory=set)
    allowlists: dict[str, list[str]] = Field(default_factory=dict)

    def is_internal_email(self, email: str) -> bool:
        """Check whether an email address belongs to one of the configured internal domains."""
        # 4.1b: exact match after NFKC/IDN normalisation; never an address with look-alike characters
        from agentos.flows.destinations import email_domain_internal

        return email_domain_internal(email, self.internal_domains)

    # 3.3: admin-configured Slack notification channels {name: internal}. send_slack may only target these;
    # untrusted text only goes to a channel the admin marked internal. Synced by the server from the channel store.
    slack_channels: dict[str, bool] = Field(default_factory=dict)

    def is_internal_slack_channel(self, name: object) -> bool:
        from agentos.flows.destinations import is_confusable

        return isinstance(name, str) and self.slack_channels.get(name) is True and not is_confusable(name, "channel")

    # Admin allowlist for http_request: hostnames, '*.suffix' wildcards or IP/CIDR ranges.
    # Default empty: no internal host is reachable and untrusted data goes nowhere via HTTP.
    http_allowlist: list[str] = Field(default_factory=list)

    # 2.5b: may a DESTRUCTIVE sink be enabled solely by a declassified value (quarantined extraction or
    # validator), as an argument or as the deciding predicate, without an approval? Admin-only (config/env,
    # never a flow). Default: no. The 2.5b name ``allow_extraction_for_destructive`` is still accepted.
    allow_declassified_for_destructive: bool = Field(
        default=False,
        validation_alias=AliasChoices("allow_declassified_for_destructive", "allow_extraction_for_destructive"),
    )

    @property
    def allow_extraction_for_destructive(self) -> bool:
        """Deprecated name (2.5b draft) of ``allow_declassified_for_destructive``."""
        return self.allow_declassified_for_destructive

    def is_http_allowlisted(self, url: str, ips: list[str] | None = None) -> bool:
        """True if the URL's host matches the admin http_allowlist."""
        from agentos.flows.net_guard import host_matches_allowlist, url_host

        host = url_host(url) if "://" in str(url) else str(url).strip().lower()
        return bool(host) and host_matches_allowlist(host, ips or [], self.http_allowlist)

    def is_in_allowlist(self, allowlist_name: str, value: str) -> bool:
        """Check if a value is present in an admin allowlist.

        ``http_allowlist`` matches a URL by host. A validator can NOT use it (2.5b: host match is not an exact,
        canonical entry, so it cannot declassify); validators need a named allowlist of exact values.
        """
        if allowlist_name == "http_allowlist":
            return isinstance(value, str) and self.is_http_allowlisted(value)
        from agentos.flows.destinations import is_confusable

        allowed_values = self.allowlists.get(allowlist_name, [])
        # 4.1b: exact raw entry only, and never a value with look-alike characters
        return value in allowed_values and not (isinstance(value, str) and is_confusable(value, "channel"))
