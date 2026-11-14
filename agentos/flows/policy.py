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

    def is_in_allowlist(self, allowlist_name: str, value: str) -> bool:
        """Check if a value is present in an admin allowlist."""
        allowed_values = self.allowlists.get(allowlist_name, [])
        return value in allowed_values
