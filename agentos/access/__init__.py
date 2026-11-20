"""3.4 access: user accounts, roles, sessions and API tokens (domain layer; no FastAPI or Mongo imports).

Design and permission matrix: docs/evidence/3.4.md.
"""

from agentos.access.permissions import CAPABILITIES, ROLES, allows
from agentos.access.service import LEGACY_PRINCIPAL, AccessError, AccessService, Conflict, NotFound, Principal
from agentos.access.store import AccessStore, access_store_for

__all__ = [
    "CAPABILITIES", "ROLES", "allows", "LEGACY_PRINCIPAL", "AccessError", "AccessService", "Conflict", "NotFound",
    "Principal", "AccessStore", "access_store_for",
]
