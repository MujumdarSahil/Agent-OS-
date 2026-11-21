"""Sandbox for code tools (3.5). Design: docs/evidence/3.5.md.

One interface, ``SandboxService.run(kind, payload, files_in, limits) -> SandboxResult``, with a Docker backend
(strongest; required for shell) and a wasm backend (Python only, works without Docker). With no backend the code
tools fail closed; code is never run as a plain subprocess on the host.
"""

from agentos.sandbox.models import (
    DEFAULT_IMAGE,
    SandboxError,
    SandboxLimits,
    SandboxResult,
    SandboxSettings,
    SandboxUnavailable,
)
from agentos.sandbox.service import SANDBOX_TOOLS, TOOL_KIND, SandboxService

__all__ = ["DEFAULT_IMAGE", "SANDBOX_TOOLS", "TOOL_KIND", "SandboxError", "SandboxLimits", "SandboxResult",
           "SandboxService", "SandboxSettings", "SandboxUnavailable"]
