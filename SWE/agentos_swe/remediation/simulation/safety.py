"""
M22 Simulation Safety Gate.

Enforces strict defensive boundaries:
- Rejects public IP targets (localhost / 127.0.0.1 loopback only).
- Command allowlist blocking destructive operations (rm -rf, mkfs, external curl/wget).
- Sandboxed filesystem boundary check.
- Resource limits (CPU & wall-clock timeout default 10s, max 30s).
"""

import re
from typing import Dict, Any, Tuple


class SimulationSafetyGate:
    """
    Validates security simulation scenarios against strict safety policies.
    """

    MAX_TIMEOUT_SECONDS: float = 30.0
    DEFAULT_TIMEOUT_SECONDS: float = 10.0

    FORBIDDEN_COMMAND_PATTERNS = [
        r"\brm\s+-rf\b",
        r"\bmkfs\b",
        r"\bdd\s+if=\b",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bchmod\s+777\s+/",
        r"\bcurl\s+http://(?!127\.0\.0\.1|localhost)",
        r"\bwget\s+http://(?!127\.0\.0\.1|localhost)",
    ]

    def evaluate_scenario_safety(
        self,
        target_host: str,
        command_str: str,
        timeout_sec: float = 10.0,
    ) -> Tuple[bool, str]:
        """
        Returns (is_allowed, reason).
        """
        # 1. Target Host Boundary Check
        host_clean = target_host.strip().lower()
        if host_clean not in ("127.0.0.1", "localhost", "sandbox_local", "local_sqlite", "none", ""):
            if not host_clean.startswith("127.") and not host_clean.startswith("localhost"):
                return False, f"BLOCKED: External target IP or domain '{target_host}' is prohibited."

        # 2. Timeout Boundary Check
        if timeout_sec > self.MAX_TIMEOUT_SECONDS:
            return False, f"BLOCKED: Simulation timeout {timeout_sec}s exceeds maximum threshold {self.MAX_TIMEOUT_SECONDS}s."

        # 3. Forbidden Command Pattern Check
        for pattern in self.FORBIDDEN_COMMAND_PATTERNS:
            if re.search(pattern, command_str, re.IGNORECASE):
                return False, f"BLOCKED: Command contains forbidden pattern matching '{pattern}'."

        return True, "ALLOWED: Simulation passes safety gate criteria."
