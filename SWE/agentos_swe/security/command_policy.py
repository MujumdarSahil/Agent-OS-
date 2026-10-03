"""
CommandPolicy - Explicit command allow/deny enforcement for M6 Production Hardening.
"""

import os
import logging
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

ALLOWED_COMMAND_BINARIES = {
    "python", "python3", "pytest", "unittest", "git", "flake8", "mypy", "black", "ruff",
}

DENIED_COMMAND_PATTERNS = [
    "powershell", "cmd.exe", "bash -i", "sh -i", "nc ", "netcat", "curl", "wget",
    "rm -rf /", "rmdir /s", "format ", "shutdown", "reboot", "eval(", "exec(",
]


class CommandPolicy:
    """
    Validates execution commands against explicit security allow/deny policies.
    """

    def __init__(
        self,
        allowed_binaries: Optional[set] = None,
        denied_patterns: Optional[List[str]] = None,
    ):
        self.allowed_binaries = allowed_binaries or ALLOWED_COMMAND_BINARIES
        self.denied_patterns = denied_patterns or DENIED_COMMAND_PATTERNS

    def validate_command(self, cmd: List[str]) -> Tuple[bool, str]:
        if not cmd:
            return False, "Empty command line."

        cmd_str = " ".join(cmd).lower()
        binary = os.path.basename(cmd[0]).lower().replace(".exe", "")

        # Check explicit deny patterns
        for pattern in self.denied_patterns:
            if pattern.lower() in cmd_str:
                msg = f"Command denied: matches forbidden security pattern '{pattern}'."
                logger.warning(f"[CommandPolicy] {msg}")
                return False, msg

        # Check explicit allow list
        if binary not in self.allowed_binaries:
            msg = f"Command denied: binary '{binary}' is not in the explicit security allow list."
            logger.warning(f"[CommandPolicy] {msg}")
            return False, msg

        return True, "Command allowed."
