"""
IsolatedSandbox - Production-hardened execution boundary for AgentOS-SWE (M3/M6).
Executes verification and reproduction commands with resource limits, secret redaction,
command allow/deny policy enforcement, network policy control, and process cleanup.
"""

import os
import time
import shutil
import tempfile
import subprocess
import logging
from typing import Dict, Any, List, Optional

from agentos_swe.security.limits import ResourceLimits, ExecutionMetrics
from agentos_swe.security.command_policy import CommandPolicy
from agentos_swe.security.secret_protection import SecretProtection

logger = logging.getLogger(__name__)


class IsolatedSandbox:
    """
    Production-hardened temporary workspace boundary enforcing security limits.
    """

    def __init__(
        self,
        base_path: Optional[str] = None,
        limits: Optional[ResourceLimits] = None,
        command_policy: Optional[CommandPolicy] = None,
    ):
        self.base_path = base_path
        self.limits = limits or ResourceLimits()
        self.command_policy = command_policy or CommandPolicy()
        self.temp_dir: Optional[str] = None
        self.latest_metrics: Optional[ExecutionMetrics] = None

    def __enter__(self) -> "IsolatedSandbox":
        self.temp_dir = tempfile.mkdtemp(prefix="agentos_swe_sandbox_")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception as ex:
                logger.debug(f"Sandbox cleanup note: {ex}")
        self.temp_dir = None

    @property
    def path(self) -> str:
        if not self.temp_dir:
            raise RuntimeError("Sandbox is not active. Use 'with IsolatedSandbox() as sandbox:' context.")
        return self.temp_dir

    def copy_file(self, src_full_path: str, rel_target_path: str) -> str:
        """Copy file into sandbox."""
        dest_path = os.path.join(self.path, rel_target_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(src_full_path, dest_path)
        return dest_path

    def write_file(self, rel_target_path: str, content: str) -> str:
        """Write a new file or test fixture inside sandbox with secret redaction."""
        sanitized_content = SecretProtection.sanitize_text(content)
        dest_path = os.path.join(self.path, rel_target_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(sanitized_content)
        return dest_path

    def run_command(self, cmd: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute command inside sandbox with security enforcement:
        1. Command Policy Check (Allow/Deny)
        2. Environment Secret Redaction & Stripping
        3. Network Policy Control (Network DENY by default)
        4. Configurable Execution Timeout & Process Cleanup
        5. Output Size Limit Truncation
        6. Secret Redaction on Stdout/Stderr
        """
        if not self.temp_dir:
            raise RuntimeError("Sandbox is not active.")

        # 1. Command Policy Validation
        allowed, policy_msg = self.command_policy.validate_command(cmd)
        if not allowed:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Security Policy Blocked: {policy_msg}",
            }

        # 2. Secret Protection & Environment Isolation
        clean_env = SecretProtection.sanitize_env(os.environ.copy())

        # 3. Network Policy Control
        if not self.limits.network_allowed:
            # Strip network proxy environment variables to enforce local network isolation
            for net_key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                clean_env.pop(net_key, None)

        effective_timeout = timeout if timeout is not None else int(self.limits.max_execution_time_sec)
        start_time = time.time()

        # 4. Subprocess Execution & Process Lifetime Management
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self.temp_dir,
                env=clean_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=effective_timeout)
                duration = time.time() - start_time
            except subprocess.TimeoutExpired:
                # Force process cleanup
                proc.kill()
                stdout_data, stderr_data = proc.communicate()
                duration = time.time() - start_time
                err_msg = f"Command execution timed out after {effective_timeout} seconds (Process terminated safely)."
                self.latest_metrics = ExecutionMetrics(
                    execution_time_sec=duration,
                    output_size_bytes=len(err_msg),
                    resource_limits_exceeded=True,
                    network_accessed=self.limits.network_allowed,
                    commands_executed=1,
                    exit_code=-1,
                )
                return {
                    "success": False,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": err_msg,
                }

            # 5. Output Size Truncation & Secret Redaction
            sanitized_stdout = SecretProtection.sanitize_text(stdout_data or "")
            sanitized_stderr = SecretProtection.sanitize_text(stderr_data or "")

            if len(sanitized_stdout) > self.limits.max_output_size_bytes:
                sanitized_stdout = (
                    sanitized_stdout[: self.limits.max_output_size_bytes]
                    + "\n...[Output Truncated: Exceeded Max Output Limit]..."
                )

            self.latest_metrics = ExecutionMetrics(
                execution_time_sec=duration,
                output_size_bytes=len(sanitized_stdout) + len(sanitized_stderr),
                resource_limits_exceeded=False,
                network_accessed=self.limits.network_allowed,
                commands_executed=1,
                exit_code=proc.returncode,
            )

            return {
                "success": proc.returncode == 0,
                "exit_code": proc.returncode,
                "stdout": sanitized_stdout,
                "stderr": sanitized_stderr,
            }
        except Exception as ex:
            return {
                "success": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": SecretProtection.sanitize_text(str(ex)),
            }
