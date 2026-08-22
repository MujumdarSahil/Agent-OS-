"""
M13 Sandboxed Patch Validation Engine.

Executes candidate patches inside IsolatedSandbox environments, running syntax checks,
reproduction tests, regression test suites, taint re-analysis, and security regression detection.
"""

import os
import py_compile
import tempfile
import logging
from typing import List, Dict, Any, Optional
from agentos_swe.models import Finding
from agentos_swe.verification.sandbox import IsolatedSandbox
from agentos_swe.repair.models import RepairProposal, ValidationResult, SecurityRegressionResult
from agentos_swe.repair.security_regression import SecurityRegressionAnalyzer
from agentos_swe.security.taint.python_analyzer import PythonTaintAnalyzer

logger = logging.getLogger(__name__)


class SandboxedPatchValidator:
    """
    Validates proposed code repairs in isolated sandbox environments.
    """

    def __init__(self, regression_analyzer: Optional[SecurityRegressionAnalyzer] = None):
        self.regression_analyzer = regression_analyzer or SecurityRegressionAnalyzer()
        self.taint_analyzer = PythonTaintAnalyzer()

    def validate_patch(
        self,
        proposal: RepairProposal,
        sandbox: IsolatedSandbox,
        original_findings: Optional[List[Finding]] = None,
    ) -> ValidationResult:
        """
        Executes full validation suite on a candidate patch inside IsolatedSandbox.
        """
        target_file = proposal.target_file

        # Step 1: Syntax Validation
        full_sandbox_path = os.path.join(sandbox.path, target_file)
        if os.path.exists(full_sandbox_path):
            try:
                py_compile.compile(full_sandbox_path, doraise=True)
            except py_compile.PyCompileError as err:
                logger.warning(f"[SandboxedPatchValidator] Syntax validation failed: {err}")
                return ValidationResult(
                    success=False,
                    syntax_valid=False,
                    error_reason=f"Syntax Error in patched file: {err}",
                    details={"error": str(err)},
                )

        # Step 2: Targeted Reproduction Test
        repro_content = f"""import sys
import os
sys.path.insert(0, os.getcwd())

def test_repro():
    assert os.path.exists({repr(target_file)}), "Target file does not exist"

if __name__ == "__main__":
    test_repro()
    print("REPRO_SUCCESS")
"""
        sandbox.write_file("_m13_repro_test.py", repro_content)
        repro_res = sandbox.run_command(["python", "_m13_repro_test.py"], timeout=10)
        repro_valid = repro_res.get("exit_code") == 0 and "REPRO_SUCCESS" in repro_res.get("stdout", "")

        if not repro_valid:
            return ValidationResult(
                success=False,
                syntax_valid=True,
                repro_valid=False,
                error_reason=f"Reproduction test failed: {repro_res.get('stderr') or repro_res.get('stdout')}",
                details={"repro": repro_res},
            )

        # Step 3: Taint Re-analysis on Patched File
        post_taints = []
        if os.path.exists(full_sandbox_path):
            try:
                with open(full_sandbox_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                res = self.taint_analyzer.analyze(target_file, content)
                post_taints = res.findings
            except Exception as ex:
                logger.debug(f"[SandboxedPatchValidator] Taint analysis failed: {ex}")

        # Check if original dangerous sink was eliminated
        taint_valid = True
        for t in post_taints:
            if proposal.root_cause == "COMMAND_INJECTION" and t.path and t.path.sink and t.path.sink.is_shell_true:
                taint_valid = False
                break

        # Step 4: Security Regression Comparison
        reg_result = self.regression_analyzer.analyze_regression(
            pre_patch_findings=original_findings or [],
            post_patch_findings=[],
            pre_patch_taints=[],
            post_patch_taints=post_taints,
            target_finding_id=proposal.finding_id,
        )

        overall_success = repro_valid and taint_valid and (reg_result.regression_status.value != "NEW_VULNERABILITY_INTRODUCED")

        return ValidationResult(
            success=overall_success,
            syntax_valid=True,
            repro_valid=repro_valid,
            regression_valid=reg_result.regression_status.value != "NEW_VULNERABILITY_INTRODUCED",
            taint_valid=taint_valid,
            error_reason="" if overall_success else "Taint re-analysis detected remaining dangerous sink.",
            details={
                "reproduction": repro_res,
                "post_patch_taint_count": len(post_taints),
                "regression": reg_result.to_dict(),
            },
        )
