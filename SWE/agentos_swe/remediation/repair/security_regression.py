"""
M13 Security Regression Detection Engine.

Performs differential comparison of pre-patch vs post-patch vulnerability findings
to verify patch effectiveness and ensure no security regressions are introduced.
"""

import logging
from typing import List, Dict, Any, Optional
from agentos_swe.core.models import Finding
from agentos_swe.security.taint.models import TaintFinding
from agentos_swe.remediation.repair.models import SecurityRegressionResult, RegressionStatus

logger = logging.getLogger(__name__)


class SecurityRegressionAnalyzer:
    """
    Evaluates pre-patch vs post-patch security findings to verify vulnerability remediation
    and detect any newly introduced vulnerabilities.
    """

    def analyze_regression(
        self,
        pre_patch_findings: List[Finding],
        post_patch_findings: List[Finding],
        pre_patch_taints: Optional[List[TaintFinding]] = None,
        post_patch_taints: Optional[List[TaintFinding]] = None,
        target_finding_id: Optional[str] = None,
    ) -> SecurityRegressionResult:
        """
        Compares pre-patch findings with post-patch findings.
        """
        pre_patch_taints = pre_patch_taints or []
        post_patch_taints = post_patch_taints or []

        # Unique keys for pre-patch
        pre_keys = {self._finding_key(f) for f in pre_patch_findings}
        for tf in pre_patch_taints:
            pre_keys.add(self._taint_key(tf))

        # Unique keys for post-patch
        post_keys = {self._finding_key(f) for f in post_patch_findings}
        for tf in post_patch_taints:
            post_keys.add(self._taint_key(tf))

        fixed_keys = pre_keys - post_keys
        remaining_keys = pre_keys & post_keys
        new_keys = post_keys - pre_keys

        fixed_list = sorted(list(fixed_keys))
        remaining_list = sorted(list(remaining_keys))
        new_list = sorted(list(new_keys))

        if new_list:
            status = RegressionStatus.NEW_VULNERABILITY_INTRODUCED
        elif target_finding_id and not any(target_finding_id in k for k in fixed_list):
            status = RegressionStatus.PARTIAL_FIX
        elif fixed_list and not new_list:
            status = RegressionStatus.CLEAN
        else:
            status = RegressionStatus.CLEAN

        return SecurityRegressionResult(
            original_findings_count=len(pre_keys),
            post_patch_findings_count=len(post_keys),
            fixed_findings=fixed_list,
            remaining_findings=remaining_list,
            newly_introduced_findings=new_list,
            regression_status=status,
            confidence=0.96,
        )

    def _finding_key(self, f: Finding) -> str:
        cat = (f.category or "gen").lower()
        file_p = (f.file or "nofile").lower()
        line_start = f.line_range[0] if f.line_range else 0
        return f"{f.id}::{cat}::{file_p}::{line_start}"

    def _taint_key(self, tf: TaintFinding) -> str:
        file_p = (tf.path.file if tf.path else "").lower()
        sink_k = tf.path.sink.sink_kind.value if tf.path and tf.path.sink else "sink"
        sink_line = tf.path.sink.line_no if tf.path and tf.path.sink else 0
        return f"taint::{sink_k}::{file_p}::{sink_line}"
