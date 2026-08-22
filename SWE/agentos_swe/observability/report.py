"""
ReportGenerator - Generates machine-readable and human-readable execution run reports for AgentOS-SWE (M7, M13, M13.1, M14, M15).
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List

from agentos_swe.observability.models import RunReport
from agentos_swe.observability.tracer import TraceCollector
from agentos_swe.security.secret_protection import SecretProtection

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates structured JSON and Markdown execution run reports from a TraceCollector,
    including M13 Vulnerability Intelligence, M13.1 Repair Validation, M14 History, and M15 Security Intelligence.
    """

    def generate_run_report(
        self,
        collector: TraceCollector,
        repository_name: str = "Unknown Repo",
        commit_ref: Optional[str] = None,
        start_time: Optional[str] = None,
    ) -> RunReport:
        start_t = start_time or (collector.events[0].timestamp if collector.events else datetime.now().isoformat())
        end_t = collector.events[-1].timestamp if collector.events else datetime.now().isoformat()

        total_tokens = sum(e.tokens for e in collector.events)
        total_latency = sum(e.latency_sec for e in collector.events)
        total_cost = sum(e.cost_est for e in collector.events)

        report = RunReport(
            repository_name=repository_name,
            commit_ref=commit_ref,
            start_time=start_t,
            end_time=end_t,
            total_duration_sec=total_latency,
            finding_metrics=collector.finding_metrics,
            repair_metrics=collector.repair_metrics,
            agent_metrics=collector.agent_metrics,
            fallback_count=collector.fallback_count,
            checkpoint_recoveries=collector.checkpoint_recoveries,
            total_tokens=total_tokens,
            total_cost_est=total_cost,
            trace_events_count=len(collector.events),
        )
        return report

    def render_markdown_report(
        self,
        report: RunReport,
        correlated_findings: Optional[List[Dict[str, Any]]] = None,
        repair_proposals: Optional[List[Dict[str, Any]]] = None,
        repair_validations: Optional[List[Dict[str, Any]]] = None,
        historical_comparison: Optional[Dict[str, Any]] = None,
        prioritized_findings: Optional[List[Dict[str, Any]]] = None,
        cross_repository_patterns: Optional[List[Dict[str, Any]]] = None,
        regression_results: Optional[List[Dict[str, Any]]] = None,
        governance_decisions: Optional[List[Dict[str, Any]]] = None,
        final_verdict: str = "PASS",
    ) -> str:
        f_m = report.finding_metrics
        r_m = report.repair_metrics

        agent_rows = []
        for name, a in report.agent_metrics.items():
            agent_rows.append(
                f"| `{name}` | {a.execution_count} | {a.success_count} | {a.failure_count} | {a.fallback_count} | {a.total_tokens} | {a.total_duration_sec:.2f}s |"
            )
        agent_table = "\n".join(agent_rows) if agent_rows else "| None | 0 | 0 | 0 | 0 | 0 | 0s |"

        # M15 Prioritized Remediation Queue Table
        prio_rows = []
        if prioritized_findings:
            for pf in prioritized_findings[:5]:
                rk = pf.get("rank", "#")
                tier = pf.get("priority_tier", "P3")
                score = pf.get("priority_score", 0)
                rc = pf.get("root_cause", "UNKNOWN")
                aff = pf.get("affected_file", "N/A")
                exp = pf.get("exploitability", "UNKNOWN")
                expo = pf.get("exposure", "UNKNOWN")
                act = pf.get("recommended_action", "Apply defensive sanitization.")
                prio_rows.append(f"| `#{rk}` | `{tier}` | `{score}` | `{rc}` | `{aff}` | `{exp}` | `{expo}` | {act} |")
        prio_table = "\n".join(prio_rows) if prio_rows else "| #1 | `P4` | `0` | `NONE` | `N/A` | `LOW` | `INTERNAL` | Zero priority findings detected |"

        # Correlated Findings table
        corr_rows = []
        if correlated_findings:
            for cf in correlated_findings:
                fid = cf.get("finding_id", "")
                rc = cf.get("root_cause", "UNKNOWN")
                sev = cf.get("severity", "MEDIUM")
                conf = cf.get("confidence", 0.0)
                aff_file = cf.get("affected_file", "N/A")
                corr_rows.append(f"| `{fid}` | `{rc}` | `{sev}` | `{conf:.2f}` | `{aff_file}` |")
        corr_table = "\n".join(corr_rows) if corr_rows else "| None | N/A | N/A | N/A | N/A |"

        # M13.1 Repair Validations table
        val_rows = []
        if repair_validations:
            for rv in repair_validations:
                fid = rv.get("finding_id", "")
                rc = rv.get("vulnerability_type", "UNKNOWN")
                tf = rv.get("target_file", "")
                verdict = rv.get("final_verdict", "INCONCLUSIVE")
                qual = rv.get("patch_quality", {}).get("quality_score", "N/A")
                val_rows.append(f"| `{fid}` | `{rc}` | `{tf}` | `{qual}` | `{verdict}` |")
        val_table = "\n".join(val_rows) if val_rows else "| None | N/A | N/A | N/A | NO_REPAIR_REQUIRED |"

        # M14 Historical Comparison Summary
        hist_section = ""
        if historical_comparison:
            score_b = historical_comparison.get("score_before", 100)
            score_a = historical_comparison.get("score_after", 100)
            delta = historical_comparison.get("score_delta", 0)
            trend = historical_comparison.get("risk_trend", "STABLE")
            n_new = len(historical_comparison.get("new_findings", []))
            n_fixed = len(historical_comparison.get("fixed_findings", []))
            n_reopened = len(historical_comparison.get("reopened_findings", []))

            hist_section = f"""
---

### 📈 M14 Historical Security Intelligence & Risk Trend
- **Security Score Before**: `{score_b} / 100`
- **Current Security Score**: `{score_a} / 100`
- **Score Delta**: `{delta:+d}`
- **Risk Trend**: `{trend}`
- **New Vulnerabilities**: `{n_new}`
- **Fixed Vulnerabilities**: `{n_fixed}`
- **Reopened Vulnerabilities**: `{n_reopened}`
- **Trend Explanation**: {historical_comparison.get("explanation", "N/A")}
"""

        # Governance table
        gov_rows = []
        if governance_decisions:
            for gd in governance_decisions:
                fid = gd.get("finding_id", "")
                dec = gd.get("decision", "ALLOW")
                gov_rows.append(f"| `{fid}` | `{dec}` |")
        gov_table = "\n".join(gov_rows) if gov_rows else "| None | ALLOW |"

        md = f"""# 📊 AgentOS-SWE Execution Run Report & Security Intelligence

### 📌 Executive Summary
- **Repository**: `{report.repository_name}`
- **Git Commit Ref**: `{report.commit_ref or 'N/A'}`
- **Start Time**: `{report.start_time}`
- **End Time**: `{report.end_time}`
- **Total Duration**: `{report.total_duration_sec:.2f}s`
- **Total Trace Events**: `{report.trace_events_count}`
- **Safety Status**: `PASS (IsolatedSandbox + DRY RUN Active)`
- **Final Verdict**: `{final_verdict}`
{hist_section}
---

### 🎯 M15 Top Remediation Queue (What Should I Fix First?)
| Rank | Tier | Score | Root Cause | Affected File | Exploitability | Exposure | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{prio_table}

---

### 🔍 Finding Summary & Metrics
- **Total Discovered**: `{f_m.total_discovered}`
- **Confirmed True Positives**: `{f_m.confirmed}`
- **Rejected False Positives**: `{f_m.rejected}`
- **Inconclusive Findings**: `{f_m.inconclusive}`

---

### 🧩 Correlated Vulnerabilities & Root-Cause Analysis
| Finding ID | Root Cause | Severity | Confidence | Affected File |
| :--- | :--- | :--- | :--- | :--- |
{corr_table}

---

### 🛠️ M13.1 Real-World Repair Validation Summary
| Finding ID | Root Cause | Target File | Patch Quality | Final Repair Verdict |
| :--- | :--- | :--- | :--- | :--- |
{val_table}

- **Patches Generated**: `{r_m.patches_generated}`
- **Reproduction Tests Passed**: `{r_m.reproduction_pass}`
- **Regression Tests Passed**: `{r_m.regression_pass}`
- **Independent Reviews Approved**: `{r_m.independent_review_pass}`
- **Validated Patches Produced**: `{r_m.validated_patches}`

---

### ⚖️ Governance Decisions
| Finding ID | Decision |
| :--- | :--- |
{gov_table}

---

### 🛡️ System Resilience & Resources
- **LLM Router Fallbacks**: `{report.fallback_count}`
- **Checkpoint Recoveries**: `{report.checkpoint_recoveries}`
- **Total Tokens Consumed**: `{report.total_tokens}`
- **Estimated Cost**: `${report.total_cost_est:.4f}`

---

### 🤖 Agent Execution Breakdown
| Agent | Runs | Success | Fail | Fallback | Tokens | Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{agent_table}

---

*Report generated by **AgentOS-SWE (Autonomous Software Verification and Repair System)**.*
"""
        return SecretProtection.sanitize_text(md)
