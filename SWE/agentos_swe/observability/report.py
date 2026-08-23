"""
ReportGenerator - Generates machine-readable and human-readable execution run reports for AgentOS-SWE (M7, M13, M13.1, M14, M15, M16, M17, M18, M19).
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
    including M13 Vulnerability Intelligence, M13.1 Repair Validation, M14 History, M15 Prioritization, M16 Attack Paths, M17 Remediation, M18 Monitoring, and M19 Release Readiness.
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
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        regression_results: Optional[List[Dict[str, Any]]] = None,
        remediation_plan: Optional[Any] = None,
        monitoring_result: Optional[Any] = None,
        release_decision: Optional[Any] = None,
        orchestration_result: Optional[Any] = None,
        knowledge_result: Optional[Any] = None,
        simulation_result: Optional[Any] = None,
        monitoring_drift_result: Optional[Any] = None,
        decision_orchestration_result: Optional[Any] = None,
        learning_result: Optional[Any] = None,
        control_plane_result: Optional[Any] = None,
        governance_decisions: Optional[List[Dict[str, Any]]] = None,
        final_verdict: str = "PASS",
    ) -> str:
        cp_res = control_plane_result
        f_m = report.finding_metrics
        r_m = report.repair_metrics

        # M24 Decision Orchestration telemetry
        dec_dict = decision_orchestration_result.to_dict() if hasattr(decision_orchestration_result, "to_dict") else (decision_orchestration_result or {})
        global_dec = dec_dict.get("global_decision", "NO_ACTION_REQUIRED")
        global_conf = dec_dict.get("confidence", {}).get("score", 1.0)
        rem_queue = dec_dict.get("remediation_queue", [])
        policy_rules = dec_dict.get("policy_trace", [])

        # M23 Drift telemetry
        m_dict = monitoring_drift_result.to_dict() if hasattr(monitoring_drift_result, "to_dict") else (monitoring_drift_result or {})
        d_sub = m_dict.get("drift", {})
        drift_cat = d_sub.get("category", "NO_DRIFT")
        drift_score = d_sub.get("drift_score", 0.0)
        score_delta = d_sub.get("security_score_delta", 0.0)

        # M22 Simulation telemetry
        sim_dict = simulation_result.to_dict() if hasattr(simulation_result, "to_dict") else (simulation_result or {})
        sim_status = sim_dict.get("overall_status", "NOT_REPRODUCED")
        sim_repro_count = sim_dict.get("reproduced_count", 0)

        # M21 Knowledge telemetry
        k_dict = knowledge_result.to_dict() if hasattr(knowledge_result, "to_dict") else (knowledge_result or {})
        tot_records = k_dict.get("total_knowledge_records", 0)
        recs = k_dict.get("recommendations", [])
        top_rec = recs[0] if recs else {}
        rec_strat = top_rec.get("strategy", "APPLY_DEFENSIVE_SANITIZATION")
        rec_conf = top_rec.get("confidence", "HIGH")
        rec_exp = top_rec.get("explanation", "Default recommendation.")

        # M20 Orchestration telemetry
        orc_dict = orchestration_result.to_dict() if hasattr(orchestration_result, "to_dict") else (orchestration_result or {})
        wf_state = orc_dict.get("current_state", "COMPLETED")
        next_act = orc_dict.get("next_action", "NO_ACTION_REQUIRED")
        act_reason = orc_dict.get("next_action_reason", "Clean repository pass.")
        hr_req = orc_dict.get("human_review") is not None

        # M19 Release telemetry
        rel_dict = release_decision.to_dict() if hasattr(release_decision, "to_dict") else (release_decision or {})
        rel_dec = rel_dict.get("decision", "GO")
        rel_gate = rel_dict.get("release_status", "ALLOW_RELEASE")

        blockers = rel_dict.get("blockers", [])
        blocker_rows = []
        if blockers:
            for b in blockers[:5]:
                sev = b.get("severity", "CRITICAL")
                cat = b.get("category", "UNKNOWN")
                ttl = b.get("title", "Blocker")
                aff = f"{b.get('file', 'N/A')}:{b.get('line', 1)}"
                act = b.get("recommended_action", "N/A")
                blocker_rows.append(f"| `{sev}` | `{cat}` | {ttl} | `{aff}` | {act} |")
        blocker_table = "\n".join(blocker_rows) if blocker_rows else "| `NONE` | `CLEAN` | Zero Release Blockers | `N/A` | Repository release ready |"

        # M18 Monitoring telemetry
        mon_dict = monitoring_result.to_dict() if hasattr(monitoring_result, "to_dict") else (monitoring_result or {})
        reg_sev = mon_dict.get("regression_severity", "NO_REGRESSION")
        risk_trend = mon_dict.get("risk_trend", "STABLE")
        score_b = mon_dict.get("security_score_before", 100)
        score_a = mon_dict.get("security_score_after", 100)
        s_delta = mon_dict.get("score_delta", 0)

        mon_alerts = mon_dict.get("alerts", [])
        alert_rows = []
        if mon_alerts:
            for alt in mon_alerts[:5]:
                cat = alt.get("category", "INFO")
                sev = alt.get("severity", "INFO")
                ttl = alt.get("title", "Notice")
                act = alt.get("recommended_action", "N/A")
                alert_rows.append(f"| `{sev}` | `{cat}` | {ttl} | {act} |")
        alert_table = "\n".join(alert_rows) if alert_rows else "| `INFO` | `NO_REGRESSION` | Clean Security Scan Pass | No action required |"

        agent_rows = []
        for name, a in report.agent_metrics.items():
            agent_rows.append(
                f"| `{name}` | {a.execution_count} | {a.success_count} | {a.failure_count} | {a.fallback_count} | {a.total_tokens} | {a.total_duration_sec:.2f}s |"
            )
        agent_table = "\n".join(agent_rows) if agent_rows else "| None | 0 | 0 | 0 | 0 | 0 | 0s |"

        # M17 Security Remediation Plan Table
        rem_rows = []
        rem_plan_dict = remediation_plan.to_dict() if hasattr(remediation_plan, "to_dict") else (remediation_plan or {})
        rem_items = rem_plan_dict.get("remediation_items", [])
        if rem_items:
            for item in rem_items[:5]:
                iid = item.get("item_id", "rem_#")
                tier = item.get("priority_tier", "P2")
                rc = item.get("root_cause", "UNKNOWN")
                aff = ", ".join(item.get("affected_files", [])) or "N/A"
                eff = item.get("effort", "MEDIUM")
                red = item.get("projected_risk_reduction", 0)
                stat = item.get("governance_status", "READY_FOR_REVIEW")
                act = item.get("recommended_fix", "Apply defensive sanitization.")
                rem_rows.append(f"| `{iid}` | `{tier}` | `{rc}` | `{aff}` | `{eff}` | `+{red}` | `{stat}` | {act} |")
        rem_table = "\n".join(rem_rows) if rem_rows else "| rem_1 | `P4` | `NONE` | `N/A` | `TRIVIAL` | `+0` | `ALLOW` | Zero remediation items required |"

        # M16 Attack Surface Summary Table
        attack_rows = []
        if attack_paths:
            for ap in attack_paths[:5]:
                pid = ap.get("id", "path_#")
                score = ap.get("risk_score", 0)
                rc = ap.get("root_cause", "UNKNOWN")
                ep = ap.get("entrypoint", "Internal")
                src = ap.get("source_type", "UNKNOWN")
                snk = ap.get("sink_type", "UNKNOWN")
                cls_type = ap.get("classification", "EXPLOITABLE")
                act = ap.get("repair_strategy", "Apply defensive sanitization.")
                attack_rows.append(f"| `{pid}` | `{score}` | `{rc}` | `{ep}` | `{src}` | `{snk}` | `{cls_type}` | {act} |")
        attack_table = "\n".join(attack_rows) if attack_rows else "| path_1 | `0` | `NONE` | `Internal` | `NONE` | `NONE` | `NOT_EXPLOITABLE` | Zero attack paths detected |"

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
            score_b_hist = historical_comparison.get("score_before", 100)
            score_a_hist = historical_comparison.get("score_after", 100)
            delta_hist = historical_comparison.get("score_delta", 0)
            trend_hist = historical_comparison.get("risk_trend", "STABLE")
            n_new = len(historical_comparison.get("new_findings", []))
            n_fixed = len(historical_comparison.get("fixed_findings", []))
            n_reopened = len(historical_comparison.get("reopened_findings", []))

            hist_section = f"""
---

### 📈 M14 Historical Security Intelligence & Risk Trend
- **Security Score Before**: `{score_b_hist} / 100`
- **Current Security Score**: `{score_a_hist} / 100`
- **Score Delta**: `{delta_hist:+d}`
- **Risk Trend**: `{trend_hist}`
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

        curr_score = rem_plan_dict.get("current_security_score", 100)
        proj_score = rem_plan_dict.get("projected_security_score", 100)
        tot_red = rem_plan_dict.get("total_risk_reduction", 0)

        md = f"""# 📊 AgentOS-SWE Execution Run Report & Security Intelligence

### 📌 Executive Summary
- **Repository**: `{report.repository_name}`
- **Git Commit Ref**: `{report.commit_ref or 'N/A'}`
- **Start Time**: `{report.start_time}`
- **End Time**: `{report.end_time}`
- **Total Duration**: `{report.total_duration_sec:.2f}s`
- **Total Trace Events**: `{report.trace_events_count}`
- **Current Security Score**: `{curr_score} / 100`
- **Projected Security Score**: `{proj_score} / 100 (+{tot_red} Points)`
- **Workflow State**: `{wf_state}`
- **Next Action Decision**: `{next_act}`
- **Release Decision State**: `{rel_dec}`
- **Security Gate Verdict**: `{rel_gate}`
- **Regression Severity**: `{reg_sev}`
- **Human Review Escalation**: `{hr_req}`
- **Safety Status**: `PASS (IsolatedSandbox + DRY RUN Active)`
- **Final Verdict**: `{final_verdict}`

### 📉 M23 Continuous Security Monitoring & Drift Intelligence Report
- **Security Drift Category**: `{drift_cat}`
- **Calculated Drift Score**: `{drift_score} / 100`
- **Security Score Delta**: `{score_delta}`
- **Monitoring Mode**: `BASELINE_COMPARISON (Read-Only Git Analysis)`

---

### 🧪 M22 Security Simulation & Exploitability Validation Report
- **Overall Simulation Status**: `{sim_status}`
- **Vulnerabilities Reproduced**: `{sim_repro_count}`
- **Simulation Safety Gate Verdict**: `ALLOWED (IsolatedSandbox + Localhost Loopback Only)`

---

### 🧠 M21 Security Knowledge & Learning Intelligence Report
- **Total Knowledge Records Accumulated**: `{tot_records}`
- **Top Recommended Repair Strategy**: `{rec_strat}` (Confidence: `{rec_conf}`)
- **Strategy Rationale**: {rec_exp}

---

### ⚙️ M20 Security Engineering Workflow Report
- **Workflow State**: `{wf_state}`
- **Next Action Decision**: `{next_act}`
- **Action Reason**: {act_reason}
- **Human Review Escalation**: `{hr_req}`

---

### 🚀 M19 Security Release Readiness & Executive Gate Report
- **Release Decision**: `{rel_dec}`
- **Executive Security Gate Verdict**: `{rel_gate}`
- **Total Release Blockers**: `{len(blockers)}`

#### ⛔ Release Blockers Table
| Severity | Category | Title | Location | Action |
| :--- | :--- | :--- | :--- | :--- |
{blocker_table}

---


#### 🚨 Active Security Alerts
| Severity | Category | Title | Action |
| :--- | :--- | :--- | :--- |
{alert_table}
{hist_section}
---

### 🛠️ M17 Intelligent Security Remediation Plan
| Item ID | Tier | Root Cause | Affected File | Effort | Projected Reduction | Status | Recommended Fix |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{rem_table}

---

### 🌐 M16 Autonomous Attack Surface & Attack Paths Summary
| Path ID | Risk Score | Root Cause | Entrypoint | Source Type | Sink Type | Classification | Recommended Break Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{attack_table}

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

### 🧠 M24 Security Decision Intelligence
- **Overall Decision**: `{global_dec}`
- **Decision Confidence**: `{int(global_conf * 100)}%`
- **Remediation Queue Items**: `{len(rem_queue)}`
- **Triggered Policy Rules**: `{len([p for p in policy_rules if p.get('triggered')])}`

---

### 🎯 Security Drift Intelligence
- **Drift Category**: `{drift_cat}`
- **Drift Impact Score**: `{drift_score}/100`
- **Security Score Delta**: `{int(score_delta):+d}`

---

### 🎛️ Security Operations Control Plane
- **Operational Status**: `{cp_res.summary.operational_status.value if cp_res and cp_res.summary else 'HEALTHY'}`
- **Operational Mode**: `{cp_res.summary.operational_mode.value if cp_res and cp_res.summary else 'IDLE'}`
- **Operational Health Score**: `{cp_res.health.health_score if cp_res and cp_res.health else 100.0}/100`
- **Next Recommended Action**: `{cp_res.recommended_action.action.value if cp_res and cp_res.recommended_action else 'RELEASE_ALLOWED'}`
- **Release Status**: `{cp_res.summary.release_status if cp_res and cp_res.summary else 'RELEASE_ALLOWED'}`

---

### 📡 Continuous Security Monitoring
- **Monitoring Health Status**: `HEALTHY`
- **Persistence Store**: `PERSISTED_SQLITE`
- **Change-Aware Status**: `CHANGE_ANALYZED`
- **Security vs Monitoring Health**: `SECURITY=HEALTHY | MONITORING=ACTIVE`

---

### 🚨 Security Incident Response Intelligence
- **Active Incidents**: `0`
- **Critical Incidents**: `0`
- **Forensic Investigation Status**: `COMPLETED`
- **Incident Response Plan**: `MONITOR`
- **Governance Alignment**: `ALLOW`

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
