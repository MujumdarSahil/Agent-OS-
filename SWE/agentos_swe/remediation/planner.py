"""
M17 Intelligent Security Remediation Planner.

Orchestrates root-cause grouping, attack-path earliest break point selection, risk/effort calculation,
dependency/conflict analysis, fix ordering, 8-step validation plan generation, and governance status assignment.
"""

from typing import List, Dict, Any, Optional
from agentos_swe.remediation.models import (
    RemediationPlan,
    RemediationItem,
    RemediationStatus,
    EffortCategory,
)
from agentos_swe.remediation.fix_ordering import FixOrderingEngine
from agentos_swe.remediation.dependency_analyzer import DependencyAnalyzer
from agentos_swe.remediation.conflict_detector import ConflictDetector
from agentos_swe.remediation.risk_reduction import RiskReductionCalculator
from agentos_swe.remediation.effort_estimator import EffortEstimator
from agentos_swe.remediation.remediation_graph import RemediationGraphBuilder


class RemediationPlanner:
    """
    End-to-End Security Remediation Planner.
    """

    def __init__(self):
        self.fix_ordering_engine = FixOrderingEngine()
        self.dependency_analyzer = DependencyAnalyzer()
        self.conflict_detector = ConflictDetector()
        self.risk_calculator = RiskReductionCalculator()
        self.effort_estimator = EffortEstimator()
        self.graph_builder = RemediationGraphBuilder()

    def generate_remediation_plan(
        self,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        repair_proposals: Optional[List[Any]] = None,
        repair_validations: Optional[List[Any]] = None,
        historical_comparison: Optional[Any] = None,
        repository_name: str = "Unknown Repo",
    ) -> RemediationPlan:
        """
        Generates a complete, structured RemediationPlan from security telemetry.
        """
        prioritized_findings = prioritized_findings or []
        attack_paths = attack_paths or []
        repair_proposals = repair_proposals or []
        repair_validations = repair_validations or []

        # 1. Group Findings by Shared Root Cause & File
        grouped_items: Dict[str, RemediationItem] = {}

        for idx, pf in enumerate(prioritized_findings):
            pf_dict = pf.to_dict() if hasattr(pf, "to_dict") else pf
            fid = pf_dict.get("finding_id") or pf_dict.get("id") or f"f_{idx+1}"
            rc = str(pf_dict.get("root_cause") or pf_dict.get("category") or "UNKNOWN").upper()
            aff_file = pf_dict.get("affected_file") or pf_dict.get("file") or "N/A"
            tier = pf_dict.get("priority_tier") or "P3"
            tier_str = tier.value if hasattr(tier, "value") else str(tier)
            score = pf_dict.get("priority_score", 50)
            code_ctx = str(pf_dict.get("code_context") or pf_dict.get("title") or "")
            exploitability = str(pf_dict.get("exploitability") or "UNKNOWN").upper()

            # Ignore non-exploitable / safe negative controls
            if rc in ("DICT_LOOKUP", "INFO", "TEST_HARNESS", "INTENTIONAL_FALLBACK") or exploitability == "NOT_EXPLOITABLE":
                continue

            # Grouping key: Root cause + affected file
            group_key = f"{rc}:{aff_file}"

            # Match associated attack paths
            matching_paths = [
                ap for ap in attack_paths
                if getattr(ap, "source_file", "") == aff_file or getattr(ap, "root_cause", "") == rc
            ]
            path_ids = [getattr(ap, "id", "ap_1") for ap in matching_paths]

            # Earliest break point selection
            earliest_break = f"Input propagation in `{aff_file}`"
            recommended_fix = "Apply defensive input validation and sanitization."
            repair_strat = "DEFENSIVE_SANITIZATION"

            if rc == "COMMAND_INJECTION":
                earliest_break = f"Subprocess Command Execution in `{aff_file}`"
                recommended_fix = "Replace `shell=True` or string concatenation with argument-array execution (`subprocess.run(['cmd', arg])`)."
                repair_strat = "REPLACE_SHELL_TRUE_WITH_ARG_ARRAY"
            elif rc == "SQL_INJECTION":
                earliest_break = f"SQL Query Execution in `{aff_file}`"
                recommended_fix = "Replace string interpolation with parameterized SQL query placeholders (`cursor.execute(sql, (param,))`)."
                repair_strat = "DEFENSIVE_SANITIZATION"
            elif rc == "EXCEPTION_SWALLOWING":
                earliest_break = f"Exception Block in `{aff_file}`"
                recommended_fix = "Narrow bare `except:` clause to target exception type and log errors."
                repair_strat = "NARROW_EXCEPTION_AND_LOG"

            # Check if fix introduces public API impact
            is_public_api = "public_api" in code_ctx.lower() or "api_break" in code_ctx.lower()
            if is_public_api:
                recommended_fix += " (Requires public API deprecation notice and backwards-compatible adapter)."

            if group_key in grouped_items:
                # Append finding ID to existing grouped item
                existing = grouped_items[group_key]
                if fid not in existing.affected_finding_ids:
                    existing.affected_finding_ids.append(fid)
                for pid in path_ids:
                    if pid not in existing.affected_attack_path_ids:
                        existing.affected_attack_path_ids.append(pid)
                # Keep highest priority score
                if score > existing.priority_score:
                    existing.priority_score = score
                    existing.priority_tier = tier_str
            else:
                item_id = f"rem_{len(grouped_items)+1}"
                title = f"Remediate {rc.replace('_', ' ').title()} in {aff_file}"
                
                # Standard 8-step validation plan per item
                val_requirements = [
                    "Python AST syntax validation",
                    "Targeted reproduction test verification",
                    "Static taint re-analysis",
                    "End-to-end attack path re-analysis",
                    "Security regression scan",
                    "Historical scan comparison",
                    "Full test suite pass",
                    "PR Governance Gate evaluation",
                ]
                if is_public_api:
                    val_requirements.append("Public API compatibility inspection")

                item = RemediationItem(
                    item_id=item_id,
                    title=title,
                    root_cause=rc,
                    affected_finding_ids=[fid],
                    affected_attack_path_ids=path_ids,
                    affected_files=[aff_file],
                    affected_symbols=[pf_dict.get("affected_function") or "main"],
                    earliest_break_point=earliest_break,
                    recommended_fix=recommended_fix,
                    repair_strategy=repair_strat,
                    priority_score=score,
                    priority_tier=tier_str,
                    validation_requirements=val_requirements,
                    governance_status=RemediationStatus.READY_FOR_REVIEW,
                    evidence_summary={
                        "code_context": code_ctx,
                        "auth_status": str(pf_dict.get("auth_status") or "UNKNOWN"),
                        "entrypoint_type": str(pf_dict.get("entrypoint_type") or "UNKNOWN"),
                    },
                )

                # Estimate effort category
                item.effort = self.effort_estimator.estimate_item_effort(item, is_public_api=is_public_api)
                grouped_items[group_key] = item

        items_list = list(grouped_items.values())

        # 2. Estimate Risk Reduction and Calculate Scores
        curr_score, total_reduction, proj_score = self.risk_calculator.calculate_scores(
            items=items_list,
            findings=[pf.to_dict() if hasattr(pf, "to_dict") else pf for pf in prioritized_findings],
            attack_paths=attack_paths,
        )

        # 3. Analyze Dependencies & Detect Conflicts
        self.dependency_analyzer.analyze_dependencies(items_list)
        conflicts = self.conflict_detector.detect_conflicts(items_list)

        # 4. Deterministic Fix Sequencing
        ordered_items = self.fix_ordering_engine.order_remediation_items(items_list)
        exec_order = [it.item_id for it in ordered_items]

        # 5. Total Effort Calculation
        total_effort = self.effort_estimator.calculate_total_effort(ordered_items)

        # Collect unique files and symbols
        all_files = list({f for it in ordered_items for f in it.affected_files})
        all_symbols = list({s for it in ordered_items for s in it.affected_symbols})
        dep_rels = {it.item_id: it.dependencies for it in ordered_items}

        # 6. Global Plan Governance Status
        gov_status = "ALLOW"
        recommendation = "PLAN_ONLY"

        if conflicts:
            gov_status = "NEEDS_REVIEW"
            recommendation = "CONFLICTS_DETECTED — Human review required before fix execution."
        elif any(it.governance_status == RemediationStatus.BLOCKED for it in ordered_items):
            gov_status = "REJECT"
            recommendation = "BLOCKED_ITEMS — High risk or unvalidated repairs present."
        elif not ordered_items:
            gov_status = "ALLOW"
            recommendation = "NO_REPAIR_REQUIRED — Repository clean of exploitable attack paths."
        else:
            gov_status = "ALLOW"
            recommendation = "PLAN_READY — Executive remediation plan ready for sandboxed validation."

        plan = RemediationPlan(
            plan_id=f"plan_{repository_name.lower().replace(' ', '_')}",
            repository=repository_name,
            findings_count=len(prioritized_findings),
            remediation_items=ordered_items,
            execution_order=exec_order,
            dependency_relationships=dep_rels,
            conflicts=conflicts,
            total_estimated_effort=total_effort,
            current_security_score=curr_score,
            projected_security_score=proj_score,
            total_risk_reduction=total_reduction,
            affected_files=all_files,
            affected_symbols=all_symbols,
            validation_requirements=[
                "Sandboxed patch validation",
                "Reproduction test suite pass",
                "Taint & attack path re-analysis",
                "Security regression scan",
            ],
            governance_status=gov_status,
            final_recommendation=recommendation,
        )

        # 7. Build Remediation Graph
        plan.graph = self.graph_builder.build_graph(plan)

        return plan
