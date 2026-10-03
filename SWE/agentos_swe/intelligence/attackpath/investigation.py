"""
M16 Autonomous Security Investigator.

Generates complete SecurityInvestigation outputs including "Why is this dangerous?" narratives
and "How to break the attack path" remediation instructions connected to M13/M13.1 repair strategies.
"""

from typing import Dict, Any, Optional
from agentos_swe.intelligence.attackpath.models import (
    AttackPath,
    SecurityInvestigation,
    PathClassification,
)


class AutonomousSecurityInvestigator:
    """
    Autonomous Security Investigator generating evidence narratives and remediation break points.
    """

    def investigate_attack_path(
        self,
        attack_path: AttackPath,
        validation_result: Optional[Any] = None,
    ) -> SecurityInvestigation:
        """
        Builds a comprehensive SecurityInvestigation for an AttackPath.
        """
        fid = attack_path.id
        rc = attack_path.root_cause
        ep = attack_path.entrypoint
        src = attack_path.source_type
        snk = attack_path.sink_type
        aff_file = attack_path.source_file

        # 1. "Why is this dangerous?" Evidence Narrative
        if attack_path.classification == PathClassification.EXPLOITABLE:
            why_narrative = (
                f"An unauthenticated attacker entrypoint (`{ep}`) accepts input (`{src}`). "
                f"The un-sanitized value propagates through application logic in `{aff_file}` "
                f"and reaches dangerous sink `{snk}` ({rc}). "
                f"This creates an exploitable attack vector from external source to sink execution."
            )
        elif attack_path.classification == PathClassification.PARTIALLY_MITIGATED:
            why_narrative = (
                f"Entrypoint (`{ep}`) accepts input (`{src}`) reaching sink `{snk}`. "
                f"Sanitizer step `{attack_path.sanitizer_steps}` was detected along the path, "
                f"partially mitigating direct exploitability."
            )
        else:
            why_narrative = (
                f"Path from `{ep}` to `{snk}` in `{aff_file}` is classified as `{attack_path.classification.value}`. "
                f"Zero active external exploit vectors detected for this execution path."
            )

        # 2. "How to break the attack path" Remediation Instructions
        if rc == "COMMAND_INJECTION":
            how_break = (
                f"Break Point: Shell Command Execution in `{aff_file}`.\n"
                f"Recommended Control: Replace `shell=True` or string concatenation with argument-array execution (`subprocess.run(['cmd', arg])`).\n"
                f"Expected Result: Taint path no longer reaches OS shell interpreter."
            )
        elif rc == "SQL_INJECTION":
            how_break = (
                f"Break Point: SQL Query Building in `{aff_file}`.\n"
                f"Recommended Control: Replace string interpolation with parameterized SQL query placeholders (`cursor.execute(sql, (param,))`).\n"
                f"Expected Result: Unsanitized data cannot alter SQL query AST semantics."
            )
        elif rc == "EXCEPTION_SWALLOWING":
            how_break = (
                f"Break Point: Exception Block in `{aff_file}`.\n"
                f"Recommended Control: Narrow bare `except:` to target exception class and add logging.\n"
                f"Expected Result: Silent error suppression eliminated; restores system observability."
            )
        else:
            how_break = (
                f"Break Point: Input propagation in `{aff_file}`.\n"
                f"Recommended Control: Apply strict input validation and defensive sanitization.\n"
                f"Expected Result: Complete elimination of root cause '{rc}' exploitability."
            )

        # 3. Validation Status Integration
        val_status = "UNTESTED"
        if validation_result:
            val_status = str(getattr(validation_result, "final_verdict", "INCONCLUSIVE"))

        return SecurityInvestigation(
            investigation_id=f"inv_{fid}",
            target_finding_id=fid,
            attack_path=attack_path,
            why_dangerous_narrative=why_narrative,
            how_to_break_narrative=how_break,
            risk_score=attack_path.risk_score,
            exploitability=attack_path.classification.value,
            exposure=attack_path.entrypoint_type.value,
            blast_radius="BROAD" if len(attack_path.propagation_steps) >= 3 else "LOCAL",
            historical_status="NEW_ATTACK_PATH",
            root_cause=rc,
            recommendation=attack_path.repair_strategy or "DEFENSIVE_SANITIZATION",
            repair_strategy=attack_path.repair_strategy,
            validation_status=val_status,
        )
