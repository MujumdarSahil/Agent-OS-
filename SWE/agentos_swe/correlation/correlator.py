"""
M13 Provider-Agnostic Evidence Correlation Engine.

Correlates findings across investigation agents, static taint analysis, code graph,
semantic resolvers, and verification results into unified CorrelatedFinding objects.
"""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from agentos_swe.models import Finding, Evidence, EvidenceSource
from agentos_swe.security.taint.models import TaintFinding, TaintPath
from agentos_swe.context import RepositoryContext
from agentos_swe.correlation.models import (
    CorrelatedFinding,
    EvidenceChain,
    ConfidenceExplanation,
    RootCauseCategory,
)
from agentos_swe.correlation.root_cause import RootCauseAnalyzer

logger = logging.getLogger(__name__)


class EvidenceCorrelator:
    """
    Evidence-Driven Vulnerability Correlator combining multi-agent findings,
    taint flows, code graph relations, semantic classifications, and verification states.
    """

    def __init__(self, root_cause_analyzer: Optional[RootCauseAnalyzer] = None):
        self.root_cause_analyzer = root_cause_analyzer or RootCauseAnalyzer()

    def correlate(
        self,
        findings: List[Finding],
        taint_findings: Optional[List[TaintFinding]] = None,
        semantic_results: Optional[Dict[str, Any]] = None,
        context: Optional[RepositoryContext] = None,
        verification_results: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CorrelatedFinding]:
        """
        Main entrypoint to correlate findings into unified CorrelatedFinding objects.
        """
        if not findings and not taint_findings:
            return []

        taint_findings = taint_findings or []
        semantic_results = semantic_results or {}
        verification_results = verification_results or []

        # 1. Group findings by correlation keys (file, nearby lines, function, variable, root cause)
        clusters: List[Dict[str, Any]] = []

        # Track processed items
        processed_findings: Set[str] = set()
        processed_taints: Set[int] = set()

        # Step A: Cluster Taint Findings first (strongest structural dataflow evidence)
        for idx, tf in enumerate(taint_findings):
            cluster = {
                "file": tf.path.file or (tf.path.source.file if tf.path.source else ""),
                "findings": [],
                "taint_finding": tf,
                "lines": self._get_taint_lines(tf),
                "symbols": {tf.path.source.var_name, tf.path.sink.var_name} if tf.path and tf.path.source and tf.path.sink else set(),
            }

            # Associate raw findings that overlap in file and line range or symbol
            for raw_f in findings:
                if raw_f.id in processed_findings:
                    continue
                if self._is_correlated(raw_f, cluster):
                    cluster["findings"].append(raw_f)
                    processed_findings.add(raw_f.id)

            clusters.append(cluster)
            processed_taints.add(idx)

        # Step B: Cluster remaining raw findings
        for raw_f in findings:
            if raw_f.id in processed_findings:
                continue

            # Look for existing cluster match
            matched = False
            for cluster in clusters:
                if self._is_correlated(raw_f, cluster):
                    cluster["findings"].append(raw_f)
                    processed_findings.add(raw_f.id)
                    matched = True
                    break

            if not matched:
                lines = (raw_f.line_range[0], raw_f.line_range[1]) if raw_f.line_range else (0, 0)
                clusters.append({
                    "file": raw_f.file or "",
                    "findings": [raw_f],
                    "taint_finding": None,
                    "lines": lines,
                    "symbols": {raw_f.symbol} if raw_f.symbol else set(),
                })
                processed_findings.add(raw_f.id)

        # 2. Build CorrelatedFinding for each cluster
        correlated_results: List[CorrelatedFinding] = []

        for idx, cluster in enumerate(clusters):
            primary_finding = cluster["findings"][0] if cluster["findings"] else None
            tf = cluster["taint_finding"]

            finding_id = primary_finding.id if primary_finding else f"corr_taint_{idx}"
            file_path = cluster["file"]
            lines = cluster["lines"]
            symbol = list(cluster["symbols"])[0] if cluster["symbols"] else (primary_finding.symbol if primary_finding else None)

            # Determine root cause
            root_cause = self.root_cause_analyzer.determine_root_cause(
                finding=primary_finding or Finding(id=finding_id, title=tf.title if tf else ""),
                taint_finding=tf,
                semantic_info=semantic_results.get(file_path),
            )

            # Build Evidence Chain
            evidence_chain = self._build_evidence_chain(
                findings=cluster["findings"],
                taint_finding=tf,
                semantic_results=semantic_results.get(file_path),
                context=context,
                verification_results=verification_results,
            )

            # Calculate explainable confidence
            confidence, explanation = self._calculate_confidence(
                findings=cluster["findings"],
                taint_finding=tf,
                evidence_chain=evidence_chain,
                semantic_info=semantic_results.get(file_path),
                verification_results=verification_results,
            )

            # Severity calculation
            severity = self._determine_severity(cluster["findings"], tf)

            # Remediation recommendation
            remediation = self._generate_remediation_recommendation(root_cause, tf)

            # Related IDs
            related_ids = [f.id for f in cluster["findings"] if f.id != finding_id]

            category = primary_finding.category if primary_finding else (tf.title if tf else root_cause.value)

            corr = CorrelatedFinding(
                finding_id=finding_id,
                vulnerability_category=category,
                severity=severity,
                confidence=confidence,
                confidence_explanation=explanation,
                evidence_chain=evidence_chain,
                related_finding_ids=related_ids,
                root_cause=root_cause,
                affected_file=file_path,
                affected_function=symbol,
                affected_lines=lines if lines != (0, 0) else None,
                remediation_recommendation=remediation,
            )
            correlated_results.append(corr)

        return correlated_results

    def _get_taint_lines(self, tf: TaintFinding) -> Tuple[int, int]:
        if not tf.path:
            return (0, 0)
        start = tf.path.source.line_no if tf.path.source else 0
        end = tf.path.sink.line_no if tf.path.sink else start
        return (start, end)

    def _is_correlated(self, raw_f: Finding, cluster: Dict[str, Any]) -> bool:
        """Check if raw finding correlates with existing cluster."""
        if raw_f.file and cluster["file"] and raw_f.file.lower() != cluster["file"].lower():
            return False

        # Line proximity check (+/- 5 lines)
        if raw_f.line_range and cluster["lines"] != (0, 0):
            c_start, c_end = cluster["lines"]
            f_start, f_end = raw_f.line_range
            if abs(f_start - c_start) <= 5 or abs(f_end - c_end) <= 5:
                return True

        # Symbol overlap check
        if raw_f.symbol and raw_f.symbol in cluster["symbols"]:
            return True

        # Vulnerability / Title keyword overlap
        title_lower = (raw_f.title or "").lower()
        if cluster["taint_finding"] and any(kw in title_lower for kw in ["injection", "shell", "eval", "sql", "taint", "xss", "traversal"]):
            return True

        return False

    def _build_evidence_chain(
        self,
        findings: List[Finding],
        taint_finding: Optional[TaintFinding],
        semantic_results: Optional[Dict[str, Any]],
        context: Optional[RepositoryContext],
        verification_results: Optional[List[Dict[str, Any]]],
    ) -> EvidenceChain:
        chain = EvidenceChain()

        if taint_finding and taint_finding.path:
            p = taint_finding.path
            if p.source:
                chain.source_evidence.append(p.source.to_dict())
            for step in p.propagation_steps:
                chain.propagation_evidence.append(step.to_dict())
            if p.sink:
                chain.sink_evidence.append(p.sink.to_dict())

        for f in findings:
            chain.agent_evidence.append({
                "finding_id": f.id,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
            })
            for ev in f.evidence:
                if ev.source == EvidenceSource.CODE_GRAPH:
                    chain.graph_evidence.append(ev.to_dict())

        if semantic_results:
            chain.semantic_evidence.append(semantic_results)

        if verification_results:
            for vr in verification_results:
                chain.verification_evidence.append(vr)

        return chain

    def _calculate_confidence(
        self,
        findings: List[Finding],
        taint_finding: Optional[TaintFinding],
        evidence_chain: EvidenceChain,
        semantic_info: Optional[Dict[str, Any]],
        verification_results: Optional[List[Dict[str, Any]]],
    ) -> Tuple[float, ConfidenceExplanation]:
        score = 0.40  # Base confidence
        rationale: List[str] = []

        if taint_finding:
            if evidence_chain.source_evidence:
                score += 0.15
                rationale.append("+ untrusted source identified")
            if evidence_chain.propagation_evidence:
                score += 0.15
                rationale.append("+ propagation chain confirmed")
            if evidence_chain.sink_evidence:
                score += 0.15
                rationale.append("+ dangerous sink confirmed")

        if len(findings) > 1:
            score += 0.10
            rationale.append("+ multi-agent investigation agreement")

        if evidence_chain.graph_evidence:
            score += 0.05
            rationale.append("+ code graph relationship verified")

        if semantic_info:
            score += 0.05
            rationale.append("+ semantic type resolved")

        if verification_results:
            for vr in verification_results:
                if vr.get("status") in ("CONFIRMED", "VERIFIED"):
                    score += 0.15
                    rationale.append("+ verification confirmation passed")
                    break

        final_score = min(0.99, max(0.10, round(score, 2)))
        return final_score, ConfidenceExplanation(score=final_score, rationale=rationale)

    def _determine_severity(self, findings: List[Finding], taint_finding: Optional[TaintFinding]) -> str:
        if taint_finding:
            return taint_finding.severity.value

        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = "medium"
        max_val = 2
        for f in findings:
            val = order.get((f.severity or "").lower(), 1)
            if val > max_val:
                max_val = val
                max_sev = f.severity.lower()
        return max_sev

    def _generate_remediation_recommendation(
        self, root_cause: RootCauseCategory, taint_finding: Optional[TaintFinding]
    ) -> str:
        if root_cause == RootCauseCategory.COMMAND_INJECTION:
            return "Avoid shell=True execution. Use argument array lists with subprocess or sanitize using shlex.quote."
        elif root_cause == RootCauseCategory.SQL_INJECTION:
            return "Use parameterized queries with placeholders instead of string formatting or concatenation."
        elif root_cause == RootCauseCategory.XSS:
            return "Context-aware HTML escaping on untrusted dynamic output using html.escape() or markupsafe.escape()."
        elif root_cause == RootCauseCategory.PATH_TRAVERSAL:
            return "Canonicalize and validate paths using os.path.abspath / Path.resolve() and enforce allowed target directories."
        elif root_cause == RootCauseCategory.UNSAFE_DESERIALIZATION:
            return "Replace unsafe deserializers (pickle.loads/yaml.load) with safe equivalents (json.loads/yaml.safe_load)."
        elif root_cause == RootCauseCategory.EXCEPTION_SWALLOWING:
            return "Narrow caught exception type, log diagnostic error details, and provide controlled fallback handling."
        return "Apply safe coding patterns and sanitize all external inputs prior to processing."
