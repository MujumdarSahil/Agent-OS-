"""
M21 Security Knowledge Package & SecurityKnowledgeEngine Facade.

Provides security knowledge persistent storage, pattern learning, recommendations,
retrieval, graph traversal, and cross-repository intelligence.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from agentos_swe.knowledge.models import (
    SecurityKnowledgeRecord,
    SecurityPattern,
    RemediationPattern,
    AttackPathPattern,
    SecurityOutcome,
    KnowledgeFeedback,
    CrossRepositorySecurityPattern,
    RemediationRecommendation,
)
from agentos_swe.knowledge.store import SecurityKnowledgeStore
from agentos_swe.knowledge.fingerprint import SecurityPatternFingerprinter
from agentos_swe.knowledge.patterns import SecurityPatternLearner
from agentos_swe.knowledge.retrieval import SecurityKnowledgeRetriever
from agentos_swe.knowledge.learning import RemediationSuccessLearner
from agentos_swe.knowledge.recommendations import AdaptiveSecurityRecommendationEngine
from agentos_swe.knowledge.graph import SecurityKnowledgeGraph


class SecurityKnowledgeEngine:
    """
    Main Security Knowledge Facade coordinating storage, pattern learning,
    retrieval, adaptive recommendations, and knowledge graph operations.
    """

    def __init__(self, store_path: Optional[str] = None):
        self.store = SecurityKnowledgeStore(db_path=store_path)
        self.fingerprinter = SecurityPatternFingerprinter()
        self.learner = SecurityPatternLearner()
        self.retriever = SecurityKnowledgeRetriever(store=self.store)
        self.recommendation_engine = AdaptiveSecurityRecommendationEngine()
        self.success_learner = RemediationSuccessLearner()

    def process_scan_knowledge(
        self,
        verified_findings: Optional[List[Any]] = None,
        prioritized_findings: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        remediation_plan: Optional[Any] = None,
        monitoring_result: Optional[Any] = None,
        release_decision: Optional[Any] = None,
        repository_name: str = "Unknown Repo",
    ) -> Dict[str, Any]:
        """
        Extracts patterns, persists knowledge records, builds graph, and generates recommendations.
        """
        findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in (prioritized_findings or verified_findings or [])]
        paths = [ap.to_dict() if hasattr(ap, "to_dict") else ap for ap in (attack_paths or [])]
        rem_plan = remediation_plan.to_dict() if hasattr(remediation_plan, "to_dict") else (remediation_plan or {})
        mon_res = monitoring_result.to_dict() if hasattr(monitoring_result, "to_dict") else (monitoring_result or {})
        rel_dec = release_decision.to_dict() if hasattr(release_decision, "to_dict") else (release_decision or {})

        records_created: List[SecurityKnowledgeRecord] = []
        patterns_learned: List[SecurityPattern] = []
        attack_patterns: List[AttackPathPattern] = []
        recommendations: List[RemediationRecommendation] = []
        graph = SecurityKnowledgeGraph()

        # Add repository node
        graph.add_node(repository_name, repository_name, "Repository")

        # 1. Process Findings & Extract Patterns
        for f in findings[:5]:
            rc = str(f.get("root_cause") or f.get("category") or "UNKNOWN").upper()
            fam = f.get("vulnerability_family") or rc
            pat = self.learner.extract_pattern(f, repository_name)
            patterns_learned.append(pat)

            # Build Knowledge Record
            kid = f"kn_{pat.pattern_id}_{repository_name}"
            rec = SecurityKnowledgeRecord(
                knowledge_id=kid,
                vulnerability_family=fam,
                root_cause=rc,
                source_pattern=pat.source_type,
                sink_pattern=pat.sink_type,
                attack_path_pattern=paths[0].get("id", "none") if paths else "none",
                affected_framework=pat.framework,
                affected_language="PYTHON",
                remediation_strategy=rem_plan.get("remediation_items", [{}])[0].get("recommended_fix", "Defensive sanitization") if rem_plan.get("remediation_items") else "Defensive sanitization",
                validation_result="SUCCESSFUL_REPAIR" if rel_dec.get("decision") in ("GO", "GO_WITH_WARNINGS") else "FAILED_VALIDATION",
                regression_result=mon_res.get("regression_severity", "NO_REGRESSION"),
                release_outcome=rel_dec.get("decision", "GO"),
                confidence=0.95 if rel_dec.get("decision") == "GO" else 0.60,
                recurrence_count=1,
                successful_repairs=1 if rel_dec.get("decision") in ("GO", "GO_WITH_WARNINGS") else 0,
                failed_repairs=1 if rel_dec.get("decision") == "BLOCKED" else 0,
                repositories_seen=[repository_name],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                evidence=f.get("evidence", []) if isinstance(f.get("evidence"), list) else [],
            )

            self.store.save_record(rec)
            records_created.append(rec)

            # Populate Graph
            f_node_id = f"find_{f.get('finding_id', '1')}"
            graph.add_node(f_node_id, f.get("finding_id", "Finding"), "Finding", f)
            graph.add_node(rc, rc, "RootCause")
            graph.add_edge(repository_name, f_node_id, "FOUND_IN")
            graph.add_edge(f_node_id, rc, "HAS_ROOT_CAUSE")

            # Generate Recommendation
            hist_recs = [r.to_dict() for r in self.retriever.retrieve_similar_records(f)]
            rec_item = self.recommendation_engine.generate_recommendation(f, hist_recs)
            recommendations.append(rec_item)

        # 2. Extract Attack Path Patterns
        for ap in paths[:5]:
            app = self.learner.extract_attack_path_pattern(ap, repository_name)
            attack_patterns.append(app)
            graph.add_node(app.pattern_id, app.pattern_id, "AttackPath", ap)
            graph.add_edge(repository_name, app.pattern_id, "FORMS_ATTACK_PATH")

        # 3. Aggregate Cross-Repository Patterns
        all_store_records = [r.to_dict() for r in self.store.search("")]
        cross_patterns = self.learner.learn_cross_repository_patterns(all_store_records)

        return {
            "records_created": [r.to_dict() for r in records_created],
            "patterns_learned": [p.to_dict() for p in patterns_learned],
            "attack_patterns": [ap.to_dict() for ap in attack_patterns],
            "recommendations": [rec.to_dict() for rec in recommendations],
            "cross_patterns": [cp.to_dict() for cp in cross_patterns],
            "knowledge_graph": graph,
            "total_knowledge_records": len(all_store_records),
        }


__all__ = [
    "SecurityKnowledgeRecord",
    "SecurityPattern",
    "RemediationPattern",
    "AttackPathPattern",
    "SecurityOutcome",
    "KnowledgeFeedback",
    "CrossRepositorySecurityPattern",
    "RemediationRecommendation",
    "SecurityKnowledgeStore",
    "SecurityPatternFingerprinter",
    "SecurityPatternLearner",
    "SecurityKnowledgeRetriever",
    "RemediationSuccessLearner",
    "AdaptiveSecurityRecommendationEngine",
    "SecurityKnowledgeGraph",
    "SecurityKnowledgeEngine",
]
