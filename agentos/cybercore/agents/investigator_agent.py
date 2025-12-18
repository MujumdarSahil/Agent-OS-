"""
Investigator Agent - Correlates logs and IOCs, identifies root cause patterns
Uses LogAnalysis MCP
"""

from typing import Dict, Any, Optional, List
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
from agentos.cybercore.tools.ioc_normalizer import IOCNormalizerTool


class InvestigatorAgent(Agent):
    """
    Investigator Agent - Deep investigation and correlation.
    Queries logs, enriches IOCs, and identifies root cause patterns.
    """
    
    def __init__(
        self,
        name: str = "InvestigatorAgent",
        memory_ref: Optional[UMBAdapter] = None,
        log_analysis_mcp: Optional[Any] = None,
        threat_intel_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["log_analysis", "ioc_enrichment", "correlation", "root_cause_analysis"],
            memory_ref=memory_ref,
        )
        self.log_analysis_mcp = log_analysis_mcp
        self.threat_intel_mcp = threat_intel_mcp
        self.role = "investigator"
    
    async def investigate(self, alert_id: str, query: str, log_entries: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Investigate an alert by querying logs and enriching IOCs.
        
        Args:
            alert_id: Alert ID to investigate
            query: Investigation query
            log_entries: Optional log entries to analyze
            
        Returns:
            Investigation results
        """
        # Query logs
        log_results = []
        if self.log_analysis_mcp:
            if log_entries:
                search_result = await self.log_analysis_mcp.call_skill("search_logs", {
                    "query": query,
                    "log_entries": log_entries,
                    "filters": {},
                })
            else:
                search_result = await self.log_analysis_mcp.call_skill("search_logs", {
                    "query": query,
                    "filters": {},
                })
            
            if search_result.get("success"):
                log_results = search_result["results"]
        
        # Extract and normalize IOCs from logs
        all_iocs = []
        for log in log_results:
            log_str = str(log)
            iocs = IOCNormalizerTool.extract_iocs_from_text(log_str)
            all_iocs.extend(iocs)
        
        # Enrich IOCs
        enriched_iocs = []
        if self.threat_intel_mcp:
            for ioc in all_iocs[:10]:  # Limit to avoid quota
                enrich_result = await self.threat_intel_mcp.call_skill("enrich_ioc", {
                    "ioc_type": ioc["type"],
                    "ioc_value": ioc["value"],
                })
                if enrich_result.get("success"):
                    enriched_iocs.append(enrich_result["enriched"])
        
        # Detect patterns in logs
        patterns = []
        if self.log_analysis_mcp:
            for log_entry in log_results[:20]:  # Limit
                log_str = str(log_entry)
                pattern_result = await self.log_analysis_mcp.call_skill("detect_patterns", {
                    "log_entry": log_str,
                    "log_type": "generic",
                })
                if pattern_result.get("success") and pattern_result.get("suspicious"):
                    patterns.append(pattern_result)
        
        # Correlate findings
        correlation = self._correlate_findings(log_results, enriched_iocs, patterns)
        
        # Generate hypothesis
        hypothesis = self._generate_hypothesis(correlation, enriched_iocs, patterns)
        
        investigation_result = {
            "alert_id": alert_id,
            "log_results_count": len(log_results),
            "enriched_iocs": enriched_iocs,
            "patterns_detected": len(patterns),
            "correlation": correlation,
            "hypothesis": hypothesis,
            "investigator": self.id,
        }
        
        # Store in memory
        if self.memory_ref:
            await self.memory_ref.upsert({
                "text": f"Investigation result: {investigation_result}",
                "metadata": {
                    "author_agent": self.id,
                    "permission_level": "squad_shared",
                    "alert_id": alert_id,
                    "type": "investigation_result",
                }
            })
        
        return {
            "success": True,
            "investigation": investigation_result,
        }
    
    def _correlate_findings(
        self,
        logs: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Correlate findings from logs, IOCs, and patterns"""
        high_threat_iocs = [ioc for ioc in iocs if ioc.get("threat_score", 0) > 0.7]
        attack_tags = set()
        
        for pattern in patterns:
            tags = pattern.get("attack_tags", [])
            attack_tags.update(tags)
        
        return {
            "total_iocs": len(iocs),
            "high_threat_iocs": len(high_threat_iocs),
            "log_count": len(logs),
            "pattern_count": len(patterns),
            "attack_tags": list(attack_tags),
            "correlation_score": len(high_threat_iocs) / max(len(iocs), 1) if iocs else 0,
        }
    
    def _generate_hypothesis(
        self,
        correlation: Dict[str, Any],
        iocs: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]]
    ) -> str:
        """Generate root cause hypothesis"""
        if correlation.get("high_threat_iocs", 0) > 0:
            return "Potential malicious activity detected with high-threat IOCs"
        elif correlation.get("pattern_count", 0) > 0:
            return "Suspicious activity patterns detected in logs"
        elif correlation.get("correlation_score", 0) > 0.5:
            return "Suspicious activity pattern detected"
        else:
            return "No clear malicious pattern identified"

