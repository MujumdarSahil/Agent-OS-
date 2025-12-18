"""
Threat Hunt Agent - Runs scheduled proactive hunts, uses pattern-matching tools
"""

from typing import Dict, Any, Optional, List
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
from agentos.cybercore.tools.log_pattern_detector import LogPatternDetector


class ThreatHuntAgent(Agent):
    """
    Threat Hunt Agent - Proactive threat detection.
    Runs scheduled hunts and queries logs for TTP signatures.
    """
    
    def __init__(
        self,
        name: str = "ThreatHuntAgent",
        memory_ref: Optional[UMBAdapter] = None,
        log_analysis_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["threat_hunting", "pattern_detection", "anomaly_detection", "ttp_detection"],
            memory_ref=memory_ref,
        )
        self.log_analysis_mcp = log_analysis_mcp
        self.role = "threat_hunter"
    
    async def hunt(self, pattern: str, time_range: Dict[str, str] = None, log_entries: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Hunt for threats using pattern matching.
        
        Args:
            pattern: Pattern to search for
            time_range: Time range for search
            log_entries: Optional log entries to analyze
            
        Returns:
            Hunting results
        """
        time_range = time_range or {"start": "7d", "end": "now"}
        
        # Query logs
        log_results = []
        if self.log_analysis_mcp:
            if log_entries:
                search_result = await self.log_analysis_mcp.call_skill("search_logs", {
                    "query": pattern,
                    "log_entries": log_entries,
                    "filters": {},
                })
            else:
                search_result = await self.log_analysis_mcp.call_skill("search_logs", {
                    "query": pattern,
                    "filters": {},
                })
            
            if search_result.get("success"):
                log_results = search_result["results"]
        
        # Detect patterns
        patterns = []
        attack_tags = set()
        
        for log_entry in log_results[:50]:  # Limit
            log_str = str(log_entry)
            detection = LogPatternDetector.detect_patterns(log_str)
            
            if detection.get("suspicious"):
                patterns.append({
                    "log_entry": log_str[:200],  # Truncate
                    "detection": detection,
                })
                attack_tags.update(detection.get("attack_tags", []))
        
        # Detect brute force
        brute_force = None
        if log_results:
            log_strings = [str(log) for log in log_results]
            brute_force = LogPatternDetector.detect_brute_force(log_strings)
        
        return {
            "success": True,
            "pattern": pattern,
            "time_range": time_range,
            "log_results_count": len(log_results),
            "patterns_detected": len(patterns),
            "attack_tags": list(attack_tags),
            "brute_force": brute_force,
            "hunter": self.id,
        }
    
    async def hunt_ttp(self, ttp_id: str, log_entries: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Hunt for specific MITRE ATT&CK TTP.
        
        Args:
            ttp_id: MITRE ATT&CK TTP ID (e.g., "T1078")
            log_entries: Optional log entries to analyze
            
        Returns:
            TTP hunt results
        """
        # Get TTP pattern
        ttp_info = LogPatternDetector.ATTACK_PATTERNS.get(ttp_id)
        if not ttp_info:
            return {
                "success": False,
                "error": f"Unknown TTP: {ttp_id}",
            }
        
        pattern = ttp_info["pattern"]
        
        # Hunt for pattern
        hunt_result = await self.hunt(pattern, log_entries=log_entries)
        
        if hunt_result.get("success"):
            hunt_result["ttp_id"] = ttp_id
            hunt_result["ttp_name"] = ttp_info["name"]
            hunt_result["ttp_description"] = ttp_info["description"]
        
        return hunt_result

