"""
Triage Agent - Consumes alerts, deduplicates, and classifies incidents
Uses ModelHub and ThreatIntel MCP
"""

from typing import Dict, Any, Optional
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
import uuid


class TriageAgent(Agent):
    """
    Triage Agent - Alert triage and classification.
    Consumes alerts, deduplicates, and classifies incidents.
    """
    
    def __init__(
        self,
        name: str = "TriageAgent",
        memory_ref: Optional[UMBAdapter] = None,
        model_hub_mcp: Optional[Any] = None,
        threat_intel_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["alert_analysis", "classification", "deduplication", "incident_triage"],
            memory_ref=memory_ref,
        )
        self.model_hub_mcp = model_hub_mcp
        self.threat_intel_mcp = threat_intel_mcp
        self.role = "triage"
        self.processed_alerts = {}  # For deduplication
    
    async def triage_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Triage a security alert.
        
        Args:
            alert: Raw alert data
            
        Returns:
            Triage result with classification and severity
        """
        from agentos.cybercore.utils.normalization import AlertNormalizer
        
        # Normalize alert
        normalized = AlertNormalizer.normalize_alert(alert)
        alert_id = normalized.get("id") or str(uuid.uuid4())
        
        # Deduplication
        alert_key = f"{normalized.get('source')}:{normalized.get('title')}"
        if alert_key in self.processed_alerts:
            return {
                "success": True,
                "triage_result": {
                    "alert_id": alert_id,
                    "duplicate": True,
                    "original_alert_id": self.processed_alerts[alert_key],
                },
            }
        
        self.processed_alerts[alert_key] = alert_id
        
        # Enrich IOCs with threat intelligence
        enriched_iocs = []
        if self.threat_intel_mcp and normalized.get("iocs"):
            for ioc in normalized["iocs"][:5]:  # Limit to avoid quota
                enrich_result = await self.threat_intel_mcp.call_skill("enrich_ioc", {
                    "ioc_type": ioc["type"],
                    "ioc_value": ioc["value"],
                })
                if enrich_result.get("success"):
                    enriched_iocs.append(enrich_result["enriched"])
        
        # Classify using AI model
        classification = None
        if self.model_hub_mcp:
            classification_result = await self.model_hub_mcp.call_skill("classify", {
                "text": normalized.get("description", ""),
                "model": "incident_classifier",
                "agent_id": self.id,
            })
            if classification_result.get("success"):
                classification = classification_result["classification"]
        
        # Determine severity
        severity = normalized.get("severity", "low")
        if enriched_iocs:
            max_threat = max(ioc.get("threat_score", 0.5) for ioc in enriched_iocs)
            if max_threat > 0.7:
                severity = "high"
            elif max_threat > 0.4:
                severity = "medium"
        
        # Create triage result
        triage_result = {
            "alert_id": alert_id,
            "severity": severity,
            "classification": classification,
            "enriched_iocs": enriched_iocs,
            "recommended_action": self._recommend_action(severity, classification),
            "confidence": 0.8,
            "triage_agent": self.id,
        }
        
        # Store in memory
        if self.memory_ref:
            await self.memory_ref.upsert({
                "text": f"Triage result: {triage_result}",
                "metadata": {
                    "author_agent": self.id,
                    "permission_level": "squad_shared",
                    "alert_id": alert_id,
                    "type": "triage_result",
                }
            })
        
        return {
            "success": True,
            "triage_result": triage_result,
        }
    
    def _recommend_action(self, severity: str, classification: Optional[Dict[str, Any]]) -> str:
        """Recommend action based on severity and classification"""
        if severity == "critical":
            return "immediate_investigation"
        elif severity == "high":
            return "investigate"
        elif classification and classification.get("label") == "malicious":
            return "investigate"
        else:
            return "monitor"

