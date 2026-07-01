"""
Threat Intelligence MCP - Lightweight threat intelligence feed integrator
"""

from typing import Dict, Any
from agentos.mcp_connectors.base_mcp import BaseMCPConnector
from agentos.cybercore.utils.normalization import IOCNormalizer
from datetime import datetime


class ThreatIntelMCP(BaseMCPConnector):
    """
    Threat Intelligence MCP - IOC enrichment and reputation checking.
    Lightweight integrator for threat intelligence feeds.
    """
    
    def __init__(self, endpoint: str = "threat://intel"):
        super().__init__(endpoint, "threat_intel_mcp", "threat_intelligence")
        self.skills = [
            {
                "id": "enrich_ioc",
                "name": "enrich_ioc",
                "description": "Enrich IOC with threat intelligence",
                "type": "tool",
                "inputs": {"ioc_type": "string", "ioc_value": "string"},
                "outputs": {"enriched": "dict", "threat_score": "float"},
                "latency_estimate": 2.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "public",
                "cost_estimate": {"cost": 0.1},
            },
            {
                "id": "check_reputation",
                "name": "check_reputation",
                "description": "Check IOC reputation",
                "type": "tool",
                "inputs": {"ioc_type": "string", "ioc_value": "string"},
                "outputs": {"reputation": "string", "confidence": "float"},
                "latency_estimate": 1.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "public",
                "cost_estimate": {"cost": 0.05},
            },
        ]
        self.ioc_cache: Dict[str, Dict[str, Any]] = {}
    
    async def connect(self) -> bool:
        """Connect to threat intelligence service"""
        self.status = "active"
        return True
    
    async def disconnect(self):
        """Disconnect"""
        self.status = "inactive"
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call threat intelligence skill"""
        if skill_name == "enrich_ioc":
            ioc_type = params.get("ioc_type", "").lower()
            ioc_value = params.get("ioc_value", "")
            
            # Normalize IOC
            normalized = IOCNormalizer.normalize_ioc(ioc_value, ioc_type)
            if not normalized["normalized"]:
                return {
                    "success": False,
                    "error": f"Invalid IOC: {ioc_value}",
                }
            
            ioc_key = f"{normalized['type']}:{normalized['value']}"
            
            # Check cache
            if ioc_key in self.ioc_cache:
                cached = self.ioc_cache[ioc_key]
                return {
                    "success": True,
                    "enriched": cached,
                    "threat_score": cached.get("threat_score", 0.5),
                    "sources": cached.get("sources", []),
                    "cached": True,
                }
            
            # Enrich IOC (in production would query real threat intel feeds)
            enriched = {
                "ioc_type": normalized["type"],
                "ioc_value": normalized["value"],
                "threat_score": 0.5,  # Default neutral
                "sources": ["internal", "public_feeds"],
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "tags": [],
                "categories": [],
                "description": f"Enriched {normalized['type']} indicator",
            }
            
            # Simple heuristic (in production would use real threat intel)
            if normalized["type"] == "ip":
                # Check if internal IP
                if any(part in normalized["value"] for part in ["192.168", "10.0", "127.0", "172.16"]):
                    enriched["threat_score"] = 0.1
                    enriched["tags"].append("internal")
                else:
                    enriched["threat_score"] = 0.6
                    enriched["tags"].append("external")
            
            elif normalized["type"] == "domain":
                # Check for suspicious TLDs or patterns
                if any(tld in normalized["value"] for tld in [".tk", ".ml", ".ga", ".cf"]):
                    enriched["threat_score"] = 0.7
                    enriched["tags"].append("suspicious_tld")
            
            # Cache result
            self.ioc_cache[ioc_key] = enriched
            
            return {
                "success": True,
                "enriched": enriched,
                "threat_score": enriched["threat_score"],
                "sources": enriched["sources"],
            }
        
        elif skill_name == "check_reputation":
            ioc_type = params.get("ioc_type", "").lower()
            ioc_value = params.get("ioc_value", "")
            
            # Enrich first
            enrich_result = await self.call_skill("enrich_ioc", params)
            if not enrich_result.get("success"):
                return enrich_result
            
            enriched = enrich_result["enriched"]
            threat_score = enriched.get("threat_score", 0.5)
            
            # Determine reputation
            if threat_score > 0.7:
                reputation = "malicious"
            elif threat_score > 0.4:
                reputation = "suspicious"
            else:
                reputation = "clean"
            
            return {
                "success": True,
                "reputation": reputation,
                "confidence": abs(threat_score - 0.5) * 2,  # Confidence based on distance from neutral
                "threat_score": threat_score,
            }
        
        return {"success": False, "error": f"Unknown skill: {skill_name}"}

