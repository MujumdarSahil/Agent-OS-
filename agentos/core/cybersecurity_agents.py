"""
Cybersecurity Agent Types - Specialized agents for security operations
"""

from typing import Dict, Any, List, Optional
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
import uuid


class TriageAgent(Agent):
    """
    Triage Agent - Ingests alerts, deduplicates, and classifies incidents.
    Uses ModelHubMCP and ThreatIntelMCP.
    """
    
    def __init__(
        self,
        name: str = "TriageAgent",
        memory_ref: Optional[UMBAdapter] = None,
        model_hub_mcp: Optional[Any] = None,
        threat_intel_mcp: Optional[Any] = None,
        alert_ingest_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["alert_analysis", "classification", "deduplication", "incident_triage"],
            memory_ref=memory_ref,
        )
        self.model_hub_mcp = model_hub_mcp
        self.threat_intel_mcp = threat_intel_mcp
        self.alert_ingest_mcp = alert_ingest_mcp
        self.role = "triage"
    
    async def triage_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Triage a security alert.
        
        Args:
            alert: Raw alert data
            
        Returns:
            Triage result with classification and severity
        """
        # Ingest and normalize
        if self.alert_ingest_mcp:
            ingest_result = await self.alert_ingest_mcp.call_skill("ingest_alert", {
                "alert_raw": alert,
                "source": alert.get("source", "unknown"),
                "alert_type": alert.get("type", "generic"),
            })
            
            if not ingest_result.get("success"):
                return {"success": False, "error": "Failed to ingest alert"}
            
            normalized = ingest_result["normalized"]
        else:
            normalized = alert
        
        # Enrich with threat intelligence
        iocs = self._extract_iocs(normalized)
        enriched_iocs = []
        
        if self.threat_intel_mcp:
            for ioc in iocs:
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
                "text": str(normalized),
                "model": "incident_classifier",
                "agent_id": self.id,
            })
            if classification_result.get("success"):
                classification = classification_result["classification"]
        
        # Create triage result
        triage_result = {
            "alert_id": normalized.get("id", str(uuid.uuid4())),
            "severity": normalized.get("severity", "low"),
            "classification": classification,
            "enriched_iocs": enriched_iocs,
            "recommended_action": self._recommend_action(normalized, classification),
            "triage_agent": self.id,
        }
        
        # Store in memory
        if self.memory_ref:
            await self.memory_ref.upsert({
                "text": f"Triage result: {triage_result}",
                "metadata": {
                    "author_agent": self.id,
                    "permission_level": "squad_shared",
                    "alert_id": triage_result["alert_id"],
                    "type": "triage_result",
                }
            })
        
        return {
            "success": True,
            "triage_result": triage_result,
        }
    
    def _extract_iocs(self, alert: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract IOCs from alert"""
        iocs = []
        
        # Extract IPs
        for field in ["source_ip", "dest_ip", "src_ip", "destination_ip"]:
            if field in alert and alert[field]:
                iocs.append({"type": "ip", "value": alert[field]})
        
        # Extract domains
        for field in ["domain", "hostname", "url"]:
            if field in alert and alert[field]:
                iocs.append({"type": "domain", "value": alert[field]})
        
        # Extract hashes
        for field in ["file_hash", "md5", "sha256"]:
            if field in alert and alert[field]:
                iocs.append({"type": "hash", "value": alert[field]})
        
        return iocs
    
    def _recommend_action(self, alert: Dict[str, Any], classification: Optional[Dict[str, Any]]) -> str:
        """Recommend action based on alert and classification"""
        severity = alert.get("severity", "low")
        
        if severity == "critical":
            return "immediate_investigation"
        elif severity == "high":
            return "investigate"
        elif classification and classification.get("label") == "malicious":
            return "investigate"
        else:
            return "monitor"


class InvestigatorAgent(Agent):
    """
    Investigator Agent - Queries logs, enriches IOCs, correlates evidence.
    Uses LogAnalysisMCP and ThreatIntelMCP.
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
    
    async def investigate(self, alert_id: str, query: str) -> Dict[str, Any]:
        """
        Investigate an alert by querying logs and enriching IOCs.
        
        Args:
            alert_id: Alert ID to investigate
            query: Investigation query
            
        Returns:
            Investigation results
        """
        # Query logs
        log_results = []
        if self.log_analysis_mcp:
            search_result = await self.log_analysis_mcp.call_skill("search_logs", {
                "query": query,
                "time_range": {"start": "24h", "end": "now"},
                "filters": {},
            })
            if search_result.get("success"):
                log_results = search_result["results"]
        
        # Extract and enrich IOCs from logs
        all_iocs = []
        for log in log_results:
            iocs = self._extract_iocs(log)
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
        
        # Correlate findings
        correlation = self._correlate_findings(log_results, enriched_iocs)
        
        # Generate hypothesis
        hypothesis = self._generate_hypothesis(correlation, enriched_iocs)
        
        investigation_result = {
            "alert_id": alert_id,
            "log_results_count": len(log_results),
            "enriched_iocs": enriched_iocs,
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
    
    def _extract_iocs(self, log: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract IOCs from log entry"""
        iocs = []
        log_str = str(log).lower()
        
        # Simple extraction (in production would use more sophisticated methods)
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, log_str)
        for ip in ips:
            iocs.append({"type": "ip", "value": ip})
        
        return iocs
    
    def _correlate_findings(self, logs: List[Dict[str, Any]], iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate findings from logs and IOCs"""
        # Simple correlation (in production would use more sophisticated methods)
        high_threat_iocs = [ioc for ioc in iocs if ioc.get("threat_score", 0) > 0.7]
        
        return {
            "total_iocs": len(iocs),
            "high_threat_iocs": len(high_threat_iocs),
            "log_count": len(logs),
            "correlation_score": len(high_threat_iocs) / max(len(iocs), 1),
        }
    
    def _generate_hypothesis(self, correlation: Dict[str, Any], iocs: List[Dict[str, Any]]) -> str:
        """Generate root cause hypothesis"""
        if correlation.get("high_threat_iocs", 0) > 0:
            return "Potential malicious activity detected with high-threat IOCs"
        elif correlation.get("correlation_score", 0) > 0.5:
            return "Suspicious activity pattern detected"
        else:
            return "No clear malicious pattern identified"


class SandboxAnalystAgent(Agent):
    """
    Sandbox Analyst Agent - Submits artifacts for isolated analysis.
    Uses SandboxMCP for malware analysis.
    """
    
    def __init__(
        self,
        name: str = "SandboxAnalystAgent",
        memory_ref: Optional[UMBAdapter] = None,
        sandbox_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["malware_analysis", "behavior_analysis", "artifact_analysis"],
            memory_ref=memory_ref,
        )
        self.sandbox_mcp = sandbox_mcp
        self.role = "sandbox_analyst"
    
    async def analyze_artifact(self, artifact_hash: str, artifact_type: str = "file") -> Dict[str, Any]:
        """
        Submit artifact for sandbox analysis.
        
        Args:
            artifact_hash: Hash of the artifact
            artifact_type: Type of artifact (file, url, email)
            
        Returns:
            Analysis results
        """
        if not self.sandbox_mcp:
            return {"success": False, "error": "Sandbox MCP not available"}
        
        # Submit to sandbox
        analysis_result = await self.sandbox_mcp.call_skill("analyze_artifact", {
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
        })
        
        if not analysis_result.get("success"):
            return analysis_result
        
        # Summarize behavior
        behavior_summary = analysis_result.get("behavior_summary", {})
        network_indicators = analysis_result.get("network_indicators", [])
        risk_level = analysis_result.get("risk_level", "unknown")
        
        summary = {
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "risk_level": risk_level,
            "behavior_summary": behavior_summary,
            "network_indicators": network_indicators,
            "recommendation": self._generate_recommendation(risk_level, behavior_summary),
            "analyst": self.id,
        }
        
        # Store in memory
        if self.memory_ref:
            await self.memory_ref.upsert({
                "text": f"Sandbox analysis: {summary}",
                "metadata": {
                    "author_agent": self.id,
                    "permission_level": "squad_shared",
                    "artifact_hash": artifact_hash,
                    "type": "sandbox_analysis",
                }
            })
        
        return {
            "success": True,
            "analysis": summary,
        }
    
    def _generate_recommendation(self, risk_level: str, behavior: Dict[str, Any]) -> str:
        """Generate recommendation based on analysis"""
        if risk_level == "high" or risk_level == "critical":
            return "Immediate containment recommended"
        elif risk_level == "medium":
            return "Further investigation recommended"
        else:
            return "Monitor and review"


class ComplianceAgent(Agent):
    """
    Compliance Agent - Audits password policies and compliance.
    Uses PasswordAuditMCP.
    """
    
    def __init__(
        self,
        name: str = "ComplianceAgent",
        memory_ref: Optional[UMBAdapter] = None,
        password_audit_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["password_audit", "compliance_checking", "policy_analysis"],
            memory_ref=memory_ref,
        )
        self.password_audit_mcp = password_audit_mcp
        self.role = "compliance"
    
    async def audit_password_policy(
        self,
        policy_config: Dict[str, Any],
        password_hashes: List[str]
    ) -> Dict[str, Any]:
        """
        Audit password policy compliance.
        
        Args:
            policy_config: Password policy configuration
            password_hashes: List of password hashes (never cleartext)
            
        Returns:
            Audit results
        """
        if not self.password_audit_mcp:
            return {"success": False, "error": "Password audit MCP not available"}
        
        # Audit policy
        audit_result = await self.password_audit_mcp.call_skill("audit_policy", {
            "policy_config": policy_config,
            "password_hashes": password_hashes,
        })
        
        if not audit_result.get("success"):
            return audit_result
        
        # Store results
        if self.memory_ref:
            await self.memory_ref.upsert({
                "text": f"Password policy audit: {audit_result}",
                "metadata": {
                    "author_agent": self.id,
                    "permission_level": "squad_shared",
                    "type": "compliance_audit",
                }
            })
        
        return {
            "success": True,
            "audit": audit_result,
        }


class ResponderAgent(Agent):
    """
    Responder Agent - Orchestrates containment and remediation.
    Uses ResponseActionMCP with policy checks.
    """
    
    def __init__(
        self,
        name: str = "ResponderAgent",
        memory_ref: Optional[UMBAdapter] = None,
        response_action_mcp: Optional[Any] = None,
        governance: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["incident_response", "containment", "remediation"],
            memory_ref=memory_ref,
        )
        self.response_action_mcp = response_action_mcp
        self.governance = governance
        self.role = "responder"
    
    async def contain_incident(
        self,
        incident_id: str,
        host_id: Optional[str] = None,
        user_id: Optional[str] = None,
        reason: str = ""
    ) -> Dict[str, Any]:
        """
        Contain an incident (isolate host or revoke credentials).
        Requires policy check and optionally human approval.
        
        Args:
            incident_id: Incident ID
            host_id: Optional host ID to isolate
            user_id: Optional user ID to revoke credentials
            reason: Reason for containment
            
        Returns:
            Containment result
        """
        if not self.response_action_mcp:
            return {"success": False, "error": "Response action MCP not available"}
        
        # Policy check
        if self.governance:
            decision = await self.governance.check(
                agent_id=self.id,
                action="contain_incident",
                context={
                    "incident_id": incident_id,
                    "host_id": host_id,
                    "user_id": user_id,
                    "agent": self,
                }
            )
            if not decision.allowed:
                return {
                    "success": False,
                    "error": f"Policy violation: {decision.reason}",
                    "requires_approval": True,
                }
        
        results = []
        
        # Isolate host if provided
        if host_id:
            isolate_result = await self.response_action_mcp.call_skill("isolate_host", {
                "host_id": host_id,
                "reason": reason,
                "approved": True,  # Would be set by human approval in production
                "approved_by": "system",
            })
            results.append(isolate_result)
        
        # Revoke credentials if provided
        if user_id:
            revoke_result = await self.response_action_mcp.call_skill("revoke_credentials", {
                "user_id": user_id,
                "reason": reason,
                "approved": True,
                "approved_by": "system",
            })
            results.append(revoke_result)
        
        # Create ticket
        ticket_result = await self.response_action_mcp.call_skill("create_ticket", {
            "title": f"Incident Response: {incident_id}",
            "description": f"Containment actions taken: {reason}",
            "priority": "high",
        })
        results.append(ticket_result)
        
        return {
            "success": True,
            "incident_id": incident_id,
            "actions": results,
        }


class ThreatHuntingAgent(Agent):
    """
    Threat Hunting Agent - Proactively searches for suspicious patterns.
    Uses LogAnalysisMCP and UMB memory.
    """
    
    def __init__(
        self,
        name: str = "ThreatHuntingAgent",
        memory_ref: Optional[UMBAdapter] = None,
        log_analysis_mcp: Optional[Any] = None,
    ):
        super().__init__(
            name=name,
            skills=["threat_hunting", "pattern_detection", "anomaly_detection"],
            memory_ref=memory_ref,
        )
        self.log_analysis_mcp = log_analysis_mcp
        self.role = "threat_hunter"
    
    async def hunt(self, pattern: str, time_range: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Hunt for threats using pattern matching.
        
        Args:
            pattern: Pattern to search for
            time_range: Time range for search
            
        Returns:
            Hunting results
        """
        time_range = time_range or {"start": "7d", "end": "now"}
        
        # Query logs
        if self.log_analysis_mcp:
            analysis_result = await self.log_analysis_mcp.call_skill("analyze_pattern", {
                "pattern": pattern,
                "time_range": time_range,
            })
            
            if analysis_result.get("success"):
                anomalies = analysis_result.get("anomalies", [])
                summary = analysis_result.get("summary", {})
                
                return {
                    "success": True,
                    "pattern": pattern,
                    "anomalies": anomalies,
                    "summary": summary,
                    "hunter": self.id,
                }
        
        return {
            "success": False,
            "error": "Log analysis MCP not available",
        }


class ReviewerAgent(Agent):
    """
    Reviewer Agent - Independent verification of high-impact actions.
    Reviews and validates recommendations from other agents.
    """
    
    def __init__(
        self,
        name: str = "ReviewerAgent",
        memory_ref: Optional[UMBAdapter] = None,
    ):
        super().__init__(
            name=name,
            skills=["review", "verification", "validation"],
            memory_ref=memory_ref,
        )
        self.role = "reviewer"
    
    async def review_recommendation(
        self,
        recommendation: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Review and validate a recommendation.
        
        Args:
            recommendation: Recommendation to review
            context: Context information
            
        Returns:
            Review result with approval/rejection
        """
        # Review logic (in production would use more sophisticated methods)
        risk_level = recommendation.get("risk_level", "low")
        action = recommendation.get("action", "")
        
        # High-risk actions require more scrutiny
        if risk_level in ["high", "critical"]:
            if action in ["isolate_host", "revoke_credentials"]:
                # Require additional verification
                approved = context.get("verified", False)
            else:
                approved = True
        else:
            approved = True
        
        review_result = {
            "recommendation_id": recommendation.get("id", str(uuid.uuid4())),
            "approved": approved,
            "reviewer": self.id,
            "reasoning": "Risk assessment and action validation",
            "timestamp": context.get("timestamp"),
        }
        
        # Store review
        if self.memory_ref:
            await self.memory_ref.upsert({
                "text": f"Review result: {review_result}",
                "metadata": {
                    "author_agent": self.id,
                    "permission_level": "squad_shared",
                    "type": "review_result",
                }
            })
        
        return {
            "success": True,
            "review": review_result,
        }

