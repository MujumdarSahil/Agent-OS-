"""
Sandbox Analysis Agent - Submits files to Sandbox MCP, summarizes malware behaviors
"""

from typing import Dict, Any, Optional
from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter


class SandboxAnalysisAgent(Agent):
    """
    Sandbox Analysis Agent - Malware and artifact analysis.
    Submits files to Sandbox MCP and summarizes behaviors.
    """
    
    def __init__(
        self,
        name: str = "SandboxAnalysisAgent",
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
    
    async def analyze_artifact(self, artifact_hash: str, artifact_type: str = "file", file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Submit artifact for sandbox analysis.
        
        Args:
            artifact_hash: Hash of the artifact
            artifact_type: Type of artifact (file, url, email)
            file_path: Optional file path
            
        Returns:
            Analysis results
        """
        if not self.sandbox_mcp:
            return {"success": False, "error": "Sandbox MCP not available"}
        
        # Submit to sandbox
        submit_params = {
            "file_hash": artifact_hash,
            "artifact_type": artifact_type,
        }
        if file_path:
            submit_params["file_path"] = file_path
        
        analysis_result = await self.sandbox_mcp.call_skill("submit_file", submit_params)
        
        if not analysis_result.get("success"):
            return analysis_result
        
        analysis_id = analysis_result["analysis_id"]
        
        # Get analysis results
        get_result = await self.sandbox_mcp.call_skill("get_analysis", {
            "analysis_id": analysis_id,
        })
        
        if not get_result.get("success"):
            return get_result
        
        analysis = get_result["analysis"]
        behavior_summary = analysis.get("behavior_summary", {})
        network_indicators = analysis.get("network_indicators", [])
        risk_level = analysis.get("risk_level", "unknown")
        
        # Summarize behavior
        summary = {
            "artifact_hash": artifact_hash,
            "artifact_type": artifact_type,
            "analysis_id": analysis_id,
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

