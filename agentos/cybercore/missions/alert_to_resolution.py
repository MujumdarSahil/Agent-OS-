"""
Alert to Resolution Mission
Pipeline: triage_agent → investigator_agent → sandbox_analysis_agent → compliance_agent
"""

from typing import Dict, Any
from agentos.core.squad import Squad
from agentos.core.planner import Planner, TaskGraph


class AlertToResolutionMission:
    """Alert to Resolution Mission"""
    
    @staticmethod
    async def execute(squad: Squad, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute alert to resolution mission.
        
        Args:
            squad: Squad with triage, investigator, sandbox, and compliance agents
            alert: Security alert
            
        Returns:
            Mission results
        """
        results = {
            "alert_id": alert.get("id"),
            "steps": [],
            "final_status": "pending",
        }
        
        # Step 1: Triage
        triage_agent = None
        for agent in squad.agents.values():
            if hasattr(agent, "role") and agent.role == "triage":
                triage_agent = agent
                break
        
        if not triage_agent:
            # Try to find by name
            for agent in squad.agents.values():
                if hasattr(agent, "role") and agent.role == "triage":
                    triage_agent = agent
                    break
        
        if triage_agent and hasattr(triage_agent, "triage_alert"):
            triage_result = await triage_agent.triage_alert(alert)
            results["steps"].append({
                "step": "triage",
                "result": triage_result,
            })
        
        # Step 2: Investigate
        investigator_agent = None
        for agent in squad.agents.values():
            if hasattr(agent, "role") and agent.role == "investigator":
                investigator_agent = agent
                break
        
        if investigator_agent and hasattr(investigator_agent, "investigate"):
            alert_id = alert.get("id", "unknown")
            investigation = await investigator_agent.investigate(alert_id, "security alert")
            results["steps"].append({
                "step": "investigation",
                "result": investigation,
            })
        
        # Step 3: Sandbox analysis (if artifact found)
        sandbox_agent = None
        for agent in squad.agents.values():
            if hasattr(agent, "role") and agent.role == "sandbox_analyst":
                sandbox_agent = agent
                break
        
        if sandbox_agent and hasattr(sandbox_agent, "analyze_artifact"):
            # Check if there's an artifact to analyze
            artifact_hash = alert.get("file_hash")
            if artifact_hash:
                analysis = await sandbox_agent.analyze_artifact(artifact_hash)
                results["steps"].append({
                    "step": "sandbox_analysis",
                    "result": analysis,
                })
        
        results["final_status"] = "completed"
        return results

