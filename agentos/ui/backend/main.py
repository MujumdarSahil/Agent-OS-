"""
FastAPI Backend - Main API server for AgentOS UI
"""

import logging
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="AgentOS API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API token validation (stub)
async def verify_token(authorization: str = Header(None)):
    """Verify API token"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    return authorization.replace("Bearer ", "")


# Request models
class TrainingJobRequest(BaseModel):
    dataset_path: str
    model_id: str
    hyperparams: Optional[Dict[str, Any]] = None


class LoRAJobRequest(BaseModel):
    base_model: str
    dataset: str
    rank: int = 8
    epochs: int = 3


class QuantizeRequest(BaseModel):
    model_id: str
    method: str = "gptq"


# Endpoints
@app.get("/api/models")
async def list_models(token: str = Depends(verify_token)):
    """List registered models"""
    try:
        from agentos.modelhub.llm_connector import LLMConnector
        
        # Stub: would get from actual model registry
        models = [
            {
                "model_id": "gpt-3.5-turbo",
                "provider": "openai",
                "backend": "api",
                "quantized": False,
                "size": "175B",
            },
            {
                "model_id": "claude-3-opus",
                "provider": "claude",
                "backend": "api",
                "quantized": False,
                "size": "unknown",
            },
        ]
        
        return {"success": True, "models": models}
    
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/models/{model_id}/train/sft")
async def start_sft_job(
    model_id: str,
    request: TrainingJobRequest,
    token: str = Depends(verify_token)
):
    """Start SFT training job"""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator
        from agentos.core.governance import GovernanceEngine
        
        # Governance check
        governance = GovernanceEngine()
        governance.initialize_security_policies()
        
        decision = await governance.check(
            agent_id="ui_user",
            action="start_training",
            context={
                "model_id": model_id,
                "job_type": "sft",
                "dataset_path": request.dataset_path,
            }
        )
        
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason)
        
        orchestrator = TrainingOrchestrator()
        job_id = orchestrator.start_sft_job(
            dataset_path=request.dataset_path,
            model_id=model_id,
            hyperparams=request.hyperparams
        )
        
        return {"success": True, "job_id": job_id}
    
    except Exception as e:
        logger.error(f"Error starting SFT job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/models/{model_id}/train/lora")
async def start_lora_job(
    model_id: str,
    request: LoRAJobRequest,
    token: str = Depends(verify_token)
):
    """Start LoRA training job"""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator
        from agentos.core.governance import GovernanceEngine
        
        # Governance check
        governance = GovernanceEngine()
        governance.initialize_security_policies()
        
        decision = await governance.check(
            agent_id="ui_user",
            action="start_training",
            context={
                "model_id": model_id,
                "job_type": "lora",
            }
        )
        
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason)
        
        orchestrator = TrainingOrchestrator()
        job_id = orchestrator.start_lora_job(
            base_model=request.base_model,
            dataset=request.dataset,
            rank=request.rank,
            epochs=request.epochs
        )
        
        return {"success": True, "job_id": job_id}
    
    except Exception as e:
        logger.error(f"Error starting LoRA job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/models/{model_id}/quantize")
async def start_quantization_job(
    model_id: str,
    request: QuantizeRequest,
    token: str = Depends(verify_token)
):
    """Start quantization job"""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator
        
        orchestrator = TrainingOrchestrator()
        job_id = orchestrator.start_quantization_job(
            model_id=model_id,
            method=request.method
        )
        
        return {"success": True, "job_id": job_id}
    
    except Exception as e:
        logger.error(f"Error starting quantization job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/models/{model_id}/status")
async def get_job_status(model_id: str, token: str = Depends(verify_token)):
    """Get job statuses for model"""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator
        
        orchestrator = TrainingOrchestrator()
        # Stub: would get actual job statuses
        return {
            "success": True,
            "jobs": [],
            "model_id": model_id,
        }
    
    except Exception as e:
        logger.error(f"Error getting job status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/modelhub/metrics")
async def get_modelhub_metrics(token: str = Depends(verify_token)):
    """Get ModelHub metrics"""
    try:
        from agentos.modelhub.llm_connector import LLMConnector
        
        # Stub metrics
        return {
            "success": True,
            "metrics": {
                "total_tokens": 1000,
                "total_calls": 50,
                "cache_hit_rate": 0.3,
                "average_latency": 0.5,
            }
        }
    
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools")
async def list_tools(token: str = Depends(verify_token)):
    """List available tools"""
    try:
        from agentos.dmsg.registry import MCPRegistry
        
        registry = MCPRegistry()
        tools = []
        
        for mcp_id, mcp_node in registry.mcp_nodes.items():
            for skill in mcp_node.skills:
                tools.append({
                    "tool_id": skill.id,
                    "name": skill.name,
                    "description": skill.description,
                    "mcp_id": mcp_id,
                    "domain": mcp_node.domain,
                })
        
        return {"success": True, "tools": tools}
    
    except Exception as e:
        logger.error(f"Error listing tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/{tool_id}/invoke")
async def invoke_tool(
    tool_id: str,
    params: Dict[str, Any],
    token: str = Depends(verify_token)
):
    """Invoke a tool with governance checks"""
    try:
        from agentos.core.governance import GovernanceEngine
        
        # Governance check
        governance = GovernanceEngine()
        governance.initialize_security_policies()
        
        decision = await governance.check(
            agent_id="ui_user",
            action="tool_call",
            context={
                "tool_id": tool_id,
                "params": params,
            }
        )
        
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason)
        
        # Stub: would actually invoke tool
        return {
            "success": True,
            "tool_id": tool_id,
            "result": {"status": "executed"},
        }
    
    except Exception as e:
        logger.error(f"Error invoking tool: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "AgentOS API", "version": "1.0.0"}

