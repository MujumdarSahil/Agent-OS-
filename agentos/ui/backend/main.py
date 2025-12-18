"""
FastAPI Backend - Main API server and Python-only UI for AgentOS
"""

import logging
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from agentos.core.agent import Agent
from agentos.core.umb_adapter import UMBAdapter
from agentos.dmsg.registry import MCPRegistry

logger = logging.getLogger(__name__)

# In-memory registries for simple UI control
AGENTS: Dict[str, Agent] = {}
TASKS: Dict[str, Dict[str, Any]] = {}
TOOLS: Dict[str, Dict[str, Any]] = {}

# Shared memory bus for agents created via UI
UMB = UMBAdapter(backend="simple")


# Initialize FastAPI app
app = FastAPI(title="AgentOS API", version="1.0.0")

# Templates for Python-only UI
templates = Jinja2Templates(directory="agentos/ui/backend/templates")


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


@app.get("/ui", response_class=HTMLResponse)
async def ui_home(request: Request):
    """Render the main Python-only UI for managing agents, tools, and tasks."""
    registry = MCPRegistry()
    mcp_summaries: List[Dict[str, Any]] = []
    for mcp_id, mcp_node in registry.mcp_nodes.items():
        mcp_summaries.append(
            {
                "id": mcp_id,
                "name": getattr(mcp_node, "name", mcp_id),
                "domain": getattr(mcp_node, "domain", "unknown"),
                "skill_count": len(getattr(mcp_node, "skills", [])),
            }
        )

    return templates.TemplateResponse(
        "ui.html",
        {
            "request": request,
            "agents": AGENTS,
            "tasks": TASKS,
            "tools": TOOLS,
            "mcps": mcp_summaries,
        },
    )


@app.post("/ui/agents")
async def ui_create_agent(
    name: str = Form(...),
    roles: str = Form(""),
    skills: str = Form(""),
):
    """Create an AgentOS Agent from the UI."""
    role_list = [r.strip() for r in roles.split(",") if r.strip()]
    skill_list = [s.strip() for s in skills.split(",") if s.strip()]

    agent = Agent(
        name=name,
        roles=role_list,
        skills=skill_list,
        memory_ref=UMB,
    )
    AGENTS[agent.id] = agent

    return RedirectResponse(url="/ui", status_code=303)


@app.post("/ui/tools")
async def ui_register_tool(
    name: str = Form(...),
    description: str = Form(""),
):
    """Register a logical tool in the in-memory registry."""
    TOOLS[name] = {
        "name": name,
        "description": description,
    }
    return RedirectResponse(url="/ui", status_code=303)


@app.post("/ui/tasks")
async def ui_create_task(
    description: str = Form(...),
    agent_id: str = Form(""),
):
    """Create a simple task and optionally execute it with an agent."""
    task_id = f"task-{len(TASKS) + 1}"
    task: Dict[str, Any] = {
        "id": task_id,
        "description": description,
        "agent_id": agent_id or None,
        "status": "created",
        "result": None,
    }

    if agent_id and agent_id in AGENTS:
        agent = AGENTS[agent_id]
        result = await agent.execute(
            {
                "id": task_id,
                "description": description,
                "type": "generic",
            }
        )
        task["status"] = "executed" if result.get("success") else "error"
        task["result"] = result

    TASKS[task_id] = task
    return RedirectResponse(url="/ui", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint: redirect to the Python-only UI."""
    return RedirectResponse(url="/ui", status_code=302)


# ==== JSON APIs (existing programmatic interface, still Python-only) ====


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


@app.get("/api/models")
async def list_models(token: str = Depends(verify_token)):
    """List registered models (stub)."""
    try:
        from agentos.modelhub.llm_connector import LLMConnector  # noqa: F401

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
    token: str = Depends(verify_token),
):
    """Start SFT training job (stub)."""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator
        from agentos.core.governance import GovernanceEngine

        governance = GovernanceEngine()
        governance.initialize_security_policies()

        decision = await governance.check(
            agent_id="ui_user",
            action="start_training",
            context={
                "model_id": model_id,
                "job_type": "sft",
                "dataset_path": request.dataset_path,
            },
        )

        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason)

        orchestrator = TrainingOrchestrator()
        job_id = orchestrator.start_sft_job(
            dataset_path=request.dataset_path,
            model_id=model_id,
            hyperparams=request.hyperparams,
        )

        return {"success": True, "job_id": job_id}
    except Exception as e:
        logger.error(f"Error starting SFT job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/models/{model_id}/train/lora")
async def start_lora_job(
    model_id: str,
    request: LoRAJobRequest,
    token: str = Depends(verify_token),
):
    """Start LoRA training job (stub)."""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator
        from agentos.core.governance import GovernanceEngine

        governance = GovernanceEngine()
        governance.initialize_security_policies()

        decision = await governance.check(
            agent_id="ui_user",
            action="start_training",
            context={
                "model_id": model_id,
                "job_type": "lora",
            },
        )

        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason)

        orchestrator = TrainingOrchestrator()
        job_id = orchestrator.start_lora_job(
            base_model=request.base_model,
            dataset=request.dataset,
            rank=request.rank,
            epochs=request.epochs,
        )

        return {"success": True, "job_id": job_id}
    except Exception as e:
        logger.error(f"Error starting LoRA job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/models/{model_id}/quantize")
async def start_quantization_job(
    model_id: str,
    request: QuantizeRequest,
    token: str = Depends(verify_token),
):
    """Start quantization job (stub)."""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator

        orchestrator = TrainingOrchestrator()
        job_id = orchestrator.start_quantization_job(
            model_id=model_id,
            method=request.method,
        )

        return {"success": True, "job_id": job_id}
    except Exception as e:
        logger.error(f"Error starting quantization job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/models/{model_id}/status")
async def get_job_status(model_id: str, token: str = Depends(verify_token)):
    """Get job statuses for a model (stub)."""
    try:
        from agentos.modelhub.training.orchestrator import TrainingOrchestrator

        _ = TrainingOrchestrator()
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
    """Get ModelHub metrics (stub)."""
    try:
        from agentos.modelhub.llm_connector import LLMConnector  # noqa: F401

        return {
            "success": True,
            "metrics": {
                "total_tokens": 1000,
                "total_calls": 50,
                "cache_hit_rate": 0.3,
                "average_latency": 0.5,
            },
        }
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools")
async def list_tools(token: str = Depends(verify_token)):
    """List available tools from MCP registry (JSON)."""
    try:
        registry = MCPRegistry()
        tools: List[Dict[str, Any]] = []

        for mcp_id, mcp_node in registry.mcp_nodes.items():
            for skill in mcp_node.skills:
                tools.append(
                    {
                        "tool_id": skill.id,
                        "name": skill.name,
                        "description": skill.description,
                        "mcp_id": mcp_id,
                        "domain": mcp_node.domain,
                    }
                )

        return {"success": True, "tools": tools}
    except Exception as e:
        logger.error(f"Error listing tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/tools/{tool_id}/invoke")
async def invoke_tool(
    tool_id: str,
    params: Dict[str, Any],
    token: str = Depends(verify_token),
):
    """Invoke a tool with governance checks (stub)."""
    try:
        from agentos.core.governance import GovernanceEngine

        governance = GovernanceEngine()
        governance.initialize_security_policies()

        decision = await governance.check(
            agent_id="ui_user",
            action="tool_call",
            context={
                "tool_id": tool_id,
                "params": params,
            },
        )

        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason)

        return {
            "success": True,
            "tool_id": tool_id,
            "result": {"status": "executed"},
        }
    except Exception as e:
        logger.error(f"Error invoking tool: {e}")
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

