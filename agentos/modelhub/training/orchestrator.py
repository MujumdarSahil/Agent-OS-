"""
Training Orchestrator - Orchestrates SFT, LoRA, QLoRA, and quantization jobs
"""

import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from agentos.core.umb_adapter import UMBAdapter

logger = logging.getLogger(__name__)


class TrainingOrchestrator:
    """
    Training Orchestrator - Manages training and quantization jobs.
    
    Jobs write metadata to storage and push status updates to UMB & UI.
    """
    
    def __init__(self, umb_adapter: Optional[UMBAdapter] = None):
        """
        Initialize Training Orchestrator.
        
        Args:
            umb_adapter: UMB adapter for status updates
        """
        self.umb_adapter = umb_adapter
        self.jobs: Dict[str, Dict[str, Any]] = {}
        logger.info("TrainingOrchestrator initialized")
    
    def start_sft_job(
        self,
        dataset_path: str,
        model_id: str,
        hyperparams: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Start Supervised Fine-Tuning (SFT) job.
        
        Args:
            dataset_path: Path to training dataset
            model_id: Base model ID
            hyperparams: Training hyperparameters
            
        Returns:
            Job ID
        """
        job_id = f"sft_{uuid.uuid4().hex[:8]}"
        hyperparams = hyperparams or {}
        
        job = {
            "job_id": job_id,
            "job_type": "sft",
            "status": "queued",
            "dataset_path": dataset_path,
            "model_id": model_id,
            "hyperparams": hyperparams,
            "created_at": datetime.now().isoformat(),
            "progress": 0.0,
        }
        
        self.jobs[job_id] = job
        self._update_job_status(job_id, "queued")
        
        logger.info(f"SFT job started: {job_id} for model {model_id}")
        return job_id
    
    def start_lora_job(
        self,
        base_model: str,
        dataset: str,
        rank: int = 8,
        epochs: int = 3
    ) -> str:
        """
        Start LoRA (Low-Rank Adaptation) job.
        
        Args:
            base_model: Base model identifier
            dataset: Dataset path or identifier
            rank: LoRA rank
            epochs: Training epochs
            
        Returns:
            Job ID
        """
        job_id = f"lora_{uuid.uuid4().hex[:8]}"
        
        job = {
            "job_id": job_id,
            "job_type": "lora",
            "status": "queued",
            "base_model": base_model,
            "dataset": dataset,
            "rank": rank,
            "epochs": epochs,
            "created_at": datetime.now().isoformat(),
            "progress": 0.0,
        }
        
        self.jobs[job_id] = job
        self._update_job_status(job_id, "queued")
        
        logger.info(f"LoRA job started: {job_id} for model {base_model}")
        return job_id
    
    def start_qlora_job(
        self,
        base_model: str,
        dataset: str,
        rank: int = 8,
        epochs: int = 3,
        bits: int = 4
    ) -> str:
        """
        Start QLoRA (Quantized LoRA) job.
        
        Uses bitsandbytes + QLoRA flow.
        
        Args:
            base_model: Base model identifier
            dataset: Dataset path
            rank: LoRA rank
            epochs: Training epochs
            bits: Quantization bits (4 or 8)
            
        Returns:
            Job ID
        """
        job_id = f"qlora_{uuid.uuid4().hex[:8]}"
        
        job = {
            "job_id": job_id,
            "job_type": "qlora",
            "status": "queued",
            "base_model": base_model,
            "dataset": dataset,
            "rank": rank,
            "epochs": epochs,
            "bits": bits,
            "created_at": datetime.now().isoformat(),
            "progress": 0.0,
        }
        
        self.jobs[job_id] = job
        self._update_job_status(job_id, "queued")
        
        logger.info(f"QLoRA job started: {job_id} for model {base_model}")
        return job_id
    
    def start_quantization_job(
        self,
        model_id: str,
        method: str = "gptq"
    ) -> str:
        """
        Start quantization job (GPTQ/AWQ/SmoothQuant).
        
        Args:
            model_id: Model ID to quantize
            method: Quantization method (gptq, awq, smoothquant)
            
        Returns:
            Job ID
        """
        job_id = f"quant_{uuid.uuid4().hex[:8]}"
        
        job = {
            "job_id": job_id,
            "job_type": "quantization",
            "status": "queued",
            "model_id": model_id,
            "method": method,
            "created_at": datetime.now().isoformat(),
            "progress": 0.0,
        }
        
        self.jobs[job_id] = job
        self._update_job_status(job_id, "queued")
        
        logger.info(f"Quantization job started: {job_id} for model {model_id} using {method}")
        return job_id
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        return self.jobs.get(job_id)
    
    def _update_job_status(self, job_id: str, status: str, progress: float = 0.0):
        """Update job status and push to UMB"""
        if job_id in self.jobs:
            self.jobs[job_id]["status"] = status
            self.jobs[job_id]["progress"] = progress
            self.jobs[job_id]["updated_at"] = datetime.now().isoformat()
            
            # Push to UMB if available
            if self.umb_adapter:
                try:
                    self.umb_adapter.upsert({
                        "id": f"training_job_{job_id}",
                        "text": f"Training job {job_id}: {status}",
                        "vector": [],
                        "metadata": {
                            "job_id": job_id,
                            "status": status,
                            "progress": progress,
                            "timestamp": datetime.now().isoformat(),
                        }
                    })
                except Exception as e:
                    logger.warning(f"Failed to update UMB: {e}")

