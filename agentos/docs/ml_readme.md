# ModelHub & ML Training Guide

## Overview

AgentOS ModelHub provides training capabilities for fine-tuning models using SFT, LoRA, QLoRA, and quantization.

## Running SFT/LoRA Locally

### Prerequisites

```bash
pip install torch transformers peft bitsandbytes
```

### CPU Fallback

For CPU-only systems, training will automatically fall back to CPU mode (slower but functional).

### Example: Start LoRA Job

```python
from agentos.modelhub.training.orchestrator import TrainingOrchestrator

orchestrator = TrainingOrchestrator()
job_id = orchestrator.start_lora_job(
    base_model="meta-llama/Llama-2-7b-hf",
    dataset="path/to/dataset.json",
    rank=8,
    epochs=3
)

# Check status
status = orchestrator.get_job_status(job_id)
print(f"Job {job_id}: {status['status']}")
```

## Quantization Utils

### GPTQ Quantization

```python
from agentos.modelhub.training.quantize_utils import QuantizeUtils

result = QuantizeUtils.quantize_model(
    model_id="model-name",
    method="gptq",
    bits=4
)
```

### Safety Considerations

- Quantization is for optimization only
- No model modification for malicious purposes
- All operations logged with safety_metadata

## Safety Considerations

1. **Training Data**: Ensure training datasets are ethical and legal
2. **Model Outputs**: All model outputs pass through safety filters
3. **Resource Limits**: Training jobs respect resource quotas
4. **Governance**: All training operations require governance approval

## Local GPU Support

For GPU-accelerated training:

1. Install CUDA-compatible PyTorch
2. Ensure GPU drivers are installed
3. Training will automatically use GPU if available

## Heavy Jobs

Heavy training jobs should be run on dedicated infrastructure. The framework supports external job orchestration.

