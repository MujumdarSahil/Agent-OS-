"""
ModelHub LLM Connector - Safe LLM access with redaction and filtering
"""

import os
import re
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class LLMConnector:
    """
    LLM Connector - Safe access to LLMs with redaction and filtering.
    Supports OpenAI, Claude, and local models.
    """
    
    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
    ):
        """
        Initialize LLM connector.
        
        Args:
            provider: LLM provider ("openai", "claude", "local")
            model: Model name
            api_key: API key (or from .env)
        """
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        self.redaction_enabled = True
        self.quota_tracker: Dict[str, Dict[str, int]] = {}  # agent_id -> {tokens: int, calls: int}
        self.call_log: List[Dict[str, Any]] = []  # Log of model calls
        self.safety_filter_enabled = True
    
    def redact_sensitive(self, text: str) -> str:
        """
        Redact sensitive information from text.
        
        Args:
            text: Text to redact
            
        Returns:
            Redacted text
        """
        if not self.redaction_enabled:
            return text
        
        # Redact email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]', text)
        
        # Redact IP addresses
        text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]', text)
        
        # Redact credit card numbers
        text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[CARD_REDACTED]', text)
        
        # Redact SSN
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]', text)
        
        return text
    
    async def call(
        self,
        prompt: str,
        agent_id: str = "unknown",
        max_tokens: int = 1000,
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """
        Call LLM with safety controls.
        
        Args:
            prompt: Prompt text
            agent_id: Agent ID for quota tracking
            max_tokens: Maximum tokens
            temperature: Temperature setting
            
        Returns:
            LLM response
        """
        # Check quota
        if agent_id not in self.quota_tracker:
            self.quota_tracker[agent_id] = {"tokens": 0, "calls": 0}
        
        quota = self.quota_tracker[agent_id]
        if quota["tokens"] > 100000:  # Example limit
            return {
                "success": False,
                "error": "Token quota exceeded",
            }
        
        # Redact sensitive data
        redacted_prompt = self.redact_sensitive(prompt)
        
        # Call LLM (simulated - in production would call actual API)
        if self.provider == "openai":
            response = await self._call_openai(redacted_prompt, max_tokens, temperature)
        elif self.provider == "claude":
            response = await self._call_claude(redacted_prompt, max_tokens, temperature)
        elif self.provider == "local":
            response = await self._call_local(redacted_prompt, max_tokens, temperature)
        else:
            return {
                "success": False,
                "error": f"Unsupported provider: {self.provider}",
            }
        
        # Update quota
        tokens_used = response.get("tokens_used", 0)
        quota["tokens"] += tokens_used
        quota["calls"] += 1
        
        # Log model call
        call_log_entry = {
            "agent_id": agent_id,
            "model": self.model,
            "provider": self.provider,
            "tokens_used": tokens_used,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
            "prompt_length": len(prompt),
        }
        self.call_log.append(call_log_entry)
        
        # Apply safety filter if enabled
        if self.safety_filter_enabled and response.get("success"):
            response = self._apply_safety_filter(response)
        
        return response
    
    def _apply_safety_filter(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Apply safety filter to model response"""
        response_text = response.get("response", "")
        
        # Check for prohibited content
        prohibited_patterns = [
            r"exploit",
            r"malware",
            r"password.*crack",
            r"brute.*force",
        ]
        
        for pattern in prohibited_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                response["response"] = "[SAFETY FILTER: Response blocked due to prohibited content]"
                response["safety_filtered"] = True
                break
        
        return response
    
    def get_model_metadata(self) -> Dict[str, Any]:
        """Get model metadata for UI"""
        return {
            "model_id": self.model,
            "provider": self.provider,
            "backend": "api" if self.provider != "local" else "local",
            "quantized": False,  # Would check actual model
            "size": "unknown",
            "call_count": sum(q["calls"] for q in self.quota_tracker.values()),
            "total_tokens": sum(q["tokens"] for q in self.quota_tracker.values()),
        }
    
    def get_call_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent call log"""
        return self.call_log[-limit:]
    
    async def _call_openai(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Call OpenAI API (simulated)"""
        # In production, would use openai library
        tokens_used = len(prompt.split()) + max_tokens // 2
        
        return {
            "success": True,
            "response": f"OpenAI response to: {prompt[:50]}...",
            "tokens_used": tokens_used,
            "model": self.model,
            "provider": "openai",
        }
    
    async def _call_claude(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Call Claude API (simulated)"""
        tokens_used = len(prompt.split()) + max_tokens // 2
        
        return {
            "success": True,
            "response": f"Claude response to: {prompt[:50]}...",
            "tokens_used": tokens_used,
            "model": self.model,
            "provider": "claude",
        }
    
    async def _call_local(self, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
        """Call local model (simulated)"""
        tokens_used = len(prompt.split()) + max_tokens // 2
        
        return {
            "success": True,
            "response": f"Local model response to: {prompt[:50]}...",
            "tokens_used": tokens_used,
            "model": self.model,
            "provider": "local",
        }
    
    async def classify(self, text: str, categories: List[str], agent_id: str = "unknown") -> Dict[str, Any]:
        """
        Classify text using LLM.
        
        Args:
            text: Text to classify
            categories: List of categories
            agent_id: Agent ID
            
        Returns:
            Classification result
        """
        prompt = f"Classify the following text into one of these categories: {', '.join(categories)}\n\nText: {text}"
        
        result = await self.call(prompt, agent_id=agent_id, max_tokens=100)
        
        if result.get("success"):
            # Parse classification (simplified)
            response = result["response"]
            classification = {
                "label": categories[0] if categories else "unknown",
                "confidence": 0.85,
                "categories": categories,
            }
            
            return {
                "success": True,
                "classification": classification,
            }
        
        return result

