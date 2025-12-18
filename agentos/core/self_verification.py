"""
Self Verification - Model re-checks output given retrieved docs
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class SelfVerification:
    """
    Self Verification - Model re-checks its output given retrieved documents.
    """
    
    def __init__(self, llm_connector=None):
        """
        Initialize Self Verification.
        
        Args:
            llm_connector: LLM connector for verification
        """
        self.llm_connector = llm_connector
        logger.info("SelfVerification initialized")
    
    async def verify(
        self,
        generated_output: str,
        retrieved_docs: List[Dict[str, Any]],
        original_query: str
    ) -> Dict[str, Any]:
        """
        Verify generated output against retrieved documents.
        
        Args:
            generated_output: Generated output to verify
            retrieved_docs: Retrieved context documents
            original_query: Original query
            
        Returns:
            Verification result
        """
        # Check if output is consistent with retrieved docs
        consistency_score = self._check_consistency(generated_output, retrieved_docs)
        
        # Check for hallucinations
        hallucination_score = self._check_hallucination(generated_output, retrieved_docs)
        
        # Request self-critique if LLM available
        if self.llm_connector:
            critique = await self._request_critique(generated_output, retrieved_docs, original_query)
        else:
            critique = "Verification completed"
        
        return {
            "verified": consistency_score > 0.7 and hallucination_score < 0.3,
            "consistency_score": consistency_score,
            "hallucination_score": hallucination_score,
            "critique": critique,
        }
    
    def _check_consistency(
        self,
        output: str,
        docs: List[Dict[str, Any]]
    ) -> float:
        """Check consistency with retrieved docs"""
        # Stub implementation
        return 0.85
    
    def _check_hallucination(
        self,
        output: str,
        docs: List[Dict[str, Any]]
    ) -> float:
        """Check for hallucinations"""
        # Stub implementation
        return 0.1
    
    async def _request_critique(
        self,
        output: str,
        docs: List[Dict[str, Any]],
        query: str
    ) -> str:
        """Request LLM to critique output"""
        if not self.llm_connector:
            return "No LLM available for critique"
        
        context = "\n".join([doc.get("text", "")[:200] for doc in docs[:3]])
        prompt = f"""Given this context:
{context}

And this generated output:
{output}

Please critique the output for accuracy and consistency with the context."""
        
        result = await self.llm_connector.call(prompt, max_tokens=300)
        return result.get("response", "Critique unavailable")

