"""
CAG - Context-Augmented Generation

Augments prompts with context before sending to models.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CAG:
    """
    Context-Augmented Generation - Augments prompts with context.
    
    Integrates with ModelHub connector to send augmented prompts.
    """
    
    @staticmethod
    def augment_prompt_with_context(
        prompt: str,
        context_docs: List[Dict[str, Any]],
        max_context_length: int = 2000
    ) -> Dict[str, Any]:
        """
        Augment prompt with context documents.
        
        Args:
            prompt: Original prompt
            context_docs: List of context documents
            max_context_length: Maximum context length in characters
            
        Returns:
            Augmented prompt dictionary
        """
        if not context_docs:
            return {
                "augmented_prompt": prompt,
                "context_used": False,
                "context_docs_count": 0,
            }
        
        # Build context text
        context_parts = []
        current_length = 0
        
        for doc in context_docs:
            doc_text = doc.get("text", "")
            if current_length + len(doc_text) > max_context_length:
                break
            
            context_parts.append(doc_text)
            current_length += len(doc_text)
        
        context_text = "\n\n---\n\n".join(context_parts)
        
        # Augment prompt
        augmented_prompt = f"""Context Information:
{context_text}

---
User Query: {prompt}

Please provide a response using the context information above."""
        
        return {
            "augmented_prompt": augmented_prompt,
            "context_used": True,
            "context_docs_count": len(context_parts),
            "original_prompt": prompt,
            "context_length": current_length,
        }
    
    @staticmethod
    def prepare_for_modelhub(
        augmented_prompt: str,
        model_id: str,
        additional_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Prepare augmented prompt for ModelHub connector.
        
        Args:
            augmented_prompt: Augmented prompt text
            model_id: Model ID
            additional_params: Additional parameters
            
        Returns:
            ModelHub request dictionary
        """
        request = {
            "prompt": augmented_prompt,
            "model_id": model_id,
            "parameters": additional_params or {},
            "augmented": True,
        }
        
        return request

