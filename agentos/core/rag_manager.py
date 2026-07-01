"""
RAG Manager - Retrieval-Augmented Generation integration

Provides RAG capabilities integrated with UMB and ModelHub.
"""

import logging
from typing import Dict, Any, List, Optional
from agentos.core.umb_adapter import UMBAdapter

logger = logging.getLogger(__name__)


class RAGManager:
    """
    RAG Manager - Manages retrieval-augmented generation workflows.
    
    Supports both retrieval-first and generator-first flows.
    """
    
    def __init__(self, umb_adapter: Optional[UMBAdapter] = None):
        """
        Initialize RAG Manager.
        
        Args:
            umb_adapter: UMB adapter for vector search
        """
        self.umb_adapter = umb_adapter
        logger.info("RAGManager initialized")
    
    async def create_retrieval_context(
        self,
        query: str,
        scope: str = "squad_shared",
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Create retrieval context from UMB.
        
        Args:
            query: Search query
            scope: Memory scope (squad_shared, mission_scoped, agent_private)
            top_k: Number of results to retrieve
            
        Returns:
            Retrieval context with documents
        """
        if not self.umb_adapter:
            return {
                "context_docs": [],
                "query": query,
                "scope": scope,
            }
        
        try:
            # Search UMB for relevant documents
            results = await self.umb_adapter.search(
                query=query,
                top_k=top_k,
                scope=scope
            )
            
            context_docs = []
            for result in results:
                context_docs.append({
                    "text": result.get("text", ""),
                    "metadata": result.get("metadata", {}),
                    "score": result.get("score", 0.0),
                })
            
            return {
                "context_docs": context_docs,
                "query": query,
                "scope": scope,
                "retrieval_count": len(context_docs),
            }
        
        except Exception as e:
            logger.error(f"Error creating retrieval context: {e}")
            return {
                "context_docs": [],
                "query": query,
                "scope": scope,
                "error": str(e),
            }
    
    async def run_rag(
        self,
        query: str,
        model_id: Optional[str] = None,
        top_k: int = 5,
        scope: str = "squad_shared",
        flow_type: str = "retrieval_first"
    ) -> Dict[str, Any]:
        """
        Run RAG workflow.
        
        Args:
            query: User query
            model_id: Model ID for generation (optional)
            top_k: Number of documents to retrieve
            scope: Memory scope
            flow_type: "retrieval_first" or "generator_first"
            
        Returns:
            RAG result with context and generation
        """
        # Step 1: Retrieve context
        retrieval_context = await self.create_retrieval_context(
            query=query,
            scope=scope,
            top_k=top_k
        )
        
        context_docs = retrieval_context.get("context_docs", [])
        
        # Step 2: Augment prompt with context
        if flow_type == "retrieval_first":
            # Retrieve first, then generate
            augmented_prompt = self._augment_prompt_with_context(query, context_docs)
        else:
            # Generator-first: generate initial response, then refine with context
            augmented_prompt = query
        
        result = {
            "query": query,
            "retrieval_context": retrieval_context,
            "augmented_prompt": augmented_prompt,
            "flow_type": flow_type,
            "context_docs_count": len(context_docs),
        }
        
        # If model_id provided, would call ModelHub here
        if model_id:
            result["model_id"] = model_id
            result["generation_pending"] = True
        
        logger.info(f"RAG workflow completed: {len(context_docs)} documents retrieved")
        return result
    
    def _augment_prompt_with_context(
        self,
        prompt: str,
        context_docs: List[Dict[str, Any]]
    ) -> str:
        """Augment prompt with retrieved context"""
        if not context_docs:
            return prompt
        
        context_text = "\n\n".join([
            f"Document {i+1}:\n{doc.get('text', '')}"
            for i, doc in enumerate(context_docs)
        ])
        
        augmented = f"""Context from knowledge base:
{context_text}

User query: {prompt}

Please answer the query using the provided context."""
        
        return augmented

