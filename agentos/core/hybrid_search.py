"""
Hybrid Search - Combine vector and keyword DSL queries
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class HybridSearch:
    """
    Hybrid Search - Combines vector similarity and keyword search.
    """
    
    @staticmethod
    def hybrid_search(
        query: str,
        query_vector: List[float],
        vector_results: List[Dict[str, Any]],
        keyword_results: List[Dict[str, Any]],
        vector_weight: float = 0.7,
        keyword_weight: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Combine vector and keyword search results.
        
        Args:
            query: Original query text
            query_vector: Query vector
            vector_results: Results from vector search
            keyword_results: Results from keyword search
            vector_weight: Weight for vector results
            keyword_weight: Weight for keyword results
            
        Returns:
            Combined and ranked results
        """
        # Create result map
        result_map = {}
        
        # Add vector results
        for i, result in enumerate(vector_results):
            doc_id = result.get("doc_id", f"vec_{i}")
            if doc_id not in result_map:
                result_map[doc_id] = {
                    "doc_id": doc_id,
                    "text": result.get("text", ""),
                    "metadata": result.get("metadata", {}),
                    "vector_score": result.get("score", 0.0),
                    "keyword_score": 0.0,
                }
            else:
                result_map[doc_id]["vector_score"] = result.get("score", 0.0)
        
        # Add keyword results
        for i, result in enumerate(keyword_results):
            doc_id = result.get("doc_id", f"kw_{i}")
            if doc_id not in result_map:
                result_map[doc_id] = {
                    "doc_id": doc_id,
                    "text": result.get("text", ""),
                    "metadata": result.get("metadata", {}),
                    "vector_score": 0.0,
                    "keyword_score": result.get("score", 1.0 / (i + 1)),
                }
            else:
                result_map[doc_id]["keyword_score"] = result.get("score", 1.0 / (i + 1))
        
        # Calculate hybrid scores
        combined_results = []
        for doc_id, result in result_map.items():
            hybrid_score = (
                vector_weight * result["vector_score"] +
                keyword_weight * result["keyword_score"]
            )
            result["hybrid_score"] = hybrid_score
            combined_results.append(result)
        
        # Sort by hybrid score
        combined_results.sort(key=lambda x: x["hybrid_score"], reverse=True)
        
        return combined_results

