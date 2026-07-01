"""
KG-RAG - Knowledge Graph RAG hooks

Converts graph context (triples) to doc-context for RAG.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class KGRAG:
    """
    Knowledge Graph RAG - Integrates knowledge graphs with RAG.
    """
    
    @staticmethod
    def graph_to_doc_context(
        graph_context: List[Dict[str, Any]],
        format_type: str = "triples"
    ) -> List[Dict[str, Any]]:
        """
        Convert graph context (triples) to document context for RAG.
        
        Args:
            graph_context: List of graph triples or nodes
            format_type: Format of graph context (triples, nodes, edges)
            
        Returns:
            List of document contexts
        """
        doc_contexts = []
        
        if format_type == "triples":
            for triple in graph_context:
                subject = triple.get("subject", "")
                predicate = triple.get("predicate", "")
                object_ = triple.get("object", "")
                
                doc_text = f"{subject} {predicate} {object_}"
                doc_contexts.append({
                    "text": doc_text,
                    "metadata": {
                        "type": "kg_triple",
                        "subject": subject,
                        "predicate": predicate,
                        "object": object_,
                    }
                })
        
        elif format_type == "nodes":
            for node in graph_context:
                node_id = node.get("id", "")
                properties = node.get("properties", {})
                
                doc_text = f"Entity {node_id}: {properties}"
                doc_contexts.append({
                    "text": doc_text,
                    "metadata": {
                        "type": "kg_node",
                        "node_id": node_id,
                        "properties": properties,
                    }
                })
        
        logger.info(f"Converted {len(graph_context)} graph elements to {len(doc_contexts)} doc contexts")
        return doc_contexts
    
    @staticmethod
    def augment_rag_with_kg(
        rag_context: Dict[str, Any],
        kg_context: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Augment RAG context with knowledge graph context.
        
        Args:
            rag_context: RAG retrieval context
            kg_context: Knowledge graph context
            
        Returns:
            Augmented context
        """
        kg_docs = KGRAG.graph_to_doc_context(kg_context)
        
        # Combine RAG docs with KG docs
        all_docs = rag_context.get("context_docs", []) + kg_docs
        
        return {
            **rag_context,
            "context_docs": all_docs,
            "kg_docs_count": len(kg_docs),
            "total_docs_count": len(all_docs),
        }

