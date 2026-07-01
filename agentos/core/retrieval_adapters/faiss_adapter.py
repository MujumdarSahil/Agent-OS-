"""
FAISS Adapter - FAISS vector database adapter
"""

import logging
from typing import Dict, Any, List
import numpy as np

logger = logging.getLogger(__name__)


class FAISSAdapter:
    """
    FAISS Adapter - Interface for FAISS vector database.
    
    Implements index_documents, search, and delete operations.
    """
    
    def __init__(self, dimension: int = 384):
        """
        Initialize FAISS adapter.
        
        Args:
            dimension: Vector dimension
        """
        self.dimension = dimension
        self.index = None
        self.documents = {}  # doc_id -> document
        logger.info(f"FAISSAdapter initialized with dimension {dimension}")
    
    def index_documents(self, docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Index documents.
        
        Args:
            docs: List of documents with 'id', 'vector', and 'text'
            
        Returns:
            Indexing result
        """
        try:
            import faiss
            
            if not self.index:
                # Create FAISS index
                self.index = faiss.IndexFlatL2(self.dimension)
            
            vectors = []
            for doc in docs:
                doc_id = doc.get("id")
                vector = doc.get("vector", [])
                
                if len(vector) != self.dimension:
                    logger.warning(f"Vector dimension mismatch for doc {doc_id}")
                    continue
                
                vectors.append(vector)
                self.documents[doc_id] = doc
            
            if vectors:
                vectors_array = np.array(vectors, dtype=np.float32)
                self.index.add(vectors_array)
            
            return {
                "success": True,
                "indexed_count": len(vectors),
                "total_documents": len(self.documents),
            }
        
        except ImportError:
            logger.warning("FAISS not available, using stub implementation")
            return {
                "success": False,
                "error": "FAISS not installed",
            }
        except Exception as e:
            logger.error(f"Error indexing documents: {e}")
            return {
                "success": False,
                "error": str(e),
            }
    
    def search(self, query: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar documents.
        
        Args:
            query: Query vector
            top_k: Number of results
            
        Returns:
            List of similar documents
        """
        if not self.index:
            return []
        
        try:
            if isinstance(query, list):
                query = np.array([query], dtype=np.float32)
            else:
                query = query.reshape(1, -1).astype(np.float32)
            
            distances, indices = self.index.search(query, top_k)
            
            results = []
            for i, idx in enumerate(indices[0]):
                if idx < len(self.documents):
                    doc_id = list(self.documents.keys())[idx]
                    doc = self.documents[doc_id]
                    results.append({
                        "doc_id": doc_id,
                        "text": doc.get("text", ""),
                        "metadata": doc.get("metadata", {}),
                        "score": float(distances[0][i]),
                    })
            
            return results
        
        except Exception as e:
            logger.error(f"Error searching: {e}")
            return []
    
    def delete(self, doc_id: str) -> bool:
        """
        Delete a document.
        
        Args:
            doc_id: Document ID
            
        Returns:
            True if deleted, False otherwise
        """
        if doc_id in self.documents:
            del self.documents[doc_id]
            # Note: FAISS doesn't support deletion, would need to rebuild index
            logger.warning("FAISS index deletion requires rebuild")
            return True
        return False

