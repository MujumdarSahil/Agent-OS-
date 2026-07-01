"""
Chroma Adapter - ChromaDB vector database adapter
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ChromaAdapter:
    """
    Chroma Adapter - Interface for ChromaDB.
    
    Implements index_documents, search, and delete operations.
    """
    
    def __init__(self, collection_name: str = "agentos_docs"):
        """
        Initialize Chroma adapter.
        
        Args:
            collection_name: Chroma collection name
        """
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        logger.info(f"ChromaAdapter initialized with collection {collection_name}")
    
    def _get_collection(self):
        """Get or create Chroma collection"""
        try:
            import chromadb
            
            if not self.client:
                self.client = chromadb.Client()
            
            if not self.collection:
                self.collection = self.client.get_or_create_collection(
                    name=self.collection_name
                )
            
            return self.collection
        
        except ImportError:
            logger.warning("ChromaDB not available, using stub implementation")
            return None
    
    def index_documents(self, docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Index documents in ChromaDB.
        
        Args:
            docs: List of documents with 'id', 'vector', 'text', 'metadata'
            
        Returns:
            Indexing result
        """
        collection = self._get_collection()
        if not collection:
            return {
                "success": False,
                "error": "ChromaDB not available",
            }
        
        try:
            ids = []
            embeddings = []
            documents = []
            metadatas = []
            
            for doc in docs:
                ids.append(doc.get("id"))
                embeddings.append(doc.get("vector", []))
                documents.append(doc.get("text", ""))
                metadatas.append(doc.get("metadata", {}))
            
            collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas
            )
            
            return {
                "success": True,
                "indexed_count": len(ids),
            }
        
        except Exception as e:
            logger.error(f"Error indexing documents: {e}")
            return {
                "success": False,
                "error": str(e),
            }
    
    def search(self, query: List[float], top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar documents.
        
        Args:
            query: Query vector
            top_k: Number of results
            
        Returns:
            List of similar documents
        """
        collection = self._get_collection()
        if not collection:
            return []
        
        try:
            results = collection.query(
                query_embeddings=[query],
                n_results=top_k
            )
            
            formatted_results = []
            for i in range(len(results.get("ids", [[]])[0])):
                formatted_results.append({
                    "doc_id": results["ids"][0][i],
                    "text": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                    "score": results["distances"][0][i] if results.get("distances") else 0.0,
                })
            
            return formatted_results
        
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
        collection = self._get_collection()
        if not collection:
            return False
        
        try:
            collection.delete(ids=[doc_id])
            return True
        except Exception as e:
            logger.error(f"Error deleting document: {e}")
            return False

