"""
PGVector Adapter - PostgreSQL with pgvector extension adapter
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class PGVectorAdapter:
    """
    PGVector Adapter - Interface for PostgreSQL with pgvector.
    
    Implements index_documents, search, and delete operations.
    """
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize PGVector adapter.
        
        Args:
            connection_string: PostgreSQL connection string
        """
        self.connection_string = connection_string
        self.connection = None
        logger.info("PGVectorAdapter initialized")
    
    def _get_connection(self):
        """Get database connection"""
        if not self.connection_string:
            logger.warning("No connection string provided for PGVector")
            return None
        
        try:
            import psycopg2
            from psycopg2.extras import execute_values
            
            if not self.connection:
                self.connection = psycopg2.connect(self.connection_string)
            
            return self.connection
        
        except ImportError:
            logger.warning("psycopg2 not available, using stub implementation")
            return None
        except Exception as e:
            logger.error(f"Error connecting to PostgreSQL: {e}")
            return None
    
    def index_documents(self, docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Index documents in PostgreSQL.
        
        Args:
            docs: List of documents with 'id', 'vector', 'text', 'metadata'
            
        Returns:
            Indexing result
        """
        conn = self._get_connection()
        if not conn:
            return {
                "success": False,
                "error": "PostgreSQL connection not available",
            }
        
        try:
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    text TEXT,
                    vector vector(384),
                    metadata JSONB
                )
            """)
            
            # Insert documents
            for doc in docs:
                cursor.execute("""
                    INSERT INTO documents (id, text, vector, metadata)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        text = EXCLUDED.text,
                        vector = EXCLUDED.vector,
                        metadata = EXCLUDED.metadata
                """, (
                    doc.get("id"),
                    doc.get("text", ""),
                    str(doc.get("vector", [])),
                    str(doc.get("metadata", {}))
                ))
            
            conn.commit()
            
            return {
                "success": True,
                "indexed_count": len(docs),
            }
        
        except Exception as e:
            logger.error(f"Error indexing documents: {e}")
            return {
                "success": False,
                "error": str(e),
            }
    
    def search(self, query: List[float], top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar documents using pgvector.
        
        Args:
            query: Query vector
            top_k: Number of results
            
        Returns:
            List of similar documents
        """
        conn = self._get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, text, metadata, vector <-> %s::vector AS distance
                FROM documents
                ORDER BY vector <-> %s::vector
                LIMIT %s
            """, (str(query), str(query), top_k))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "doc_id": row[0],
                    "text": row[1],
                    "metadata": row[2] if row[2] else {},
                    "score": float(row[3]),
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
        conn = self._get_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error deleting document: {e}")
            return False

