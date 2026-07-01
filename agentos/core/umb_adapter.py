"""
UMB (Unified Memory Bus) Adapter - Pluggable memory layer with vector search
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid


class MemoryPermission(Enum):
    """Memory permission levels"""
    SQUAD_SHARED = "squad_shared"
    MISSION_SCOPED = "mission_scoped"
    AGENT_PRIVATE = "agent_private"
    EPISODIC = "episodic"
    AUTOBIOGRAPHICAL = "autobiographical"


@dataclass
class MemoryEntry:
    """Memory entry with vector, text, and metadata"""
    id: str
    text: str
    vector: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "vector": self.vector,
            "metadata": self.metadata,
        }


class SimpleVectorStore:
    """
    Simple in-memory vector store for MVP.
    Can be replaced with FAISS, Chroma, or PG vector extension.
    """
    
    def __init__(self):
        self.entries: Dict[str, MemoryEntry] = {}
        self.vectors: Dict[str, List[float]] = {}
    
    def add(self, entry: MemoryEntry):
        """Add a memory entry"""
        self.entries[entry.id] = entry
        if entry.vector:
            self.vectors[entry.id] = entry.vector
    
    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """Get a memory entry by ID"""
        return self.entries.get(entry_id)
    
    def search(
        self,
        query_vector: List[float],
        top_k: int = 10,
        filter_func: Optional[callable] = None
    ) -> List[tuple]:
        """
        Simple cosine similarity search.
        
        Args:
            query_vector: Query vector
            top_k: Number of results
            filter_func: Optional filter function
            
        Returns:
            List of (entry_id, similarity_score) tuples
        """
        if not query_vector:
            return []
        
        results = []
        
        for entry_id, vector in self.vectors.items():
            entry = self.entries.get(entry_id)
            if not entry:
                continue
            
            # Apply filter if provided
            if filter_func and not filter_func(entry):
                continue
            
            # Simple cosine similarity
            similarity = self._cosine_similarity(query_vector, vector)
            results.append((entry_id, similarity))
        
        # Sort by similarity (descending)
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Compute cosine similarity between two vectors"""
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = sum(a * a for a in vec1) ** 0.5
        magnitude2 = sum(b * b for b in vec2) ** 0.5
        
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
        
        return dot_product / (magnitude1 * magnitude2)
    
    def remove(self, entry_id: str):
        """Remove a memory entry"""
        if entry_id in self.entries:
            del self.entries[entry_id]
        if entry_id in self.vectors:
            del self.vectors[entry_id]


class UMBAdapter:
    """
    Unified Memory Bus Adapter - Pluggable memory layer supporting multiple backends.
    """
    
    def __init__(
        self,
        backend: str = "simple",
        embedding_func: Optional[callable] = None,
        **backend_kwargs
    ):
        """
        Initialize UMB adapter.
        
        Args:
            backend: Backend type ("simple", "faiss", "chroma", "pgvector")
            embedding_func: Function to generate embeddings from text
            **backend_kwargs: Backend-specific configuration
        """
        self.backend_type = backend
        self.embedding_func = embedding_func or self._default_embedding
        
        # Initialize backend
        if backend == "simple":
            self.store = SimpleVectorStore()
        elif backend == "faiss":
            # TODO: Implement FAISS backend
            self.store = SimpleVectorStore()
        elif backend == "chroma":
            # TODO: Implement Chroma backend
            self.store = SimpleVectorStore()
        else:
            self.store = SimpleVectorStore()
    
    def _default_embedding(self, text: str) -> List[float]:
        """
        Default embedding function (simple hash-based for MVP).
        Replace with actual embedding model in production.
        """
        # Simple hash-based embedding (not semantic, but works for MVP)
        import hashlib
        hash_obj = hashlib.md5(text.encode())
        hash_hex = hash_obj.hexdigest()
        # Convert to 128-dim vector (16 bytes * 8)
        vector = [int(hash_hex[i:i+2], 16) / 255.0 for i in range(0, 32, 2)]
        # Pad to 128 dimensions
        while len(vector) < 128:
            vector.extend([0.0] * (128 - len(vector)))
        return vector[:128]
    
    async def upsert(self, entry: Dict[str, Any]) -> str:
        """
        Upsert a memory entry.
        
        Args:
            entry: Memory entry dict with text, metadata, optional vector
            
        Returns:
            Entry ID
        """
        entry_id = entry.get("id") or str(uuid.uuid4())
        text = entry.get("text", "")
        vector = entry.get("vector")
        metadata = entry.get("metadata", {})
        
        # Generate vector if not provided
        if not vector:
            vector = self.embedding_func(text)
        
        # Create memory entry
        memory_entry = MemoryEntry(
            id=entry_id,
            text=text,
            vector=vector,
            metadata=metadata,
        )
        
        # Store
        self.store.add(memory_entry)
        
        return entry_id
    
    async def query(
        self,
        query_text: str,
        scope: List[str] = None,
        top_k: int = 10,
        permission_level: Optional[MemoryPermission] = None,
        mission_id: Optional[str] = None,
        agent_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Query memory with semantic search.
        
        Args:
            query_text: Query text
            scope: Scope filters (['squad', 'mission', 'agent'])
            permission_level: Permission level filter
            mission_id: Mission ID for mission-scoped queries
            agent_id: Agent ID for agent-private queries
            top_k: Number of results
            
        Returns:
            List of matching memory entries
        """
        # Generate query vector
        query_vector = self.embedding_func(query_text)
        
        # Build filter function
        def filter_func(entry: MemoryEntry) -> bool:
            meta = entry.metadata
            
            # Scope filtering
            if scope:
                entry_scope = meta.get("permission_level", "agent_private")
                if "squad" in scope and entry_scope != "squad_shared":
                    if "mission" not in scope or entry_scope != "mission_scoped":
                        if "agent" not in scope:
                            return False
                
                if "mission" in scope:
                    if entry_scope == "mission_scoped":
                        if mission_id and meta.get("mission_id") != mission_id:
                            return False
                    elif entry_scope != "squad_shared":
                        if "agent" not in scope:
                            return False
                
                if "agent" in scope:
                    if entry_scope == "agent_private":
                        if agent_id and meta.get("author_agent") != agent_id:
                            return False
            
            # Permission level filtering
            if permission_level:
                entry_perm = meta.get("permission_level")
                if entry_perm != permission_level.value:
                    return False
            
            # Mission filtering
            if mission_id:
                entry_mission = meta.get("mission_id")
                if entry_mission and entry_mission != mission_id:
                    return False
            
            # Agent filtering
            if agent_id:
                entry_agent = meta.get("author_agent")
                if entry_agent and entry_agent != agent_id:
                    # Allow squad-shared and mission-scoped
                    entry_perm = meta.get("permission_level")
                    if entry_perm not in ["squad_shared", "mission_scoped"]:
                        return False
            
            return True
        
        # Search
        results = self.store.search(query_vector, top_k=top_k, filter_func=filter_func)
        
        # Format results
        formatted_results = []
        for entry_id, similarity in results:
            entry = self.store.get(entry_id)
            if entry:
                formatted_results.append({
                    "id": entry.id,
                    "text": entry.text,
                    "metadata": entry.metadata,
                    "similarity": similarity,
                })
        
        return formatted_results
    
    async def revoke(self, entry_id: str) -> bool:
        """
        Revoke/delete a memory entry (for GDPR-like flows).
        
        Args:
            entry_id: Entry ID to revoke
            
        Returns:
            True if revoked successfully
        """
        entry = self.store.get(entry_id)
        if entry:
            self.store.remove(entry_id)
            return True
        return False
    
    async def get(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a memory entry by ID"""
        entry = self.store.get(entry_id)
        if entry:
            return entry.to_dict()
        return None
    
    def clear(self, scope: Optional[str] = None):
        """
        Clear memory entries (for testing or cleanup).
        
        Args:
            scope: Optional scope to clear (e.g., "mission", "agent")
        """
        if scope:
            # Clear entries matching scope
            to_remove = []
            for entry_id, entry in self.store.entries.items():
                meta = entry.metadata
                if scope == "mission" and meta.get("permission_level") == "mission_scoped":
                    to_remove.append(entry_id)
                elif scope == "agent" and meta.get("permission_level") == "agent_private":
                    to_remove.append(entry_id)
            
            for entry_id in to_remove:
                self.store.remove(entry_id)
        else:
            # Clear all
            self.store = SimpleVectorStore()

