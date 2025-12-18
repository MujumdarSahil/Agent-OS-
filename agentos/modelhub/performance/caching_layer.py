"""
Caching Layer - Cache embeddings and model outputs to save cost
"""

import logging
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CachingLayer:
    """
    Caching Layer - Caches embeddings and model outputs.
    
    Reduces API costs by caching frequently used queries.
    """
    
    def __init__(self, ttl_seconds: int = 3600):
        """
        Initialize Caching Layer.
        
        Args:
            ttl_seconds: Time-to-live for cache entries
        """
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl_seconds = ttl_seconds
        logger.info(f"CachingLayer initialized with TTL={ttl_seconds}s")
    
    def _hash_key(self, text: str, model_id: str) -> str:
        """Generate cache key"""
        combined = f"{model_id}:{text}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    def get(
        self,
        text: str,
        model_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached result.
        
        Args:
            text: Input text
            model_id: Model ID
            
        Returns:
            Cached result or None
        """
        key = self._hash_key(text, model_id)
        
        if key in self.cache:
            entry = self.cache[key]
            created_at = datetime.fromisoformat(entry["created_at"])
            
            if datetime.now() - created_at < timedelta(seconds=self.ttl_seconds):
                logger.info(f"Cache hit for key {key[:8]}")
                return entry["result"]
            else:
                # Expired
                del self.cache[key]
        
        return None
    
    def set(
        self,
        text: str,
        model_id: str,
        result: Dict[str, Any]
    ):
        """
        Cache result.
        
        Args:
            text: Input text
            model_id: Model ID
            result: Result to cache
        """
        key = self._hash_key(text, model_id)
        
        self.cache[key] = {
            "result": result,
            "created_at": datetime.now().isoformat(),
            "text": text[:100],  # Store preview
            "model_id": model_id,
        }
        
        logger.info(f"Cached result for key {key[:8]}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "cache_size": len(self.cache),
            "ttl_seconds": self.ttl_seconds,
        }

