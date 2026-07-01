"""
Chunking Utilities - Semantic and layout-aware chunking strategies
"""

import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class Chunker:
    """
    Chunker - Base class for document chunking strategies.
    """
    
    @staticmethod
    def chunk_text(
        text: str,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        strategy: str = "semantic"
    ) -> List[Dict[str, Any]]:
        """
        Chunk text using specified strategy.
        
        Args:
            text: Text to chunk
            chunk_size: Maximum chunk size in characters
            chunk_overlap: Overlap between chunks
            strategy: Chunking strategy (semantic, layout, fixed)
            
        Returns:
            List of chunks with metadata
        """
        if strategy == "semantic":
            return Chunker._semantic_chunk(text, chunk_size, chunk_overlap)
        elif strategy == "layout":
            return Chunker._layout_aware_chunk(text, chunk_size, chunk_overlap)
        else:
            return Chunker._fixed_chunk(text, chunk_size, chunk_overlap)
    
    @staticmethod
    def _semantic_chunk(
        text: str,
        chunk_size: int,
        chunk_overlap: int
    ) -> List[Dict[str, Any]]:
        """Semantic chunking - split on sentence boundaries"""
        # Split on sentence boundaries
        sentences = re.split(r'(?<=[.!?])\s+', text)
        
        chunks = []
        current_chunk = []
        current_length = 0
        
        for sentence in sentences:
            sentence_length = len(sentence)
            
            if current_length + sentence_length > chunk_size and current_chunk:
                # Save current chunk
                chunk_text = " ".join(current_chunk)
                chunks.append({
                    "text": chunk_text,
                    "length": len(chunk_text),
                    "strategy": "semantic",
                })
                
                # Start new chunk with overlap
                overlap_sentences = current_chunk[-chunk_overlap//50:] if chunk_overlap > 0 else []
                current_chunk = overlap_sentences + [sentence]
                current_length = sum(len(s) for s in current_chunk)
            else:
                current_chunk.append(sentence)
                current_length += sentence_length
        
        # Add final chunk
        if current_chunk:
            chunk_text = " ".join(current_chunk)
            chunks.append({
                "text": chunk_text,
                "length": len(chunk_text),
                "strategy": "semantic",
            })
        
        return chunks
    
    @staticmethod
    def _layout_aware_chunk(
        text: str,
        chunk_size: int,
        chunk_overlap: int
    ) -> List[Dict[str, Any]]:
        """Layout-aware chunking - respect document structure"""
        # Split on paragraph boundaries
        paragraphs = text.split("\n\n")
        
        chunks = []
        current_chunk = []
        current_length = 0
        
        for para in paragraphs:
            para_length = len(para)
            
            if current_length + para_length > chunk_size and current_chunk:
                chunk_text = "\n\n".join(current_chunk)
                chunks.append({
                    "text": chunk_text,
                    "length": len(chunk_text),
                    "strategy": "layout",
                })
                
                current_chunk = [para]
                current_length = para_length
            else:
                current_chunk.append(para)
                current_length += para_length
        
        if current_chunk:
            chunk_text = "\n\n".join(current_chunk)
            chunks.append({
                "text": chunk_text,
                "length": len(chunk_text),
                "strategy": "layout",
            })
        
        return chunks
    
    @staticmethod
    def _fixed_chunk(
        text: str,
        chunk_size: int,
        chunk_overlap: int
    ) -> List[Dict[str, Any]]:
        """Fixed-size chunking"""
        chunks = []
        start = 0
        
        while start < len(text):
            end = start + chunk_size
            chunk_text = text[start:end]
            
            chunks.append({
                "text": chunk_text,
                "length": len(chunk_text),
                "strategy": "fixed",
            })
            
            start = end - chunk_overlap
        
        return chunks

