"""
Mixed Precision Utils - Mixed precision training utilities
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class MixedPrecisionUtils:
    """
    Mixed Precision Utils - Utilities for mixed precision training.
    """
    
    @staticmethod
    def configure_mixed_precision(
        use_fp16: bool = True,
        use_bf16: bool = False
    ) -> Dict[str, Any]:
        """
        Configure mixed precision training.
        
        Args:
            use_fp16: Use FP16 precision
            use_bf16: Use BF16 precision
            
        Returns:
            Mixed precision configuration
        """
        return {
            "fp16": use_fp16,
            "bf16": use_bf16,
            "enabled": use_fp16 or use_bf16,
            "note": "Mixed precision reduces memory usage and speeds up training",
        }

