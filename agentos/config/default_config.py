"""
Default configuration for AgentOS
"""

# UMB Configuration
UMB_BACKEND = "simple"  # "simple", "faiss", "chroma", "pgvector"
UMB_EMBEDDING_DIM = 128

# WebSocket Configuration
WS_HOST = "localhost"
WS_PORT = 8765

# Resource Limits (defaults)
DEFAULT_TOKEN_LIMIT = 100000
DEFAULT_API_CALL_LIMIT = 1000
DEFAULT_CPU_LIMIT = 1.0
DEFAULT_MEMORY_LIMIT = 1024.0  # MB
DEFAULT_WALL_TIME_LIMIT = 3600.0  # seconds

# Governance
REQUIRE_HUMAN_APPROVAL = False
AUDIT_LOG_ENABLED = True

# DMSG
DMSG_TRUST_THRESHOLD = 0.5
DMSG_COST_WEIGHT = 0.3
DMSG_LATENCY_WEIGHT = 0.2

