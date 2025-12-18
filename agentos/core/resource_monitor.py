"""
Resource Monitor - Monitor and track agent resource usage
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import psutil
import time


@dataclass
class ResourceMetrics:
    """Resource usage metrics"""
    agent_id: str
    timestamp: str
    token_usage: int = 0
    api_calls: int = 0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    wall_time: float = 0.0
    cost_estimate: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResourceMonitor:
    """
    Resource monitor that tracks CPU, memory, API costs, tokens, and wall-time.
    """
    
    def __init__(self):
        self.metrics_history: Dict[str, List[ResourceMetrics]] = {}  # agent_id -> [metrics]
        self.current_metrics: Dict[str, ResourceMetrics] = {}  # agent_id -> current metrics
        self.start_times: Dict[str, float] = {}  # agent_id -> start_time
    
    def start_monitoring(self, agent_id: str):
        """Start monitoring an agent"""
        self.start_times[agent_id] = time.time()
        if agent_id not in self.metrics_history:
            self.metrics_history[agent_id] = []
    
    def stop_monitoring(self, agent_id: str):
        """Stop monitoring an agent"""
        if agent_id in self.start_times:
            del self.start_times[agent_id]
    
    def update(
        self,
        agent_id: str,
        token_usage: int = 0,
        api_calls: int = 0,
        cost_estimate: float = 0.0
    ):
        """
        Update resource metrics for an agent.
        
        Args:
            agent_id: Agent ID
            token_usage: Additional tokens used
            api_calls: Additional API calls
            cost_estimate: Additional cost estimate
        """
        if agent_id not in self.current_metrics:
            self.current_metrics[agent_id] = ResourceMetrics(
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
            )
        
        metrics = self.current_metrics[agent_id]
        metrics.token_usage += token_usage
        metrics.api_calls += api_calls
        metrics.cost_estimate += cost_estimate
        
        # Update system metrics
        try:
            process = psutil.Process()
            metrics.cpu_percent = process.cpu_percent()
            metrics.memory_mb = process.memory_info().rss / 1024 / 1024
        except Exception:
            pass
        
        # Update wall time
        if agent_id in self.start_times:
            metrics.wall_time = time.time() - self.start_times[agent_id]
    
    def get(self, agent_id: str) -> Optional[ResourceMetrics]:
        """Get current metrics for an agent"""
        return self.current_metrics.get(agent_id)
    
    def get_history(self, agent_id: str, limit: int = 100) -> List[ResourceMetrics]:
        """Get metrics history for an agent"""
        history = self.metrics_history.get(agent_id, [])
        return history[-limit:] if limit else history
    
    def snapshot(self, agent_id: str) -> ResourceMetrics:
        """
        Take a snapshot of current metrics and add to history.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Snapshot metrics
        """
        current = self.current_metrics.get(agent_id)
        if not current:
            current = ResourceMetrics(
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
            )
        
        # Create snapshot
        snapshot = ResourceMetrics(
            agent_id=current.agent_id,
            timestamp=datetime.now().isoformat(),
            token_usage=current.token_usage,
            api_calls=current.api_calls,
            cpu_percent=current.cpu_percent,
            memory_mb=current.memory_mb,
            wall_time=current.wall_time,
            cost_estimate=current.cost_estimate,
            metadata=current.metadata.copy(),
        )
        
        # Add to history
        if agent_id not in self.metrics_history:
            self.metrics_history[agent_id] = []
        self.metrics_history[agent_id].append(snapshot)
        
        return snapshot
    
    def get_all_metrics(self) -> Dict[str, ResourceMetrics]:
        """Get all current metrics"""
        return self.current_metrics.copy()
    
    def reset(self, agent_id: Optional[str] = None):
        """Reset metrics for an agent or all agents"""
        if agent_id:
            if agent_id in self.current_metrics:
                del self.current_metrics[agent_id]
            if agent_id in self.metrics_history:
                self.metrics_history[agent_id] = []
        else:
            self.current_metrics.clear()
            self.metrics_history.clear()

