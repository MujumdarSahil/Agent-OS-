"""
Network Metadata Inspector Tool - Defensive network metadata analysis

SAFETY: Read-only metadata analysis. No active network probing.
"""

import logging
from typing import Dict, Any, List, Optional
from collections import Counter

logger = logging.getLogger(__name__)


class NetworkMetadataInspector:
    """
    Network Metadata Inspector - Analyzes network metadata safely.
    
    All operations are read-only. No active network probing.
    """
    
    @staticmethod
    def inspect_metadata(
        log_entries: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Inspect network metadata from logs.
        
        Args:
            log_entries: List of network log entries
            
        Returns:
            Metadata analysis with safety_metadata
        """
        source_ips = Counter()
        dest_ips = Counter()
        ports = Counter()
        protocols = Counter()
        
        for entry in log_entries:
            if source_ip := entry.get("source_ip") or entry.get("src_ip"):
                source_ips[source_ip] += 1
            
            if dest_ip := entry.get("dest_ip") or entry.get("dst_ip"):
                dest_ips[dest_ip] += 1
            
            if port := entry.get("dest_port") or entry.get("port"):
                ports[str(port)] += 1
            
            if protocol := entry.get("protocol"):
                protocols[str(protocol)] += 1
        
        # Get top items
        top_source_ips = [{"ip": ip, "count": count} for ip, count in source_ips.most_common(10)]
        top_dest_ips = [{"ip": ip, "count": count} for ip, count in dest_ips.most_common(10)]
        top_ports = [{"port": port, "count": count} for port, count in ports.most_common(10)]
        
        result = {
            "top_source_ips": top_source_ips,
            "top_destination_ips": top_dest_ips,
            "top_ports": top_ports,
            "protocol_distribution": dict(protocols.most_common()),
            "statistics": {
                "total_connections": len(log_entries),
                "unique_source_ips": len(source_ips),
                "unique_destination_ips": len(dest_ips),
                "unique_ports": len(ports),
                "unique_protocols": len(protocols),
            },
            "safety_metadata": {
                "operation": "read_only",
                "active_probing": False,
                "network_modification": False,
                "compliance": "defensive_metadata_analysis_only",
            }
        }
        
        logger.info(f"Network metadata inspection completed: {len(log_entries)} entries analyzed")
        return result

