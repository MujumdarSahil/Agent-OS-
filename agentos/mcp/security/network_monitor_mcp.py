"""
Network Monitor MCP - Safe network monitoring and anomaly detection

Provides:
- detect_open_ports_metadata(): Detect open ports from metadata (no active scanning)
- detect_port_scans_behavior(): Detect port scan patterns from log metadata
- detect_network_anomalies(): Detect anomalies in network logs
- parse_logs_for_events(): Parse logs for security events
- classify_incident(): AI-based incident classification

SAFETY: Read-only log analysis only. No active network probing.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import Counter
from agentos.mcp_connectors.base_mcp import BaseMCPConnector

logger = logging.getLogger(__name__)


class NetworkMonitorMCP(BaseMCPConnector):
    """
    Network Monitor MCP - Safe network monitoring.
    
    All operations are read-only log analysis.
    NO active network probing or scanning.
    """
    
    def __init__(self, endpoint: str = "network://monitor"):
        super().__init__(endpoint, "network_monitor_mcp", "network_monitoring")
        self.skills = [
            {
                "id": "detect_open_ports_metadata",
                "name": "detect_open_ports_metadata",
                "description": "Detect open ports from log metadata (no active scanning)",
                "type": "tool",
                "inputs": {"log_entries": "list"},
                "outputs": {
                    "open_ports": "list",
                    "port_metadata": "dict",
                },
                "latency_estimate": 0.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.05},
            },
            {
                "id": "detect_port_scans_behavior",
                "name": "detect_port_scans_behavior",
                "description": "Detect port scan patterns from log metadata",
                "type": "tool",
                "inputs": {"log_entries": "list"},
                "outputs": {
                    "scan_detected": "bool",
                    "scan_type": "string",
                    "source_ips": "list",
                },
                "latency_estimate": 0.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.05},
            },
            {
                "id": "detect_network_anomalies",
                "name": "detect_network_anomalies",
                "description": "Detect anomalies in network logs using statistical analysis",
                "type": "tool",
                "inputs": {"log_entries": "list", "baseline_period_days": "int"},
                "outputs": {
                    "anomalies_detected": "list",
                    "anomaly_score": "float",
                    "severity": "string",
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.8,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
            },
            {
                "id": "parse_logs_for_events",
                "name": "parse_logs_for_events",
                "description": "Parse logs for security events",
                "type": "tool",
                "inputs": {"log_entries": "list", "log_type": "string"},
                "outputs": {
                    "security_events": "list",
                    "event_count": "int",
                },
                "latency_estimate": 0.8,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.08},
            },
            {
                "id": "classify_incident",
                "name": "classify_incident",
                "description": "AI-based incident classification from log metadata",
                "type": "tool",
                "inputs": {"log_entries": "list", "incident_context": "dict"},
                "outputs": {
                    "incident_type": "string",
                    "severity": "string",
                    "confidence": "float",
                },
                "latency_estimate": 1.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.15},
            },
        ]
    
    async def connect(self) -> bool:
        """Connect to Network Monitor MCP service"""
        self.status = "active"
        logger.info("Network Monitor MCP connected")
        return True
    
    async def disconnect(self):
        """Disconnect from Network Monitor MCP"""
        self.status = "inactive"
        logger.info("Network Monitor MCP disconnected")
    
    def _detect_open_ports_metadata(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect open ports from log metadata (no active scanning)"""
        if not log_entries:
            return {
                "open_ports": [],
                "port_metadata": {},
            }
        
        ports = Counter()
        port_metadata = {}
        
        for entry in log_entries:
            port = entry.get("dest_port") or entry.get("port") or entry.get("dst_port")
            if port:
                ports[str(port)] += 1
                if str(port) not in port_metadata:
                    port_metadata[str(port)] = {
                        "port": port,
                        "protocol": entry.get("protocol", "unknown"),
                        "first_seen": entry.get("timestamp", ""),
                    }
        
        return {
            "open_ports": [{"port": p, "count": c} for p, c in ports.most_common(20)],
            "port_metadata": port_metadata,
        }
    
    def _detect_port_scans_behavior(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect port scan patterns from log metadata"""
        if not log_entries:
            return {
                "scan_detected": False,
                "scan_type": "none",
                "source_ips": [],
            }
        
        source_port_map = {}
        
        for entry in log_entries:
            source_ip = entry.get("source_ip") or entry.get("src_ip") or entry.get("ip")
            dest_port = entry.get("dest_port") or entry.get("port") or entry.get("dst_port")
            
            if not source_ip or not dest_port:
                continue
            
            if source_ip not in source_port_map:
                source_port_map[source_ip] = {"ports": set(), "count": 0}
            
            source_port_map[source_ip]["ports"].add(str(dest_port))
            source_port_map[source_ip]["count"] += 1
        
        scan_sources = []
        
        for source_ip, data in source_port_map.items():
            port_count = len(data["ports"])
            connection_count = data["count"]
            
            if port_count >= 10 or connection_count >= 20:
                scan_sources.append(source_ip)
        
        scan_detected = len(scan_sources) > 0
        
        if scan_detected:
            if len(scan_sources) > 5:
                scan_type = "comprehensive_scan"
            else:
                scan_type = "targeted_scan"
        else:
            scan_type = "none"
        
        return {
            "scan_detected": scan_detected,
            "scan_type": scan_type,
            "source_ips": scan_sources,
        }
    
    def _detect_network_anomalies(self, log_entries: List[Dict[str, Any]], baseline_period_days: int = 7) -> Dict[str, Any]:
        """Detect anomalies in network logs"""
        if not log_entries:
            return {
                "anomalies_detected": [],
                "anomaly_score": 0.0,
                "severity": "low",
            }
        
        anomalies = []
        anomaly_score = 0.0
        
        source_ips = Counter()
        dest_ips = Counter()
        ports = Counter()
        
        for entry in log_entries:
            source_ips[entry.get("source_ip")] += 1
            dest_ips[entry.get("dest_ip")] += 1
            ports[entry.get("dest_port")] += 1
        
        if source_ips:
            max_source_count = max(source_ips.values())
            avg_source_count = sum(source_ips.values()) / len(source_ips)
            if max_source_count > avg_source_count * 5:
                anomalies.append({
                    "type": "unusual_source_activity",
                    "description": f"Source IP with {max_source_count} connections",
                })
                anomaly_score += 0.3
        
        if ports:
            unusual_ports = [p for p, count in ports.items() if count > 100]
            if unusual_ports:
                anomalies.append({
                    "type": "unusual_port_activity",
                    "description": f"High activity on ports: {unusual_ports[:5]}",
                })
                anomaly_score += 0.4
        
        if anomaly_score >= 0.7:
            severity = "high"
        elif anomaly_score >= 0.4:
            severity = "medium"
        else:
            severity = "low"
        
        return {
            "anomalies_detected": anomalies,
            "anomaly_score": min(1.0, anomaly_score),
            "severity": severity,
        }
    
    def _parse_logs_for_events(self, log_entries: List[Dict[str, Any]], log_type: str = "generic") -> Dict[str, Any]:
        """Parse logs for security events"""
        security_events = []
        
        security_patterns = [
            (r"failed\s+login", "Failed login attempt", "medium"),
            (r"unauthorized\s+access", "Unauthorized access attempt", "high"),
            (r"sql\s+injection", "Potential SQL injection", "high"),
            (r"xss", "Potential XSS attack", "high"),
            (r"brute\s+force", "Brute force attack", "high"),
            (r"port\s+scan", "Port scan detected", "medium"),
        ]
        
        for log_file in log_entries if isinstance(log_entries[0], dict) and "content" in log_entries[0] else [{"content": str(log_entries)}]:
            content = log_file.get("content", "")
            lines = content.split("\n") if content else []
            
            for line_num, line in enumerate(lines[:1000], 1):
                line_lower = line.lower()
                
                for pattern, description, severity in security_patterns:
                    if re.search(pattern, line_lower):
                        security_events.append({
                            "line": line_num,
                            "event": description,
                            "severity": severity,
                            "log_line": line[:200],
                        })
        
        return {
            "security_events": security_events[:50],
            "event_count": len(security_events),
        }
    
    def _classify_incident(self, log_entries: List[Dict[str, Any]], incident_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Classify security incident from log metadata"""
        if not log_entries:
            return {
                "incident_type": "unknown",
                "severity": "low",
                "confidence": 0.0,
            }
        
        incident_context = incident_context or {}
        
        # Analyze logs
        scan_result = self._detect_port_scans_behavior(log_entries)
        anomaly_result = self._detect_network_anomalies(log_entries)
        
        if scan_result["scan_detected"]:
            incident_type = "port_scan"
            severity = "medium"
            confidence = 0.85
        elif anomaly_result["anomaly_score"] > 0.5:
            incident_type = "network_anomaly"
            severity = "medium"
            confidence = 0.75
        else:
            incident_type = "normal_activity"
            severity = "low"
            confidence = 0.5
        
        return {
            "incident_type": incident_type,
            "severity": severity,
            "confidence": confidence,
        }
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call Network Monitor MCP skill"""
        try:
            logger.info(f"Network Monitor MCP skill called: {skill_name}")
            
            if skill_name == "detect_open_ports_metadata":
                log_entries = params.get("log_entries", [])
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                result = self._detect_open_ports_metadata(log_entries)
                return {"success": True, **result}
            
            elif skill_name == "detect_port_scans_behavior":
                log_entries = params.get("log_entries", [])
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                result = self._detect_port_scans_behavior(log_entries)
                return {"success": True, **result}
            
            elif skill_name == "detect_network_anomalies":
                log_entries = params.get("log_entries", [])
                baseline_period_days = params.get("baseline_period_days", 7)
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                result = self._detect_network_anomalies(log_entries, baseline_period_days)
                return {"success": True, **result}
            
            elif skill_name == "parse_logs_for_events":
                log_entries = params.get("log_entries", [])
                log_type = params.get("log_type", "generic")
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                result = self._parse_logs_for_events(log_entries, log_type)
                return {"success": True, **result}
            
            elif skill_name == "classify_incident":
                log_entries = params.get("log_entries", [])
                incident_context = params.get("incident_context", {})
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                result = self._classify_incident(log_entries, incident_context)
                return {"success": True, **result}
            
            else:
                return {"success": False, "error": f"Unknown skill: {skill_name}"}
        
        except Exception as e:
            logger.error(f"Error executing Network Monitor MCP skill {skill_name}: {e}")
            return {"success": False, "error": f"Error executing skill: {str(e)}"}

