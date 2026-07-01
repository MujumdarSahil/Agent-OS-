"""
Network Monitor MCP - Safe network monitoring and anomaly detection

This MCP provides:
- Port scan detection (metadata analysis only)
- Anomaly detection on logs
- AI-based incident classifier
- Safe metadata analysis only

SAFETY GUARANTEES:
- NO active scanning or probing
- Only analyzes provided logs/metadata
- Defensive and monitoring purposes only
- No exploitation or attack capabilities
"""

from typing import Dict, Any, List
from collections import Counter
from agentos.mcp_connectors.base_mcp import BaseMCPConnector


class NetworkMonitorMCP(BaseMCPConnector):
    """
    Network Monitor MCP - Safe network monitoring and anomaly detection.
    
    Provides port scan detection, log anomaly detection, and incident
    classification without any active network probing or exploitation.
    """
    
    def __init__(self, endpoint: str = "network://monitor"):
        super().__init__(endpoint, "network_monitor_mcp", "network_monitoring")
        self.skills = [
            {
                "id": "detect_port_scan",
                "name": "detect_port_scan",
                "description": "Detect port scan patterns from log metadata (no active scanning)",
                "type": "tool",
                "inputs": {"log_entries": "list"},
                "outputs": {
                    "scan_detected": "bool",
                    "scan_type": "string",
                    "source_ips": "list",
                    "target_ports": "list",
                    "confidence": "float"
                },
                "latency_estimate": 0.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.05},
            },
            {
                "id": "detect_anomalies",
                "name": "detect_anomalies",
                "description": "Detect anomalies in network logs using statistical analysis",
                "type": "tool",
                "inputs": {"log_entries": "list", "baseline_period_days": "int"},
                "outputs": {
                    "anomalies_detected": "list",
                    "anomaly_score": "float",
                    "severity": "string",
                    "recommendations": "list"
                },
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.8,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.1},
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
                    "indicators": "list",
                    "recommended_response": "string"
                },
                "latency_estimate": 1.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.15},
            },
            {
                "id": "analyze_metadata",
                "name": "analyze_metadata",
                "description": "Safe metadata analysis of network logs (no packet inspection)",
                "type": "tool",
                "inputs": {"log_entries": "list"},
                "outputs": {
                    "top_source_ips": "list",
                    "top_destination_ips": "list",
                    "top_ports": "list",
                    "protocol_distribution": "dict",
                    "traffic_patterns": "dict"
                },
                "latency_estimate": 0.8,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.08},
            },
        ]
    
    async def connect(self) -> bool:
        """Connect to Network Monitor MCP service"""
        self.status = "active"
        return True
    
    async def disconnect(self):
        """Disconnect from Network Monitor MCP"""
        self.status = "inactive"
    
    def _detect_port_scan(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect port scan patterns from log metadata"""
        if not log_entries:
            return {
                "scan_detected": False,
                "scan_type": "none",
                "source_ips": [],
                "target_ports": [],
                "confidence": 0.0,
            }
        
        # Analyze log entries for scan patterns
        source_port_map = {}  # source_ip -> {ports: set, count: int}
        
        for entry in log_entries:
            source_ip = entry.get("source_ip") or entry.get("src_ip") or entry.get("ip")
            dest_port = entry.get("dest_port") or entry.get("port") or entry.get("dst_port")
            
            if not source_ip or not dest_port:
                continue
            
            if source_ip not in source_port_map:
                source_port_map[source_ip] = {"ports": set(), "count": 0}
            
            source_port_map[source_ip]["ports"].add(str(dest_port))
            source_port_map[source_ip]["count"] += 1
        
        # Detect scan patterns
        scan_sources = []
        scan_ports = set()
        
        for source_ip, data in source_port_map.items():
            port_count = len(data["ports"])
            connection_count = data["count"]
            
            # Heuristics for port scan detection
            # 1. Many different ports from same source
            # 2. High connection rate
            # 3. Sequential port patterns
            
            if port_count >= 10 or connection_count >= 20:
                scan_sources.append(source_ip)
                scan_ports.update(data["ports"])
        
        scan_detected = len(scan_sources) > 0
        
        # Determine scan type
        if scan_detected:
            if len(scan_ports) > 100:
                scan_type = "comprehensive_scan"
            elif len(scan_ports) > 20:
                scan_type = "port_sweep"
            else:
                scan_type = "targeted_scan"
            
            confidence = min(0.95, 0.5 + (len(scan_sources) * 0.1))
        else:
            scan_type = "none"
            confidence = 0.0
        
        return {
            "scan_detected": scan_detected,
            "scan_type": scan_type,
            "source_ips": scan_sources,
            "target_ports": list(scan_ports)[:50],  # Limit output
            "confidence": confidence,
        }
    
    def _detect_anomalies(self, log_entries: List[Dict[str, Any]], baseline_period_days: int = 7) -> Dict[str, Any]:
        """Detect anomalies in network logs"""
        if not log_entries:
            return {
                "anomalies_detected": [],
                "anomaly_score": 0.0,
                "severity": "low",
                "recommendations": [],
            }
        
        anomalies = []
        anomaly_score = 0.0
        
        # Analyze traffic patterns
        source_ips = Counter()
        dest_ips = Counter()
        ports = Counter()
        protocols = Counter()
        
        for entry in log_entries:
            source_ips[entry.get("source_ip")] += 1
            dest_ips[entry.get("dest_ip")] += 1
            ports[entry.get("dest_port")] += 1
            protocols[entry.get("protocol")] += 1
        
        # Detect anomalies
        
        # 1. Unusual source IP frequency
        if source_ips:
            max_source_count = max(source_ips.values())
            avg_source_count = sum(source_ips.values()) / len(source_ips)
            if max_source_count > avg_source_count * 5:
                anomalies.append({
                    "type": "unusual_source_activity",
                    "description": f"Source IP with {max_source_count} connections (avg: {avg_source_count:.1f})",
                    "severity": "medium",
                })
                anomaly_score += 0.3
        
        # 2. Unusual destination concentration
        if dest_ips:
            top_dest = dest_ips.most_common(1)[0]
            if top_dest[1] > len(log_entries) * 0.5:
                anomalies.append({
                    "type": "destination_concentration",
                    "description": f"Over 50% of traffic to {top_dest[0]}",
                    "severity": "medium",
                })
                anomaly_score += 0.2
        
        # 3. Unusual port activity
        if ports:
            unusual_ports = [p for p, count in ports.items() if count > 100]
            if unusual_ports:
                anomalies.append({
                    "type": "unusual_port_activity",
                    "description": f"High activity on ports: {unusual_ports[:5]}",
                    "severity": "high",
                })
                anomaly_score += 0.4
        
        # 4. Protocol anomalies
        if protocols:
            unusual_protocols = [p for p, count in protocols.items() if count < 5]
            if unusual_protocols:
                anomalies.append({
                    "type": "unusual_protocols",
                    "description": f"Rare protocols detected: {unusual_protocols}",
                    "severity": "low",
                })
                anomaly_score += 0.1
        
        # Determine severity
        if anomaly_score >= 0.7:
            severity = "high"
        elif anomaly_score >= 0.4:
            severity = "medium"
        else:
            severity = "low"
        
        recommendations = [
            "Review source IPs with high connection counts",
            "Investigate unusual port activity",
            "Check for potential DDoS or scanning activity",
            "Update firewall rules if needed",
        ]
        
        return {
            "anomalies_detected": anomalies,
            "anomaly_score": min(1.0, anomaly_score),
            "severity": severity,
            "recommendations": recommendations,
        }
    
    def _classify_incident(self, log_entries: List[Dict[str, Any]], incident_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Classify security incident from log metadata"""
        if not log_entries:
            return {
                "incident_type": "unknown",
                "severity": "low",
                "confidence": 0.0,
                "indicators": [],
                "recommended_response": "No action needed",
            }
        
        incident_context = incident_context or {}
        indicators = []
        incident_types = []
        
        # Analyze logs for indicators
        scan_result = self._detect_port_scan(log_entries)
        if scan_result["scan_detected"]:
            indicators.append("Port scan detected")
            incident_types.append("port_scan")
        
        anomaly_result = self._detect_anomalies(log_entries)
        if anomaly_result["anomaly_score"] > 0.5:
            indicators.append("Network anomalies detected")
            incident_types.append("anomaly")
        
        # Check for specific patterns
        error_codes = Counter()
        for entry in log_entries:
            status = entry.get("status_code") or entry.get("status") or entry.get("response_code")
            if status:
                if isinstance(status, str):
                    status = int(status) if status.isdigit() else 0
                if 400 <= status < 600:
                    error_codes[status] += 1
        
        if error_codes and sum(error_codes.values()) > len(log_entries) * 0.3:
            indicators.append("High error rate detected")
            incident_types.append("service_disruption")
        
        # Determine incident type
        if "port_scan" in incident_types:
            incident_type = "port_scan"
            severity = "medium"
            recommended_response = "Block source IPs, review firewall rules"
        elif "service_disruption" in incident_types:
            incident_type = "service_disruption"
            severity = "high"
            recommended_response = "Investigate service health, check for DDoS"
        elif "anomaly" in incident_types:
            incident_type = "network_anomaly"
            severity = "medium"
            recommended_response = "Review network traffic patterns, investigate source"
        else:
            incident_type = "normal_activity"
            severity = "low"
            recommended_response = "Continue monitoring"
        
        # Calculate confidence
        confidence = min(0.95, 0.5 + (len(indicators) * 0.15))
        
        return {
            "incident_type": incident_type,
            "severity": severity,
            "confidence": confidence,
            "indicators": indicators,
            "recommended_response": recommended_response,
        }
    
    def _analyze_metadata(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network log metadata safely"""
        if not log_entries:
            return {
                "top_source_ips": [],
                "top_destination_ips": [],
                "top_ports": [],
                "protocol_distribution": {},
                "traffic_patterns": {},
            }
        
        source_ips = Counter()
        dest_ips = Counter()
        ports = Counter()
        protocols = Counter()
        
        for entry in log_entries:
            if source_ip := entry.get("source_ip") or entry.get("src_ip") or entry.get("ip"):
                source_ips[source_ip] += 1
            
            if dest_ip := entry.get("dest_ip") or entry.get("dst_ip") or entry.get("destination_ip"):
                dest_ips[dest_ip] += 1
            
            if port := entry.get("dest_port") or entry.get("port") or entry.get("dst_port"):
                ports[str(port)] += 1
            
            if protocol := entry.get("protocol") or entry.get("proto"):
                protocols[str(protocol)] += 1
        
        # Get top items
        top_source_ips = [{"ip": ip, "count": count} for ip, count in source_ips.most_common(10)]
        top_dest_ips = [{"ip": ip, "count": count} for ip, count in dest_ips.most_common(10)]
        top_ports = [{"port": port, "count": count} for port, count in ports.most_common(10)]
        protocol_distribution = dict(protocols.most_common())
        
        # Traffic patterns
        total_entries = len(log_entries)
        traffic_patterns = {
            "total_connections": total_entries,
            "unique_source_ips": len(source_ips),
            "unique_destination_ips": len(dest_ips),
            "unique_ports": len(ports),
            "unique_protocols": len(protocols),
        }
        
        return {
            "top_source_ips": top_source_ips,
            "top_destination_ips": top_dest_ips,
            "top_ports": top_ports,
            "protocol_distribution": protocol_distribution,
            "traffic_patterns": traffic_patterns,
        }
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call Network Monitor MCP skill"""
        try:
            if skill_name == "detect_port_scan":
                log_entries = params.get("log_entries", [])
                
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                
                result = self._detect_port_scan(log_entries)
                return {"success": True, **result}
            
            elif skill_name == "detect_anomalies":
                log_entries = params.get("log_entries", [])
                baseline_period_days = params.get("baseline_period_days", 7)
                
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                
                result = self._detect_anomalies(log_entries, baseline_period_days)
                return {"success": True, **result}
            
            elif skill_name == "classify_incident":
                log_entries = params.get("log_entries", [])
                incident_context = params.get("incident_context", {})
                
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                
                result = self._classify_incident(log_entries, incident_context)
                return {"success": True, **result}
            
            elif skill_name == "analyze_metadata":
                log_entries = params.get("log_entries", [])
                
                if not log_entries:
                    return {"success": False, "error": "Log entries list required"}
                
                result = self._analyze_metadata(log_entries)
                return {"success": True, **result}
            
            else:
                return {"success": False, "error": f"Unknown skill: {skill_name}"}
        
        except Exception as e:
            return {"success": False, "error": f"Error executing skill: {str(e)}"}

