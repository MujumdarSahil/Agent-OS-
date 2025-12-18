"""
Log Analyzer Tool - Defensive log analysis for security events

SAFETY: Read-only log analysis. No log modification or tampering.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)


class LogAnalyzer:
    """
    Log Analyzer - Analyzes security logs for threats and anomalies.
    
    All operations are read-only. No log modification.
    """
    
    # Security event patterns
    SECURITY_PATTERNS = [
        (r"failed\s+login", "Failed login attempt", "medium"),
        (r"unauthorized\s+access", "Unauthorized access attempt", "high"),
        (r"sql\s+injection", "Potential SQL injection", "high"),
        (r"xss", "Potential XSS attack", "high"),
        (r"brute\s+force", "Brute force attack", "high"),
        (r"port\s+scan", "Port scan detected", "medium"),
        (r"malware", "Malware detected", "high"),
        (r"root\s+login", "Root login detected", "high"),
    ]
    
    @staticmethod
    def analyze_logs(
        log_entries: List[Dict[str, Any]],
        log_type: str = "generic"
    ) -> Dict[str, Any]:
        """
        Analyze logs for security events.
        
        Args:
            log_entries: List of log entry dictionaries
            log_type: Type of log (syslog, apache, nginx, etc.)
            
        Returns:
            Analysis results with safety_metadata
        """
        security_events = []
        anomalies = []
        
        for entry in log_entries:
            content = entry.get("content", "") or str(entry)
            line_lower = content.lower()
            
            # Check for security patterns
            for pattern, description, severity in LogAnalyzer.SECURITY_PATTERNS:
                if re.search(pattern, line_lower):
                    security_events.append({
                        "event": description,
                        "severity": severity,
                        "timestamp": entry.get("timestamp", datetime.now().isoformat()),
                        "source": entry.get("source", "unknown"),
                    })
            
            # Detect anomalies (error spikes, unusual patterns)
            if re.search(r"error|exception|critical|fatal", line_lower):
                anomalies.append({
                    "type": "error_log",
                    "content": content[:200],
                })
        
        # Calculate statistics
        event_count = len(security_events)
        high_severity_count = sum(1 for e in security_events if e.get("severity") == "high")
        
        result = {
            "security_events": security_events[:100],  # Limit output
            "anomalies": anomalies[:50],
            "statistics": {
                "total_events": event_count,
                "high_severity": high_severity_count,
                "medium_severity": sum(1 for e in security_events if e.get("severity") == "medium"),
                "low_severity": sum(1 for e in security_events if e.get("severity") == "low"),
            },
            "safety_metadata": {
                "operation": "read_only",
                "log_modification": False,
                "data_retention": "ephemeral",
                "compliance": "defensive_analysis_only",
            }
        }
        
        logger.info(f"Log analysis completed: {event_count} security events found")
        return result

