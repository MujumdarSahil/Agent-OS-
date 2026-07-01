"""
Log Analysis MCP - Parse and analyze various log formats
"""

from typing import Dict, Any, List
from agentos.mcp_connectors.base_mcp import BaseMCPConnector
from agentos.cybercore.utils.log_parsers import (
    SyslogParser,
    WindowsEventLogParser,
    AuthLogParser,
)
from agentos.cybercore.tools.log_pattern_detector import LogPatternDetector


class LogAnalysisMCP(BaseMCPConnector):
    """
    Log Analysis MCP - Parse Windows Event Logs, Linux syslogs, authentication logs.
    Search queries with filters and pattern recognition.
    """
    
    def __init__(self, endpoint: str = "log://analysis"):
        super().__init__(endpoint, "log_analysis_mcp", "log_analysis")
        self.skills = [
            {
                "id": "parse_syslog",
                "name": "parse_syslog",
                "description": "Parse Linux syslog format",
                "type": "tool",
                "inputs": {"log_file": "string", "log_lines": "list"},
                "outputs": {"parsed_entries": "list"},
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.02},
            },
            {
                "id": "parse_auth_log",
                "name": "parse_auth_log",
                "description": "Parse authentication logs",
                "type": "tool",
                "inputs": {"log_file": "string", "log_lines": "list"},
                "outputs": {"parsed_entries": "list"},
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.02},
            },
            {
                "id": "parse_windows_event",
                "name": "parse_windows_event",
                "description": "Parse Windows Event Log XML",
                "type": "tool",
                "inputs": {"log_file": "string", "xml_content": "string"},
                "outputs": {"parsed_events": "list"},
                "latency_estimate": 1.5,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.02},
            },
            {
                "id": "search_logs",
                "name": "search_logs",
                "description": "Search logs with query and filters",
                "type": "tool",
                "inputs": {"query": "string", "filters": "dict", "log_entries": "list"},
                "outputs": {"results": "list", "count": "int"},
                "latency_estimate": 2.0,
                "accuracy_estimate": 0.9,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.05},
            },
            {
                "id": "detect_patterns",
                "name": "detect_patterns",
                "description": "Detect suspicious patterns with MITRE ATT&CK tagging",
                "type": "tool",
                "inputs": {"log_entry": "string", "log_type": "string"},
                "outputs": {"matches": "list", "attack_tags": "list"},
                "latency_estimate": 1.0,
                "accuracy_estimate": 0.85,
                "data_sensitivity": "confidential",
                "cost_estimate": {"cost": 0.03},
            },
        ]
        self.log_storage: List[Dict[str, Any]] = []
    
    async def connect(self) -> bool:
        """Connect to log analysis service"""
        self.status = "active"
        return True
    
    async def disconnect(self):
        """Disconnect"""
        self.status = "inactive"
    
    async def call_skill(self, skill_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call log analysis skill"""
        if skill_name == "parse_syslog":
            log_file = params.get("log_file")
            log_lines = params.get("log_lines", [])
            
            if log_file:
                entries = SyslogParser.parse_file(log_file)
            else:
                entries = [SyslogParser.parse_line(line) for line in log_lines if line]
            
            # Filter None entries
            entries = [e for e in entries if e]
            
            return {
                "success": True,
                "parsed_entries": entries,
                "count": len(entries),
            }
        
        elif skill_name == "parse_auth_log":
            log_file = params.get("log_file")
            log_lines = params.get("log_lines", [])
            
            if log_file:
                # Read file and parse
                entries = []
                try:
                    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            entry = AuthLogParser.parse_line(line.strip())
                            if entry:
                                entries.append(entry)
                except Exception as e:
                    return {
                        "success": False,
                        "error": str(e),
                    }
            else:
                entries = [AuthLogParser.parse_line(line) for line in log_lines if line]
            
            entries = [e for e in entries if e]
            
            return {
                "success": True,
                "parsed_entries": entries,
                "count": len(entries),
            }
        
        elif skill_name == "parse_windows_event":
            log_file = params.get("log_file")
            xml_content = params.get("xml_content")
            
            if log_file:
                events = WindowsEventLogParser.parse_file(log_file)
            elif xml_content:
                event = WindowsEventLogParser.parse_xml(xml_content)
                events = [event] if event else []
            else:
                return {
                    "success": False,
                    "error": "Either log_file or xml_content must be provided",
                }
            
            return {
                "success": True,
                "parsed_events": events,
                "count": len(events),
            }
        
        elif skill_name == "search_logs":
            query = params.get("query", "").lower()
            filters = params.get("filters", {})
            log_entries = params.get("log_entries", self.log_storage)
            
            # Simple search (in production would use Elasticsearch/OpenSearch)
            results = []
            for entry in log_entries:
                entry_str = str(entry).lower()
                if query in entry_str:
                    # Apply filters
                    match = True
                    for key, value in filters.items():
                        if entry.get(key) != value:
                            match = False
                            break
                    if match:
                        results.append(entry)
            
            return {
                "success": True,
                "results": results[:100],  # Limit results
                "count": len(results),
            }
        
        elif skill_name == "detect_patterns":
            log_entry = params.get("log_entry", "")
            log_type = params.get("log_type", "generic")
            
            # Detect patterns
            detection = LogPatternDetector.detect_patterns(log_entry, log_type)
            
            return {
                "success": True,
                "matches": detection["matches"],
                "attack_tags": detection["attack_tags"],
                "suspicious": detection["suspicious"],
                "match_count": detection["match_count"],
            }
        
        return {"success": False, "error": f"Unknown skill: {skill_name}"}

