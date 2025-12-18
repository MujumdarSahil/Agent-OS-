"""
Log parsing utilities for various log formats
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from datetime import datetime


class SyslogParser:
    """Parse Linux syslog format"""
    
    SYSLOG_PATTERN = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"([\w\-\.]+)\s+"
        r"([\w\-\.]+)(?:\[(\d+)\])?:\s+"
        r"(.*)$"
    )
    
    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a syslog line.
        
        Args:
            line: Syslog line
            
        Returns:
            Parsed log entry or None
        """
        if not line or not line.strip():
            return None
        
        match = SyslogParser.SYSLOG_PATTERN.match(line)
        if not match:
            return {
                "raw": line,
                "timestamp": None,
                "hostname": None,
                "service": None,
                "pid": None,
                "message": line,
            }
        
        timestamp_str, hostname, service, pid, message = match.groups()
        
        return {
            "raw": line,
            "timestamp": timestamp_str,
            "hostname": hostname,
            "service": service,
            "pid": int(pid) if pid else None,
            "message": message,
        }
    
    @staticmethod
    def parse_file(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse syslog file.
        
        Args:
            file_path: Path to log file
            
        Returns:
            List of parsed entries
        """
        entries = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = SyslogParser.parse_line(line.strip())
                    if entry:
                        entries.append(entry)
        except Exception as e:
            print(f"Error parsing syslog file: {e}")
        
        return entries


class ApacheLogParser:
    """Parse Apache/Nginx access logs"""
    
    COMMON_LOG_PATTERN = re.compile(
        r'^(\S+)\s+'  # IP
        r'(\S+)\s+'   # Identity
        r'(\S+)\s+'   # User
        r'\[([^\]]+)\]\s+'  # Timestamp
        r'"(\S+)\s+(\S+)\s+(\S+)"\s+'  # Method, path, protocol
        r'(\d+)\s+'   # Status
        r'(\S+)'      # Size
    )
    
    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse Apache common log format line.
        
        Args:
            line: Log line
            
        Returns:
            Parsed entry or None
        """
        if not line or not line.strip():
            return None
        
        match = ApacheLogParser.COMMON_LOG_PATTERN.match(line)
        if not match:
            return {
                "raw": line,
                "ip": None,
                "timestamp": None,
                "method": None,
                "path": None,
                "status": None,
            }
        
        ip, identity, user, timestamp, method, path, protocol, status, size = match.groups()
        
        return {
            "raw": line,
            "ip": ip,
            "identity": identity,
            "user": user,
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "protocol": protocol,
            "status": int(status),
            "size": size,
        }


class WindowsEventLogParser:
    """Parse Windows Event Log XML format"""
    
    @staticmethod
    def parse_xml(xml_string: str) -> Optional[Dict[str, Any]]:
        """
        Parse Windows Event Log XML.
        
        Args:
            xml_string: XML string
            
        Returns:
            Parsed event or None
        """
        if not xml_string:
            return None
        
        try:
            root = ET.fromstring(xml_string)
            
            event = {
                "system": {},
                "event_data": {},
            }
            
            # Parse System section
            system = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}System")
            if system is not None:
                provider = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Provider")
                if provider is not None:
                    event["system"]["provider"] = provider.get("Name", "")
                
                event_id = system.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
                if event_id is not None:
                    event["system"]["event_id"] = event_id.text
            
            # Parse EventData section
            event_data = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
            if event_data is not None:
                for data in event_data.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                    name = data.get("Name", "")
                    value = data.text or ""
                    event["event_data"][name] = value
            
            return event
        
        except Exception as e:
            return {
                "raw": xml_string,
                "error": str(e),
            }
    
    @staticmethod
    def parse_file(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse Windows Event Log XML file.
        
        Args:
            file_path: Path to XML file
            
        Returns:
            List of parsed events
        """
        events = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Try to parse as single event or multiple events
                if content.strip().startswith("<"):
                    event = WindowsEventLogParser.parse_xml(content)
                    if event:
                        events.append(event)
        except Exception as e:
            print(f"Error parsing Windows Event Log: {e}")
        
        return events


class AuthLogParser:
    """Parse authentication logs (SSH, login attempts)"""
    
    SSH_PATTERN = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+"
        r"sshd\[(\d+)\]:\s+"
        r"(.*)"
    )
    
    FAILED_LOGIN_PATTERN = re.compile(
        r"Failed\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)"
    )
    
    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """
        Parse authentication log line.
        
        Args:
            line: Log line
            
        Returns:
            Parsed entry or None
        """
        if not line or not line.strip():
            return None
        
        # Try SSH pattern
        match = AuthLogParser.SSH_PATTERN.match(line)
        if match:
            timestamp, hostname, pid, message = match.groups()
            
            # Check for failed login
            failed_match = AuthLogParser.FAILED_LOGIN_PATTERN.search(message)
            if failed_match:
                username, source_ip = failed_match.groups()
                return {
                    "raw": line,
                    "timestamp": timestamp,
                    "hostname": hostname,
                    "type": "failed_login",
                    "username": username,
                    "source_ip": source_ip,
                    "message": message,
                }
            
            return {
                "raw": line,
                "timestamp": timestamp,
                "hostname": hostname,
                "type": "ssh_event",
                "message": message,
            }
        
        return {
            "raw": line,
            "message": line,
        }

