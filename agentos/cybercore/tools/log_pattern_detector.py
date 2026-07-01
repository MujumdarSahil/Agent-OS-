"""
Log pattern detector - Detect suspicious patterns in logs
Includes MITRE ATT&CK tagging
"""

import re
from typing import Dict, Any, List


class LogPatternDetector:
    """Detect suspicious patterns in logs"""
    
    # MITRE ATT&CK patterns
    ATTACK_PATTERNS = {
        "T1078": {  # Valid Accounts
            "name": "Valid Accounts",
            "pattern": r"(?i)(successful\s+login|authentication\s+success|user\s+logged\s+in)",
            "description": "Successful authentication events",
        },
        "T1110": {  # Brute Force
            "name": "Brute Force",
            "pattern": r"(?i)(failed\s+login|authentication\s+failed|invalid\s+password).*(\d+)\s+times",
            "description": "Multiple failed login attempts",
        },
        "T1021": {  # Remote Services
            "name": "Remote Services",
            "pattern": r"(?i)(ssh|rdp|vnc|telnet).*(connection|session)",
            "description": "Remote service connections",
        },
        "T1071": {  # Application Layer Protocol
            "name": "Application Layer Protocol",
            "pattern": r"(?i)(http|https|dns|smtp).*(request|query|connection)",
            "description": "Network protocol usage",
        },
        "T1083": {  # File and Directory Discovery
            "name": "File and Directory Discovery",
            "pattern": r"(?i)(dir|ls|find|tree|grep).*(command|executed)",
            "description": "File system enumeration",
        },
        "T1059": {  # Command and Scripting Interpreter
            "name": "Command and Scripting Interpreter",
            "pattern": r"(?i)(cmd|powershell|bash|sh|python|perl).*(executed|ran)",
            "description": "Command execution",
        },
        "T1105": {  # Ingress Tool Transfer
            "name": "Ingress Tool Transfer",
            "pattern": r"(?i)(download|wget|curl|fetch).*(http|https|ftp)",
            "description": "File downloads",
        },
        "T1036": {  # Masquerading
            "name": "Masquerading",
            "pattern": r"(?i)(spoof|fake|masquerade|impersonate)",
            "description": "Identity masquerading",
        },
    }
    
    # Suspicious behavior patterns
    SUSPICIOUS_PATTERNS = {
        "brute_force": {
            "pattern": r"(?i)(failed\s+password|invalid\s+credentials).*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            "threshold": 5,  # Minimum failed attempts
        },
        "lateral_movement": {
            "pattern": r"(?i)(psexec|wmic|schtasks|at\s+.*\s+.*\.exe)",
            "description": "Lateral movement indicators",
        },
        "privilege_escalation": {
            "pattern": r"(?i)(sudo|su\s+-|runas|elevate|administrator)",
            "description": "Privilege escalation attempts",
        },
        "data_exfiltration": {
            "pattern": r"(?i)(large\s+transfer|bulk\s+download|mass\s+copy).*(\d+)\s*(mb|gb|tb)",
            "description": "Large data transfers",
        },
    }
    
    @staticmethod
    def detect_patterns(log_entry: str, log_type: str = "generic") -> Dict[str, Any]:
        """
        Detect suspicious patterns in log entry.
        
        Args:
            log_entry: Log entry text
            log_type: Type of log (syslog, auth, apache, etc.)
            
        Returns:
            Detection results with MITRE ATT&CK tags
        """
        if not log_entry:
            return {
                "matches": [],
                "attack_tags": [],
                "suspicious": False,
            }
        
        matches = []
        attack_tags = []
        
        # Check MITRE ATT&CK patterns
        for tactic_id, tactic_info in LogPatternDetector.ATTACK_PATTERNS.items():
            pattern = tactic_info["pattern"]
            if re.search(pattern, log_entry):
                matches.append({
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_info["name"],
                    "description": tactic_info["description"],
                    "type": "mitre_attack",
                })
                attack_tags.append(tactic_id)
        
        # Check suspicious patterns
        for pattern_name, pattern_info in LogPatternDetector.SUSPICIOUS_PATTERNS.items():
            pattern = pattern_info["pattern"]
            match = re.search(pattern, log_entry)
            if match:
                matches.append({
                    "pattern_name": pattern_name,
                    "description": pattern_info.get("description", ""),
                    "type": "suspicious",
                    "match": match.group(0) if match else "",
                })
        
        return {
            "matches": matches,
            "attack_tags": list(set(attack_tags)),
            "suspicious": len(matches) > 0,
            "match_count": len(matches),
        }
    
    @staticmethod
    def detect_brute_force(log_entries: List[str], threshold: int = 5) -> Dict[str, Any]:
        """
        Detect brute force attacks from log entries.
        
        Args:
            log_entries: List of log entries
            threshold: Minimum failed attempts
            
        Returns:
            Brute force detection results
        """
        failed_attempts = {}
        
        for entry in log_entries:
            # Look for failed login patterns
            pattern = r"(?i)(failed\s+password|invalid\s+credentials|authentication\s+failed).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            match = re.search(pattern, entry)
            if match:
                ip = match.group(2)
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        
        # Find IPs above threshold
        suspicious_ips = {
            ip: count
            for ip, count in failed_attempts.items()
            if count >= threshold
        }
        
        return {
            "brute_force_detected": len(suspicious_ips) > 0,
            "suspicious_ips": suspicious_ips,
            "total_failed_attempts": sum(failed_attempts.values()),
            "threshold": threshold,
        }
    
    @staticmethod
    def tag_with_mitre_attack(detections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Tag detections with MITRE ATT&CK framework.
        
        Args:
            detections: List of detection results
            
        Returns:
            Tagged results
        """
        all_tags = set()
        tagged_detections = []
        
        for detection in detections:
            tags = detection.get("attack_tags", [])
            all_tags.update(tags)
            
            tagged_detections.append({
                **detection,
                "mitre_attack_tags": tags,
            })
        
        return {
            "detections": tagged_detections,
            "all_attack_tags": list(all_tags),
            "tag_count": len(all_tags),
        }

