"""
YARA scanner - Safe file scanning using YARA rules
"""

from typing import Dict, Any
import os


class YARAScanner:
    """Scan files using YARA rules"""
    
    def __init__(self):
        self.rules_loaded = False
        self.yara_rules = None
        self.rule_count = 0
    
    def load_rules(self, rules_path: str) -> Dict[str, Any]:
        """
        Load YARA rules from file or directory.
        
        Args:
            rules_path: Path to YARA rule file or directory
            
        Returns:
            Load result
        """
        try:
            # Try to import yara (optional dependency)
            try:
                import yara
            except ImportError:
                return {
                    "success": False,
                    "error": "YARA Python library not installed. Install with: pip install yara-python",
                }
            
            if os.path.isfile(rules_path):
                # Load single rule file
                self.yara_rules = yara.compile(filepath=rules_path)
                self.rule_count = 1
            elif os.path.isdir(rules_path):
                # Load rules from directory
                self.yara_rules = yara.compile(filepath=rules_path)
                # Count rule files
                rule_files = [f for f in os.listdir(rules_path) if f.endswith((".yar", ".yara"))]
                self.rule_count = len(rule_files)
            else:
                return {
                    "success": False,
                    "error": f"Rules path not found: {rules_path}",
                }
            
            self.rules_loaded = True
            
            return {
                "success": True,
                "rules_path": rules_path,
                "rule_count": self.rule_count,
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file with YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Scan results
        """
        if not self.rules_loaded or not self.yara_rules:
            return {
                "success": False,
                "error": "YARA rules not loaded",
            }
        
        if not os.path.isfile(file_path):
            return {
                "success": False,
                "error": f"File not found: {file_path}",
            }
        
        try:
            
            # Scan file
            matches = self.yara_rules.match(file_path)
            
            # Format results
            results = []
            for match in matches:
                results.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "strings": [
                        {
                            "identifier": str(s.identifier),
                            "offset": s.instances[0].offset if s.instances else 0,
                        }
                        for s in match.strings
                    ],
                    "meta": match.meta,
                })
            
            return {
                "success": True,
                "file_path": file_path,
                "matches": results,
                "match_count": len(results),
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
    
    def scan_data(self, data: bytes, identifier: str = "memory") -> Dict[str, Any]:
        """
        Scan data in memory with YARA rules.
        
        Args:
            data: Data bytes to scan
            identifier: Identifier for the data
            
        Returns:
            Scan results
        """
        if not self.rules_loaded or not self.yara_rules:
            return {
                "success": False,
                "error": "YARA rules not loaded",
            }
        
        try:
            
            # Scan data
            matches = self.yara_rules.match(data=data)
            
            # Format results
            results = []
            for match in matches:
                results.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "strings": [
                        {
                            "identifier": str(s.identifier),
                            "offset": s.instances[0].offset if s.instances else 0,
                        }
                        for s in match.strings
                    ],
                    "meta": match.meta,
                })
            
            return {
                "success": True,
                "identifier": identifier,
                "matches": results,
                "match_count": len(results),
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }

