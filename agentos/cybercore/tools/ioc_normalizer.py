"""
IOC normalizer - Normalize and sanitize IOCs
"""

from typing import Dict, Any, List, Optional
from agentos.cybercore.utils.normalization import IOCNormalizer


class IOCNormalizerTool:
    """Tool for normalizing IOCs"""
    
    @staticmethod
    def normalize(ioc: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Normalize a single IOC.
        
        Args:
            ioc: IOC value
            ioc_type: Optional IOC type hint
            
        Returns:
            Normalized IOC
        """
        return IOCNormalizer.normalize_ioc(ioc, ioc_type)
    
    @staticmethod
    def normalize_batch(iocs: List[str], ioc_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Normalize multiple IOCs.
        
        Args:
            iocs: List of IOC values
            ioc_types: Optional list of IOC types
            
        Returns:
            List of normalized IOCs
        """
        results = []
        for i, ioc in enumerate(iocs):
            ioc_type = ioc_types[i] if ioc_types and i < len(ioc_types) else None
            results.append(IOCNormalizer.normalize_ioc(ioc, ioc_type))
        
        return results
    
    @staticmethod
    def extract_iocs_from_text(text: str) -> List[Dict[str, Any]]:
        """
        Extract and normalize IOCs from text.
        
        Args:
            text: Text to extract IOCs from
            
        Returns:
            List of normalized IOCs
        """
        import re
        
        iocs = []
        
        # Extract IPs
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ips = re.findall(ip_pattern, text)
        for ip in ips:
            normalized = IOCNormalizer.normalize_ioc(ip, "ip")
            if normalized["normalized"]:
                iocs.append(normalized)
        
        # Extract domains
        domain_pattern = r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
        domains = re.findall(domain_pattern, text.lower())
        for domain in domains:
            normalized = IOCNormalizer.normalize_ioc(domain, "domain")
            if normalized["normalized"]:
                iocs.append(normalized)
        
        # Extract URLs
        url_pattern = r"https?://[^\s]+"
        urls = re.findall(url_pattern, text.lower())
        for url in urls:
            normalized = IOCNormalizer.normalize_ioc(url, "url")
            if normalized["normalized"]:
                iocs.append(normalized)
        
        # Extract hashes
        hash_pattern = r"\b[a-f0-9]{32,128}\b"
        hashes = re.findall(hash_pattern, text.lower())
        for hash_val in hashes:
            normalized = IOCNormalizer.normalize_ioc(hash_val, "hash")
            if normalized["normalized"]:
                iocs.append(normalized)
        
        return iocs
    
    @staticmethod
    def create_ioc_report(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create IOC report from normalized IOCs.
        
        Args:
            iocs: List of normalized IOCs
            
        Returns:
            IOC report
        """
        by_type = {}
        normalized_count = 0
        
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in by_type:
                by_type[ioc_type] = []
            by_type[ioc_type].append(ioc["value"])
            
            if ioc.get("normalized"):
                normalized_count += 1
        
        return {
            "total_iocs": len(iocs),
            "normalized_count": normalized_count,
            "by_type": by_type,
            "types": list(by_type.keys()),
        }

