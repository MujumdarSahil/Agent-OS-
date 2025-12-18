"""
Data normalization utilities for cybersecurity operations
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import re


class IOCNormalizer:
    """Normalize Indicators of Compromise"""
    
    @staticmethod
    def normalize_ip(ip: str) -> Optional[str]:
        """
        Normalize IP address.
        
        Args:
            ip: IP address string
            
        Returns:
            Normalized IP or None if invalid
        """
        if not ip:
            return None
        
        # Remove whitespace
        ip = ip.strip()
        
        # Basic IP validation
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(pattern, ip):
            return ip
        
        return None
    
    @staticmethod
    def normalize_domain(domain: str) -> Optional[str]:
        """
        Normalize domain name.
        
        Args:
            domain: Domain string
            
        Returns:
            Normalized domain or None if invalid
        """
        if not domain:
            return None
        
        # Remove protocol if present
        domain = re.sub(r"^https?://", "", domain)
        domain = re.sub(r"^www\.", "", domain)
        
        # Remove path
        domain = domain.split("/")[0]
        domain = domain.split("?")[0]
        
        # Remove port
        domain = domain.split(":")[0]
        
        # Normalize to lowercase
        domain = domain.lower().strip()
        
        # Basic validation
        pattern = r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
        if re.match(pattern, domain):
            return domain
        
        return None
    
    @staticmethod
    def normalize_url(url: str) -> Optional[str]:
        """
        Normalize URL.
        
        Args:
            url: URL string
            
        Returns:
            Normalized URL or None if invalid
        """
        if not url:
            return None
        
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        # Basic validation
        pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        if re.match(pattern, url.lower()):
            return url.lower()
        
        return None
    
    @staticmethod
    def normalize_hash(hash_value: str) -> Optional[str]:
        """
        Normalize hash value.
        
        Args:
            hash_value: Hash string
            
        Returns:
            Normalized hash or None if invalid
        """
        if not hash_value:
            return None
        
        # Remove whitespace and convert to lowercase
        normalized = re.sub(r"\s+", "", hash_value).lower()
        
        # Basic validation (hexadecimal)
        if re.match(r"^[a-f0-9]+$", normalized) and len(normalized) >= 16:
            return normalized
        
        return None
    
    @staticmethod
    def normalize_ioc(ioc: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Normalize an IOC of unknown type.
        
        Args:
            ioc: IOC value
            ioc_type: Optional IOC type hint
            
        Returns:
            Normalized IOC dict
        """
        if not ioc:
            return {
                "value": None,
                "type": None,
                "normalized": False,
            }
        
        # Try to detect type if not provided
        if not ioc_type:
            # Try IP
            normalized_ip = IOCNormalizer.normalize_ip(ioc)
            if normalized_ip:
                return {
                    "value": normalized_ip,
                    "type": "ip",
                    "normalized": True,
                }
            
            # Try domain
            normalized_domain = IOCNormalizer.normalize_domain(ioc)
            if normalized_domain:
                return {
                    "value": normalized_domain,
                    "type": "domain",
                    "normalized": True,
                }
            
            # Try URL
            normalized_url = IOCNormalizer.normalize_url(ioc)
            if normalized_url:
                return {
                    "value": normalized_url,
                    "type": "url",
                    "normalized": True,
                }
            
            # Try hash
            normalized_hash = IOCNormalizer.normalize_hash(ioc)
            if normalized_hash:
                return {
                    "value": normalized_hash,
                    "type": "hash",
                    "normalized": True,
                }
        
        else:
            # Use provided type
            normalizers = {
                "ip": IOCNormalizer.normalize_ip,
                "domain": IOCNormalizer.normalize_domain,
                "url": IOCNormalizer.normalize_url,
                "hash": IOCNormalizer.normalize_hash,
            }
            
            if ioc_type in normalizers:
                normalized = normalizers[ioc_type](ioc)
                if normalized:
                    return {
                        "value": normalized,
                        "type": ioc_type,
                        "normalized": True,
                    }
        
        return {
            "value": ioc,
            "type": ioc_type or "unknown",
            "normalized": False,
        }


class AlertNormalizer:
    """Normalize security alerts"""
    
    @staticmethod
    def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize alert to standard format.
        
        Args:
            alert: Raw alert data
            
        Returns:
            Normalized alert
        """
        normalized = {
            "id": alert.get("id") or alert.get("alert_id"),
            "title": alert.get("title") or alert.get("message") or "Unknown alert",
            "description": alert.get("description") or alert.get("details", ""),
            "severity": alert.get("severity", "low").lower(),
            "source": alert.get("source") or alert.get("source_system", "unknown"),
            "timestamp": alert.get("timestamp") or datetime.now().isoformat(),
            "type": alert.get("type") or alert.get("alert_type", "generic"),
        }
        
        # Normalize IOCs if present
        iocs = []
        for field in ["source_ip", "dest_ip", "src_ip", "destination_ip", "ip"]:
            if field in alert and alert[field]:
                normalized_ioc = IOCNormalizer.normalize_ioc(str(alert[field]), "ip")
                if normalized_ioc["normalized"]:
                    iocs.append(normalized_ioc)
        
        for field in ["domain", "hostname", "url"]:
            if field in alert and alert[field]:
                normalized_ioc = IOCNormalizer.normalize_ioc(str(alert[field]), field)
                if normalized_ioc["normalized"]:
                    iocs.append(normalized_ioc)
        
        normalized["iocs"] = iocs
        
        return normalized

