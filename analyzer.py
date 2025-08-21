import re
import os
import logging
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Set

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self):
        self.blacklist = self._load_blacklist()
        self.ip_frequency = defaultdict(int)
        self.suspicious_ips = set()
        self.lock = Lock()
        
        # Expanded suspicious ports list
        self.blacklisted_ports = {
            # Common attack ports
            1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 138, 139, 143, 161, 179, 389, 427, 443, 444, 445, 465, 513, 514, 515, 518, 540, 548, 554, 587, 593, 631, 636, 993, 995,
            # Trojan/malware ports
            666, 1001, 1011, 1024, 1025, 1033, 1040, 1050, 1080, 1220, 1234, 1243, 1245, 1492, 1509, 1524, 1600, 1807, 1981, 1999, 2000, 2001, 2023, 2115, 2140, 2300, 2989, 3024, 3129, 3150, 3700, 4000, 4321, 4444, 4567, 4950, 5000, 5001, 5321, 5400, 5401, 5402, 5569, 5742, 6000, 6001, 6400, 6667, 6669, 6670, 6711, 6712, 6713, 6776, 6969, 7000, 7300, 7301, 7306, 7307, 7308, 7789, 8080, 8081, 8443, 8888, 9400, 9999, 10000, 10005, 10008, 11000, 11223, 12076, 12223, 12345, 12346, 16969, 20000, 20001, 20034, 21554, 22222, 23456, 26274, 27374, 27444, 27573, 30100, 31337, 31338, 31339, 31666, 33333, 34324, 40412, 40421, 40422, 40423, 40426, 47262, 50505, 50766, 53001, 54283, 54320, 54321, 61466, 65000
        }
        
        # Enhanced suspicious patterns
        self.suspicious_patterns = {
            'SQL Injection': [
                r"('|\"|;|--|\/\*|\*\/)",
                r"\b(union|select|insert|delete|update|drop|exec|execute|xp_|sp_)\b",
                r"\b(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
                r"\b(having|group\s+by|order\s+by)\b",
                r"(char|ascii|substring|length)\s*\("
            ],
            'XSS Attempt': [
                r"<\s*script[^>]*>",
                r"javascript\s*:",
                r"on(load|error|click|mouseover|focus|blur)\s*=",
                r"<\s*(iframe|object|embed|applet)[^>]*>",
                r"expression\s*\(",
                r"vbscript\s*:",
                r"<\s*meta[^>]*http-equiv"
            ],
            'RCE Attempt': [
                r"(\/bin\/bash|\/bin\/sh|cmd\.exe|powershell\.exe)",
                r"(wget|curl|nc|netcat|telnet)\s+",
                r"(echo|cat|ls|dir|type)\s+",
                r"(\||&|;|`|\$\(|\$\{)",
                r"(chmod|chown|rm|del|format)\s+",
                r"(\/etc\/passwd|\/etc\/shadow|boot\.ini|win\.ini)"
            ],
            'Path Traversal': [
                r"(\.\.[\/\\]){2,}",
                r"(\/etc\/|\\windows\\|\\system32\\)",
                r"(\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)",
                r"(\/proc\/|\/sys\/|\/dev\/)"
            ],
            'LDAP Injection': [
                r"(\*\)|\(\||\(&)",
                r"\)\(\|",
                r"\(\!\(",
                r"(objectclass=\*|cn=\*|uid=\*)"
            ],
            'NoSQL Injection': [
                r"(\$ne|\$gt|\$lt|\$in|\$nin|\$regex|\$where)",
                r"(true|false),\s*\$where",
                r"\{\s*\$\w+\s*:"
            ]
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = {
            'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar', 'msi', 'dll'
        }
        
        # Port scan detection thresholds
        self.SCAN_THRESHOLD = 20  # packets per IP
        self.SCAN_TIME_WINDOW = 300  # 5 minutes
        
    def _load_blacklist(self) -> Set[str]:
        """Load blacklist from file with error handling"""
        blacklist = set()
        blacklist_file = 'blacklist.txt'
        
        try:
            if os.path.exists(blacklist_file):
                with open(blacklist_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        entry = line.strip()
                        if entry and not entry.startswith('#'):
                            blacklist.add(entry)
                logger.info(f"Loaded {len(blacklist)} entries from blacklist")
            else:
                # Create default blacklist file
                self._create_default_blacklist(blacklist_file)
                logger.warning(f"Created default blacklist file: {blacklist_file}")
        except Exception as e:
            logger.error(f"Error loading blacklist: {e}")
            
        return blacklist
    
    def _create_default_blacklist(self, filename: str):
        """Create a default blacklist file with common malicious IPs/domains"""
        default_entries = [
            "# Default blacklist - add suspicious IPs and domains",
            "# Format: one entry per line",
            "0.0.0.0",
            "127.0.0.1",
            "192.168.0.1",
            "10.0.0.1",
            "malware.example.com",
            "phishing.example.com"
        ]
        
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write('\n'.join(default_entries))
        except Exception as e:
            logger.error(f"Error creating default blacklist: {e}")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
                
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Private IP ranges
            if first_octet == 10:
                return True
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return True
            elif first_octet == 192 and second_octet == 168:
                return True
            elif ip.startswith('127.'):
                return True
                
        except (ValueError, IndexError):
            pass
            
        return False
    
    def _check_payload_patterns(self, payload: str) -> List[str]:
        """Check payload against suspicious patterns"""
        alerts = []
        if not payload:
            return alerts
            
        payload_lower = payload.lower()
        
        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, payload_lower, re.IGNORECASE | re.MULTILINE):
                        alerts.append(threat_type)
                        break  # Only add each threat type once
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        
        return alerts
    
    def _check_suspicious_extensions(self, payload: str) -> bool:
        """Check for suspicious file extensions in payload"""
        if not payload:
            return False
            
        for ext in self.suspicious_extensions:
            if f'.{ext}' in payload.lower():
                return True
        return False
    
    def _update_ip_frequency(self, src_ip: str) -> bool:
        """Update IP frequency and detect potential scanning"""
        with self.lock:
            self.ip_frequency[src_ip] += 1
            count = self.ip_frequency[src_ip]
            
            # Mark as suspicious if exceeds threshold
            if count > self.SCAN_THRESHOLD:
                self.suspicious_ips.add(src_ip)
                return True
                
        return False
    
    def analyze_packet(self, src_ip: str, dst_ip: str = None, src_port: int = None, 
                      dst_port: int = None, protocol: str = None, payload: str = None,
                      packet_size: int = 0) -> Dict[str, any]:
        """
        Comprehensive packet analysis
        Returns dict with alert information and risk score
        """
        alerts = []
        risk_score = 0
        alert_details = {}
        
        try:
            # Validate inputs
            if not src_ip:
                return {"alert": "None", "risk_score": 0, "details": {}}
            
            # Check blacklisted IP
            if src_ip in self.blacklist:
                alerts.append("Blacklisted IP")
                risk_score += 10
                alert_details['blacklisted_ip'] = True
            
            # Check blacklisted domain in payload
            if payload:
                for blacklisted_item in self.blacklist:
                    if '.' in blacklisted_item and blacklisted_item in payload.lower():
                        alerts.append("Blacklisted Domain")
                        risk_score += 8
                        break
            
            # Check suspicious ports
            if dst_port and (dst_port in self.blacklisted_ports or str(dst_port) in self.blacklist):
                alerts.append("Suspicious Port")
                risk_score += 5
                alert_details['suspicious_port'] = dst_port
            
            # Check for port scanning
            if not self._is_private_ip(src_ip):
                is_scanning = self._update_ip_frequency(src_ip)
                if is_scanning:
                    alerts.append("Possible Port Scan")
                    risk_score += 7
                    alert_details['scan_count'] = self.ip_frequency[src_ip]
            
            # Analyze payload for suspicious patterns
            if payload:
                payload_alerts = self._check_payload_patterns(payload)
                alerts.extend(payload_alerts)
                risk_score += len(payload_alerts) * 6
                
                if payload_alerts:
                    alert_details['payload_threats'] = payload_alerts
                
                # Check for suspicious file extensions
                if self._check_suspicious_extensions(payload):
                    alerts.append("Suspicious File Extension")
                    risk_score += 4
            
            # Check for unusual packet sizes
            if packet_size > 65535:  # Jumbo frames might be suspicious
                alerts.append("Unusual Packet Size")
                risk_score += 2
                alert_details['packet_size'] = packet_size
            
            # Check for protocol anomalies
            if protocol:
                if protocol.upper() in ['ICMP'] and packet_size > 1500:
                    alerts.append("ICMP Flood Potential")
                    risk_score += 3
                elif protocol.upper() in ['UDP'] and dst_port in [53, 123, 137] and packet_size > 512:
                    alerts.append("Amplification Attack Potential")
                    risk_score += 4
            
            # Determine overall alert level
            if not alerts:
                alert_level = "None"
            elif risk_score >= 15:
                alert_level = "Critical"
            elif risk_score >= 10:
                alert_level = "High"
            elif risk_score >= 5:
                alert_level = "Medium"
            else:
                alert_level = "Low"
            
            # Combine alerts
            alert_message = ", ".join(alerts) if alerts else "None"
            
            return {
                "alert": alert_message,
                "alert_level": alert_level,
                "risk_score": min(risk_score, 100),  # Cap at 100
                "details": alert_details,
                "threat_count": len(alerts)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing packet from {src_ip}: {e}")
            return {
                "alert": "Analysis Error",
                "alert_level": "Unknown", 
                "risk_score": 0,
                "details": {"error": str(e)},
                "threat_count": 0
            }
    
    def get_suspicious_ips(self) -> Dict[str, int]:
        """Get list of suspicious IPs with their packet counts"""
        with self.lock:
            return {ip: count for ip, count in self.ip_frequency.items() 
                   if ip in self.suspicious_ips}
    
    def get_ip_stats(self) -> Dict[str, int]:
        """Get IP frequency statistics"""
        with self.lock:
            return dict(self.ip_frequency.copy())
    
    def add_to_blacklist(self, entry: str) -> bool:
        """Add entry to blacklist and save to file"""
        try:
            if entry and entry not in self.blacklist:
                self.blacklist.add(entry)
                
                # Append to file
                with open('blacklist.txt', 'a', encoding='utf-8') as file:
                    file.write(f"\n{entry}")
                
                logger.info(f"Added {entry} to blacklist")
                return True
        except Exception as e:
            logger.error(f"Error adding to blacklist: {e}")
        return False
    
    def clear_ip_frequency(self):
        """Clear IP frequency data (useful for periodic cleanup)"""
        with self.lock:
            self.ip_frequency.clear()
            self.suspicious_ips.clear()
        logger.info("Cleared IP frequency data")

# Global analyzer instance
analyzer = SecurityAnalyzer()

# Legacy function for backward compatibility
def analyze_packet(src_ip, dst_port, payload=None):
    """Legacy function - use analyzer.analyze_packet() for new code"""
    result = analyzer.analyze_packet(src_ip=src_ip, dst_port=dst_port, payload=payload)
    return result["alert"]