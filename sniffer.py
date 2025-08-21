import logging
import datetime
import threading
import time
from typing import Dict, Any, Optional
from collections import deque
import json

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, IPv6, Raw, Ether
    from scapy.error import Scapy_Exception
except ImportError as e:
    logging.error(f"Scapy not installed: {e}")
    raise ImportError("Please install scapy: pip install scapy")

from analyzer import analyzer
from logger import log_packet
from geoip import get_ip_location

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self):
        self.is_running = False
        self.packet_count = 0
        self.start_time = None
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'alerts': 0
        }
        self.recent_packets = deque(maxlen=1000)  # Store recent packets for analysis
        self.lock = threading.Lock()
        
    def _extract_payload(self, packet) -> Optional[str]:
        """Safely extract payload from packet"""
        try:
            # Check for Raw layer (contains payload)
            if Raw in packet:
                payload = packet[Raw].load
                # Try to decode as UTF-8, fallback to latin-1 if needed
                try:
                    return payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    return payload.decode('latin-1', errors='ignore')
            
            # Check for specific protocol payloads
            if TCP in packet and hasattr(packet[TCP], 'payload'):
                try:
                    return str(packet[TCP].payload)
                except:
                    pass
                    
            if UDP in packet and hasattr(packet[UDP], 'payload'):
                try:
                    return str(packet[UDP].payload)
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error extracting payload: {e}")
            
        return None
    
    def _serialize_flags(self, flags) -> str:
        """Convert Scapy flags to JSON-serializable string"""
        try:
            if flags is None:
                return ""
            
            # Convert FlagValue object to string representation
            if hasattr(flags, '__str__'):
                flag_str = str(flags)
                # Clean up the string representation if needed
                return flag_str.strip()
            
            # If it's already a string or number, return as string
            return str(flags)
            
        except Exception as e:
            logger.debug(f"Error serializing flags: {e}")
            return ""
    
    def _serialize_value(self, value) -> Any:
        """Convert any non-JSON serializable values to serializable format"""
        try:
            # Test if value is JSON serializable
            json.dumps(value)
            return value
        except (TypeError, ValueError):
            # If not serializable, convert to string
            return str(value) if value is not None else ""
    
    def _get_packet_info(self, packet) -> Dict[str, Any]:
        """Extract comprehensive packet information"""
        info = {
            'src_ip': '-',
            'dst_ip': '-',
            'src_port': '-',
            'dst_port': '-',
            'protocol': 'OTHER',
            'size': len(packet),
            'payload': None,
            'flags': None,
            'ttl': None,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # Handle Ethernet frame
            if Ether in packet:
                info['eth_src'] = packet[Ether].src
                info['eth_dst'] = packet[Ether].dst
            
            # Handle IPv4
            if IP in packet:
                info['src_ip'] = packet[IP].src
                info['dst_ip'] = packet[IP].dst
                info['ttl'] = packet[IP].ttl
                info['ip_version'] = 4
                
                # Handle TCP
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    # Properly serialize flags
                    info['flags'] = self._serialize_flags(packet[TCP].flags)
                    info['seq'] = packet[TCP].seq
                    info['ack'] = packet[TCP].ack
                    
                # Handle UDP
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
                    info['length'] = packet[UDP].len
                    
                # Handle ICMP
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    info['icmp_type'] = packet[ICMP].type
                    info['icmp_code'] = packet[ICMP].code
            
            # Handle IPv6
            elif IPv6 in packet:
                info['src_ip'] = packet[IPv6].src
                info['dst_ip'] = packet[IPv6].dst
                info['protocol'] = 'IPv6'
                info['ip_version'] = 6
                info['hop_limit'] = packet[IPv6].hlim
                
                # Check for TCP/UDP over IPv6
                if TCP in packet:
                    info['protocol'] = 'TCP6'
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    info['flags'] = self._serialize_flags(packet[TCP].flags)
                elif UDP in packet:
                    info['protocol'] = 'UDP6'
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
            
            # Handle ARP
            elif ARP in packet:
                info['protocol'] = 'ARP'
                info['src_ip'] = packet[ARP].psrc
                info['dst_ip'] = packet[ARP].pdst
                info['arp_op'] = packet[ARP].op
                info['src_mac'] = packet[ARP].hwsrc
                info['dst_mac'] = packet[ARP].hwdst
            
            # Extract payload
            info['payload'] = self._extract_payload(packet)
            
            # Ensure all values are JSON serializable
            for key, value in info.items():
                info[key] = self._serialize_value(value)
            
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
        
        return info
    
    def packet_callback(self, packet, socketio, packet_store, store_lock, max_stored_packets):
        """Enhanced packet callback with better error handling and JSON serialization"""
        try:
            # Extract packet information
            packet_info = self._get_packet_info(packet)
            
            # Get geolocation (only for external IPs)
            location = "Local Network"
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            
            if src_ip != '-' and not self._is_private_ip(src_ip):
                location = get_ip_location(src_ip)
            elif dst_ip != '-' and not self._is_private_ip(dst_ip):
                location = get_ip_location(dst_ip)
            
            # Analyze packet for threats
            analysis_result = analyzer.analyze_packet(
                src_ip=packet_info['src_ip'],
                dst_ip=packet_info['dst_ip'],
                src_port=packet_info['src_port'] if packet_info['src_port'] != '-' else None,
                dst_port=packet_info['dst_port'] if packet_info['dst_port'] != '-' else None,
                protocol=packet_info['protocol'],
                payload=packet_info['payload'],
                packet_size=packet_info['size']
            )
            
            # Prepare packet data for transmission - ensure all values are JSON serializable
            packet_data = {
                'src_ip': self._serialize_value(packet_info['src_ip']),
                'dst_ip': self._serialize_value(packet_info['dst_ip']),
                'src_port': self._serialize_value(packet_info['src_port']),
                'dst_port': self._serialize_value(packet_info['dst_port']),
                'protocol': self._serialize_value(packet_info['protocol']),
                'location': self._serialize_value(location),
                'alert': self._serialize_value(analysis_result['alert']),
                'alert_level': self._serialize_value(analysis_result['alert_level']),
                'risk_score': self._serialize_value(analysis_result['risk_score']),
                'size': self._serialize_value(packet_info['size']),
                'timestamp': self._serialize_value(packet_info['timestamp']),
                'flags': self._serialize_value(packet_info.get('flags')),
                'ttl': self._serialize_value(packet_info.get('ttl'))
            }
            
            # Verify JSON serializability before proceeding
            try:
                json.dumps(packet_data)
            except (TypeError, ValueError) as e:
                logger.error(f"Packet data still not JSON serializable: {e}")
                # Create a minimal safe packet data
                packet_data = {
                    'src_ip': str(packet_info.get('src_ip', '-')),
                    'dst_ip': str(packet_info.get('dst_ip', '-')),
                    'src_port': str(packet_info.get('src_port', '-')),
                    'dst_port': str(packet_info.get('dst_port', '-')),
                    'protocol': str(packet_info.get('protocol', 'OTHER')),
                    'location': str(location),
                    'alert': str(analysis_result.get('alert', 'None')),
                    'alert_level': str(analysis_result.get('alert_level', 'Unknown')),
                    'risk_score': int(analysis_result.get('risk_score', 0)),
                    'size': int(packet_info.get('size', 0)),
                    'timestamp': str(packet_info.get('timestamp', datetime.datetime.now().isoformat())),
                    'flags': str(packet_info.get('flags', '')),
                    'ttl': str(packet_info.get('ttl', ''))
                }
            
            # Update statistics
            with self.lock:
                self.packet_count += 1
                self.stats['total_packets'] += 1
                
                if packet_info['protocol'].startswith('TCP'):
                    self.stats['tcp_packets'] += 1
                elif packet_info['protocol'].startswith('UDP'):
                    self.stats['udp_packets'] += 1
                elif packet_info['protocol'] == 'ICMP':
                    self.stats['icmp_packets'] += 1
                else:
                    self.stats['other_packets'] += 1
                
                if analysis_result['alert'] != 'None':
                    self.stats['alerts'] += 1
                
                # Store recent packet for analysis
                self.recent_packets.append(packet_data.copy())
            
            # Store packet with thread safety
            with store_lock:
                packet_store.append(packet_data)
                if len(packet_store) > max_stored_packets:
                    packet_store.pop(0)  # Remove oldest packet
                
                # Emit to clients with better error handling
                try:
                    socketio.emit('packet', packet_data)
                    
                    # Emit IP statistics periodically
                    if self.packet_count % 50 == 0:  # Every 50 packets
                        ip_stats = analyzer.get_ip_stats()
                        # Ensure IP stats are also JSON serializable
                        serializable_ip_stats = {
                            str(k): self._serialize_value(v) for k, v in ip_stats.items()
                        }
                        socketio.emit('ip_counts', serializable_ip_stats)
                        
                    # Emit server statistics
                    if self.packet_count % 100 == 0:  # Every 100 packets
                        server_stats = self._get_server_stats()
                        socketio.emit('server_stats', server_stats)
                        
                except Exception as e:
                    logger.error(f"Error emitting packet data: {e}")
                    logger.error(f"Problematic packet data: {packet_data}")
            
            # Log packet (with error handling in logger)
            try:
                log_packet(packet_data)
            except Exception as e:
                logger.error(f"Error logging packet: {e}")
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            # Don't let packet processing errors stop the sniffer
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            if ip == '-' or not ip:
                return True
                
            # Handle IPv6 addresses
            if ':' in ip:
                return ip.startswith(('::1', 'fe80:', 'fc00:', 'fd00:'))
            
            # Handle IPv4 addresses
            parts = ip.split('.')
            if len(parts) != 4:
                return True
                
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            return (
                first_octet == 10 or
                (first_octet == 172 and 16 <= second_octet <= 31) or
                (first_octet == 192 and second_octet == 168) or
                ip.startswith('127.') or
                ip == '0.0.0.0' or
                ip == '255.255.255.255'
            )
        except (ValueError, IndexError):
            return True
    
    def _get_server_stats(self) -> Dict[str, Any]:
        """Get comprehensive server statistics"""
        with self.lock:
            uptime = (datetime.datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            
            stats = {
                'total_packets': self.stats['total_packets'],
                'tcp_packets': self.stats['tcp_packets'],
                'udp_packets': self.stats['udp_packets'],
                'icmp_packets': self.stats['icmp_packets'],
                'other_packets': self.stats['other_packets'],
                'alerts': self.stats['alerts'],
                'packets_per_second': round(self.packet_count / max(uptime, 1), 2),
                'uptime_seconds': round(uptime),
                'suspicious_ips': len(analyzer.get_suspicious_ips()),
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            # Ensure all values are JSON serializable
            return {k: self._serialize_value(v) for k, v in stats.items()}
    
    def start_sniffing(self, socketio, packet_store, store_lock, max_stored_packets, 
                      interface=None, filter_str=None):
        """Start packet capture with enhanced configuration"""
        if self.is_running:
            logger.warning("Sniffer is already running")
            return
        
        self.is_running = True
        self.start_time = datetime.datetime.now()
        
        logger.info("[*] Starting enhanced packet capture...")
        logger.info(f"[*] Interface: {interface or 'default'}")
        logger.info(f"[*] Filter: {filter_str or 'none'}")
        logger.info(f"[*] Max stored packets: {max_stored_packets}")
        
        try:
            # Configure sniffing parameters
            sniff_params = {
                'prn': lambda pkt: self.packet_callback(
                    pkt, socketio, packet_store, store_lock, max_stored_packets
                ),
                'store': False,  # Don't store packets in memory (we handle this ourselves)
                'stop_filter': lambda x: not self.is_running
            }
            
            # Add interface if specified
            if interface:
                sniff_params['iface'] = interface
            
            # Add filter if specified
            if filter_str:
                sniff_params['filter'] = filter_str
            
            # Start sniffing
            sniff(**sniff_params)
            
        except PermissionError:
            logger.error("Permission denied. Run as administrator/root for packet capture.")
            socketio.emit('error', {
                'type': 'permission_error',
                'message': 'Permission denied. Please run as administrator.'
            })
        except Scapy_Exception as e:
            logger.error(f"Scapy error: {e}")
            socketio.emit('error', {
                'type': 'scapy_error',
                'message': f'Scapy error: {str(e)}'
            })
        except Exception as e:
            logger.error(f"Unexpected error in packet capture: {e}")
            socketio.emit('error', {
                'type': 'capture_error',
                'message': f'Capture error: {str(e)}'
            })
        finally:
            self.is_running = False
            logger.info("[*] Packet capture stopped")
    
    def stop_sniffing(self):
        """Stop packet capture"""
        logger.info("[*] Stopping packet capture...")
        self.is_running = False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return self._get_server_stats()
    
    def get_recent_packets(self, count: int = 100) -> list:
        """Get recent packets for analysis"""
        with self.lock:
            return list(self.recent_packets)[-count:]

# Global sniffer instance
sniffer = PacketSniffer()

# Legacy function for backward compatibility
def start_sniffing(socketio, packet_store, store_lock, max_stored_packets):
    """Legacy function - use sniffer.start_sniffing() for new code"""
    sniffer.start_sniffing(socketio, packet_store, store_lock, max_stored_packets)