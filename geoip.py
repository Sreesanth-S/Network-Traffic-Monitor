import requests
import logging
import time
from typing import Optional, Tuple, Dict
from functools import lru_cache
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GeoIPService:
    """Enhanced GeoIP service with caching and rate limiting"""
    
    def __init__(self):
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.last_request_time = {}
        self.rate_limit_delay = 1.0  # Minimum seconds between requests for same IP
        self.request_timeout = 5  # Request timeout in seconds
        self.max_cache_size = 1000
        
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private/local"""
        try:
            if not ip or ip == '-':
                return True
                
            # Handle IPv6
            if ':' in ip:
                return ip.startswith(('::1', 'fe80:', 'fc00:', 'fd00:', '::'))
            
            # Handle IPv4
            parts = ip.split('.')
            if len(parts) != 4:
                return True
                
            try:
                octets = [int(part) for part in parts]
            except ValueError:
                return True
            
            # Check private ranges
            if octets[0] == 10:
                return True
            elif octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            elif octets[0] == 192 and octets[1] == 168:
                return True
            elif octets[0] == 127:  # Loopback
                return True
            elif octets[0] == 169 and octets[1] == 254:  # Link-local
                return True
            elif octets[0] == 0 or octets[0] >= 224:  # Reserved/Multicast
                return True
                
            return False
            
        except Exception as e:
            logger.debug(f"Error checking if IP {ip} is private: {e}")
            return True
    
    def _should_rate_limit(self, ip: str) -> bool:
        """Check if we should rate limit requests for this IP"""
        current_time = time.time()
        
        if ip in self.last_request_time:
            time_diff = current_time - self.last_request_time[ip]
            if time_diff < self.rate_limit_delay:
                return True
        
        self.last_request_time[ip] = current_time
        return False
    
    def _cleanup_cache(self):
        """Clean up cache if it gets too large"""
        with self.cache_lock:
            if len(self.cache) > self.max_cache_size:
                # Remove oldest 20% of entries
                items_to_remove = len(self.cache) // 5
                oldest_keys = list(self.cache.keys())[:items_to_remove]
                for key in oldest_keys:
                    del self.cache[key]
                logger.info(f"Cleaned up {items_to_remove} entries from GeoIP cache")
    
    def _fetch_location_from_api(self, ip: str) -> str:
        """Fetch location from multiple API sources with fallback"""
        apis = [
            {
                'url': f'http://ip-api.com/json/{ip}?fields=status,country,city,regionName',
                'parser': self._parse_ip_api_response
            },
            {
                'url': f'https://ipapi.co/{ip}/json/',
                'parser': self._parse_ipapi_co_response
            },
            {
                'url': f'http://www.geoplugin.net/json.gp?ip={ip}',
                'parser': self._parse_geoplugin_response
            }
        ]
        
        for api in apis:
            try:
                response = requests.get(
                    api['url'],
                    timeout=self.request_timeout,
                    headers={
                        'User-Agent': 'NetworkSecurityMonitor/1.0',
                        'Accept': 'application/json'
                    }
                )
                
                if response.status_code == 200:
                    location = api['parser'](response.json())
                    if location and location != "Unknown Location":
                        logger.debug(f"Got location for {ip}: {location}")
                        return location
                        
            except requests.exceptions.RequestException as e:
                logger.debug(f"API request failed for {ip}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Error parsing response for {ip}: {e}")
                continue
        
        logger.debug(f"All APIs failed for {ip}")
        return "Unknown Location"
    
    def _parse_ip_api_response(self, data: dict) -> str:
        """Parse response from ip-api.com"""
        try:
            if data.get('status') == 'success':
                country = data.get('country', '').strip()
                city = data.get('city', '').strip()
                region = data.get('regionName', '').strip()
                
                if country:
                    if city and city != region:
                        return f"{country} - {city}"
                    elif region:
                        return f"{country} - {region}"
                    else:
                        return country
            return "Unknown Location"
        except Exception as e:
            logger.debug(f"Error parsing ip-api response: {e}")
            return "Unknown Location"
    
    def _parse_ipapi_co_response(self, data: dict) -> str:
        """Parse response from ipapi.co"""
        try:
            if data.get('error') is not True:
                country = data.get('country_name', '').strip()
                city = data.get('city', '').strip()
                region = data.get('region', '').strip()
                
                if country:
                    if city and city != region:
                        return f"{country} - {city}"
                    elif region:
                        return f"{country} - {region}"
                    else:
                        return country
            return "Unknown Location"
        except Exception as e:
            logger.debug(f"Error parsing ipapi.co response: {e}")
            return "Unknown Location"
    
    def _parse_geoplugin_response(self, data: dict) -> str:
        """Parse response from geoplugin.net"""
        try:
            country = data.get('geoplugin_countryName', '').strip()
            city = data.get('geoplugin_city', '').strip()
            region = data.get('geoplugin_regionName', '').strip()
            
            if country and country != 'null':
                if city and city != 'null' and city != region:
                    return f"{country} - {city}"
                elif region and region != 'null':
                    return f"{country} - {region}"
                else:
                    return country
            return "Unknown Location"
        except Exception as e:
            logger.debug(f"Error parsing geoplugin response: {e}")
            return "Unknown Location"
    
    def get_ip_location(self, ip: str) -> str:
        """
        Get location information for an IP address
        Returns formatted string: "Country - City" or appropriate fallback
        """
        try:
            # Validate IP
            if not ip or ip == '-':
                return "Unknown Location"
            
            # Check if private IP
            if self._is_private_ip(ip):
                return "Local Network"
            
            # Check cache first
            with self.cache_lock:
                if ip in self.cache:
                    cached_result = self.cache[ip]
                    if cached_result['timestamp'] + 3600 > time.time():  # Cache for 1 hour
                        return cached_result['location']
                    else:
                        # Remove expired entry
                        del self.cache[ip]
            
            # Rate limiting
            if self._should_rate_limit(ip):
                return "Rate Limited"
            
            # Make API request
            location = self._fetch_location_from_api(ip)
            
            # Cache the result
            with self.cache_lock:
                self.cache[ip] = {
                    'location': location,
                    'timestamp': time.time()
                }
            
            # Cleanup cache if needed
            if len(self.cache) > self.max_cache_size:
                self._cleanup_cache()
            
            return location
            
        except Exception as e:
            logger.error(f"Error getting location for IP {ip}: {e}")
            return "Unknown Location"
    
    def get_cache_stats(self) -> Dict[str, any]:
        """Get cache statistics"""
        with self.cache_lock:
            return {
                'cache_size': len(self.cache),
                'max_cache_size': self.max_cache_size,
                'cache_hit_ratio': len(self.cache) / max(len(self.last_request_time), 1)
            }
    
    def clear_cache(self):
        """Clear the location cache"""
        with self.cache_lock:
            self.cache.clear()
            self.last_request_time.clear()
        logger.info("GeoIP cache cleared")

# Global instance
_geoip_service = GeoIPService()

# Legacy function for backward compatibility
def get_ip_location(ip: str) -> str:
    """Legacy function - use _geoip_service.get_ip_location() for new code"""
    return _geoip_service.get_ip_location(ip)

# Export the service instance
geoip_service = _geoip_service