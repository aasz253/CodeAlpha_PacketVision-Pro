"""
PacketVision Pro - GeoIP Lookup Module
=======================================

Provides IP geolocation lookups using the free ip-api.com API.
Results are cached in memory to avoid repeated network requests.
Private/reserved IPs are identified locally without API calls.

The module runs lookups in a background thread to avoid blocking the GUI.
"""

import logging
import threading
import time
from typing import Dict, Optional, Tuple

try:
    import urllib.request
    import json as _json
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

logger = logging.getLogger(__name__)

# Country flag emoji from 2-letter code (regional indicator symbols)
def _code_to_flag(code: str) -> str:
    """Convert 2-letter country code to flag emoji."""
    if not code or len(code) != 2:
        return ""
    return chr(0x1F1E6 + ord(code[0].upper()) - ord('A')) + \
           chr(0x1F1E6 + ord(code[1].upper()) - ord('A'))


# Private IP ranges
_PRIVATE_PREFIXES = ('10.', '127.', '169.254.', '192.168.')
_PRIVATE_RANGES = [('172.16.', '172.31.')]


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is private/reserved."""
    if not ip:
        return True
    for prefix in _PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return True
    for start, end in _PRIVATE_RANGES:
        if ip.startswith(start[:7]) or ip.startswith(end[:7]):
            return True
    if ip.startswith('0.') or ip.startswith('255.'):
        return True
    return False


class GeoIPLookup:
    """
    Thread-safe GeoIP lookup with caching.
    
    Uses ip-api.com (free, no key required, 45 req/min limit).
    Private IPs are resolved locally without network calls.
    """

    API_URL = "http://ip-api.com/json/{}?fields=status,country,countryCode,city,org"
    CACHE_TTL = 3600  # 1 hour
    BATCH_SIZE = 100

    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._cache_times: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._pending: list = []
        self._batch_timer: Optional[threading.Timer] = None

    def lookup(self, ip: str) -> Dict[str, str]:
        """
        Get geolocation for an IP address.
        Returns dict with keys: country, country_code, city, org, flag.
        Results are cached; private IPs return instantly.
        """
        if not ip or _is_private_ip(ip):
            return {'country': 'Private', 'country_code': '', 'city': 'Local', 'org': '', 'flag': ''}

        # Check cache
        with self._lock:
            if ip in self._cache:
                if time.time() - self._cache_times.get(ip, 0) < self.CACHE_TTL:
                    return self._cache[ip]
                else:
                    del self._cache[ip]
                    del self._cache_times[ip]

        # For private IPs in disguise or unreachable, return immediately
        result = {'country': 'Unknown', 'country_code': '', 'city': '', 'org': '', 'flag': ''}

        # Queue for batch lookup
        self._queue_lookup(ip)
        return result

    def lookup_sync(self, ip: str) -> Dict[str, str]:
        """Synchronous lookup (blocks). Use sparingly."""
        if not ip or _is_private_ip(ip):
            return {'country': 'Private', 'country_code': '', 'city': 'Local', 'org': '', 'flag': ''}

        with self._lock:
            if ip in self._cache and time.time() - self._cache_times.get(ip, 0) < self.CACHE_TTL:
                return self._cache[ip]

        result = self._fetch_single(ip)
        if result:
            with self._lock:
                self._cache[ip] = result
                self._cache_times[ip] = time.time()
            return result
        return {'country': 'Unknown', 'country_code': '', 'city': '', 'org': '', 'flag': ''}

    def _queue_lookup(self, ip: str):
        """Add IP to batch lookup queue."""
        with self._lock:
            if ip not in self._pending:
                self._pending.append(ip)
            if len(self._pending) >= self.BATCH_SIZE:
                self._flush_batch()
            elif self._batch_timer is None or not self._batch_timer.is_alive():
                self._batch_timer = threading.Timer(2.0, self._flush_batch)
                self._batch_timer.daemon = True
                self._batch_timer.start()

    def _flush_batch(self):
        """Send batch lookup request."""
        with self._lock:
            if not self._pending:
                return
            ips = list(self._pending[:self.BATCH_SIZE])
            self._pending = self._pending[self.BATCH_SIZE:]
            self._batch_timer = None

        threading.Thread(target=self._fetch_batch, args=(ips,), daemon=True).start()

    def _fetch_batch(self, ips: list):
        """Fetch geolocation for multiple IPs (background thread)."""
        if not HAS_URLLIB:
            return
        try:
            # ip-api.com supports comma-separated batch
            query = ','.join(ips[:self.BATCH_SIZE])
            url = f"http://ip-api.com/batch?fields=status,country,countryCode,city,org,query"
            
            import json
            data = json.dumps([{"query": ip} for ip in ips[:self.BATCH_SIZE]]).encode('utf-8')
            req = urllib.request.Request(url, data=data, 
                                       headers={'Content-Type': 'application/json'})
            
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = _json.loads(resp.read().decode('utf-8'))
            
            with self._lock:
                for item in results:
                    if item.get('status') == 'success':
                        ip = item.get('query', '')
                        code = item.get('countryCode', '')
                        result = {
                            'country': item.get('country', 'Unknown'),
                            'country_code': code,
                            'city': item.get('city', ''),
                            'org': item.get('org', ''),
                            'flag': _code_to_flag(code),
                        }
                        self._cache[ip] = result
                        self._cache_times[ip] = time.time()
        except Exception as e:
            logger.debug(f"GeoIP batch lookup failed: {e}")

    def _fetch_single(self, ip: str) -> Optional[Dict]:
        """Fetch geolocation for a single IP."""
        if not HAS_URLLIB:
            return None
        try:
            url = self.API_URL.format(ip)
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                code = data.get('countryCode', '')
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': code,
                    'city': data.get('city', ''),
                    'org': data.get('org', ''),
                    'flag': _code_to_flag(code),
                }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        return None

    def format_ip(self, ip: str) -> str:
        """Format IP with flag emoji for display. e.g. '🇺🇸 1.2.3.4'"""
        geo = self.lookup(ip)
        if geo['flag']:
            return f"{geo['flag']} {ip}"
        return ip
