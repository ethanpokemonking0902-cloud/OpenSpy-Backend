"""Reverse DNS Scanner"""

import socket
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class RDNSScanner:
    """Perform reverse DNS lookups on IP addresses"""
    
    def __init__(self):
        self.timeout = 10
        socket.setdefaulttimeout(self.timeout)
    
    def scan(self, target: str) -> dict:
        """
        Reverse DNS lookup - resolve IP to hostname
        """
        try:
            result = {
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'hostname': None,
                'records': []
            }
            
            # Try reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(target)
                result['hostname'] = hostname[0]
                result['aliases'] = hostname[1] if len(hostname) > 1 else []
                result['addresses'] = hostname[2] if len(hostname) > 2 else []
            except socket.herror as e:
                result['error'] = f'Reverse DNS lookup failed: {str(e)}'
            except socket.gaierror as e:
                result['error'] = f'Address error: {str(e)}'
            
            # Try forward resolution to verify
            try:
                forward_lookup = socket.gethostbyname(target)
                result['forward_lookup'] = forward_lookup
            except:
                pass
            
            return result
        except Exception as e:
            logger.error(f"RDNS scan error: {str(e)}")
            return {
                'error': str(e),
                'target': target,
                'timestamp': datetime.utcnow().isoformat()
            }
