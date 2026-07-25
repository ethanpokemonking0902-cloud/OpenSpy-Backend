"""SSL/TLS Certificate Scanner

Uses multiple APIs:
- ssl/socket: Certificate extraction (free)
- cryptography: Certificate parsing (free)
- IPQualityScore: Domain threat analysis, malware detection

Requires:
- IPQUALITYSCORE_KEY: https://www.ipqualityscore.com
"""

import ssl
import socket
import requests
import os
from datetime import datetime
import logging
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

# Load API key from environment
IPQUALITYSCORE_KEY = os.getenv('IPQUALITYSCORE_KEY', '')

class SSLScanner:
    """Scan SSL/TLS certificates and domain threat data"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, target: str) -> dict:
        """
        Scan SSL/TLS certificate + threat analysis - extract host from target
        """
        host = target.split(':')[0] if ':' in target else target
        port = 443
        
        try:
            # Try to extract port if provided
            if ':' in target:
                try:
                    port = int(target.split(':')[1])
                except:
                    port = 443
            
            cert_data = self._get_certificate(host, port)
            threat_data = self._get_domain_threat(host)
            
            if cert_data:
                result = {
                    'host': host,
                    'port': port,
                    'timestamp': datetime.utcnow().isoformat(),
                    'certificate': cert_data,
                    'threat_analysis': threat_data,
                    'status': 'ok'
                }
            else:
                result = {
                    'host': host,
                    'port': port,
                    'error': 'Could not retrieve certificate',
                    'threat_analysis': threat_data,
                    'status': 'failed'
                }
            return result
        except Exception as e:
            logger.error(f"SSL scan error: {str(e)}")
            return {
                'host': host,
                'port': port,
                'error': str(e),
                'status': 'error'
            }
    
    def _get_certificate(self, host: str, port: int) -> dict:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # Parse certificate
                    cert = x509.load_pem_x509_certificate(cert_pem.encode())
                    
                    # Extract information - safely get subject and issuer
                    try:
                        subject = {attr.rfc4514_string(): str(attr.value) for attr in cert.subject}
                    except:
                        subject = {}
                    
                    # Get SANs
                    sans = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = [name.value for name in san_ext.value]
                    except:
                        pass
                    
                    # Get issuers - safely
                    try:
                        issuer = {attr.rfc4514_string(): str(attr.value) for attr in cert.issuer}
                    except:
                        issuer = {}
                    
                    # Get valid dates - handle both UTC and non-UTC versions
                    try:
                        not_valid_before = cert.not_valid_before_utc
                    except AttributeError:
                        not_valid_before = cert.not_valid_before
                    
                    try:
                        not_valid_after = cert.not_valid_after_utc
                    except AttributeError:
                        not_valid_after = cert.not_valid_after
                    
                    result = {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_valid_before': not_valid_before.isoformat(),
                        'not_valid_after': not_valid_after.isoformat(),
                        'subject_alt_names': [str(s) for s in sans],
                        'public_key_size': cert.public_key().key_size,
                        'signature_algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
                        'is_valid': not_valid_after > datetime.utcnow(),
                        'days_until_expiry': (not_valid_after - datetime.utcnow()).days,
                    }
                    
                    return result
        except Exception as e:
            logger.error(f"Certificate extraction error: {str(e)}")
            return None
    
    def _get_domain_threat(self, domain: str) -> dict:
        """Get domain threat analysis using IPQualityScore"""
        if not IPQUALITYSCORE_KEY:
            return {'status': 'api_key_missing', 'note': 'Set IPQUALITYSCORE_KEY in .env'}
        
        try:
            # Remove www and protocol if present
            domain_clean = domain.replace('www.', '').replace('https://', '').replace('http://', '').split('/')[0]
            
            url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_KEY}/{domain_clean}"
            
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                
                return {
                    'domain': domain_clean,
                    'fraud_score': data.get('fraud_score'),  # 0-100
                    'is_suspicious': data.get('suspicious'),
                    'phishing': data.get('phishing'),
                    'malware': data.get('malware'),
                    'parkingpage': data.get('parkingpage'),
                    'spyware': data.get('spyware'),
                    'dns_valid': data.get('dns_valid'),
                    'domain_rank': data.get('domain_rank'),
                    'status': 'found'
                }
            return {'status': 'error', 'error': f'API returned {resp.status_code}'}
        except Exception as e:
            logger.debug(f"Domain threat analysis error: {str(e)}")
            return {'status': 'error', 'error': str(e)}

    def scan_headers(self, target: str) -> dict:
        """
        Scan HTTP security headers
        """
        try:
            from urllib.parse import urlparse
            
            # Ensure we have a valid URL
            if not target.startswith('http://') and not target.startswith('https://'):
                target = f'https://{target}'
            
            # Try both https and http if https fails
            try:
                response = requests.head(target, timeout=self.timeout, allow_redirects=True)
            except:
                target_http = target.replace('https://', 'http://')
                response = requests.head(target_http, timeout=self.timeout, allow_redirects=True)
            
            headers = response.headers
            
            # Check for security headers
            security_headers = {
                'strict-transport-security': headers.get('Strict-Transport-Security'),
                'content-security-policy': headers.get('Content-Security-Policy'),
                'x-content-type-options': headers.get('X-Content-Type-Options'),
                'x-frame-options': headers.get('X-Frame-Options'),
                'x-xss-protection': headers.get('X-XSS-Protection'),
                'referrer-policy': headers.get('Referrer-Policy'),
                'permissions-policy': headers.get('Permissions-Policy'),
                'access-control-allow-origin': headers.get('Access-Control-Allow-Origin'),
            }
            
            result = {
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'status_code': response.status_code,
                'security_headers': {k: v for k, v in security_headers.items() if v is not None},
                'missing_headers': [k for k, v in security_headers.items() if v is None],
                'all_headers': dict(headers),
            }
            
            return result
        except Exception as e:
            logger.error(f"Headers scan error: {str(e)}")
            return {
                'target': target,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
