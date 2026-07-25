"""SSL/TLS Certificate Scanner"""

import ssl
import socket
from datetime import datetime
import logging
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

class SSLScanner:
    """Scan SSL/TLS certificates"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, target: str) -> dict:
        """
        Scan SSL/TLS certificate - extract host from target
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
            if cert_data:
                result = {
                    'host': host,
                    'port': port,
                    'timestamp': datetime.utcnow().isoformat(),
                    'certificate': cert_data,
                    'status': 'ok'
                }
            else:
                result = {
                    'host': host,
                    'port': port,
                    'error': 'Could not retrieve certificate',
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
                    
                    # Extract information
                    subject = dict(x.rfc4514_string() for x in cert.subject)
                    
                    # Get SANs
                    sans = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = [name.value for name in san_ext.value]
                    except:
                        pass
                    
                    # Get issuers
                    issuer = dict(x.rfc4514_string() for x in cert.issuer)
                    
                    result = {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_valid_before': cert.not_valid_before_utc.isoformat(),
                        'not_valid_after': cert.not_valid_after_utc.isoformat(),
                        'subject_alt_names': [str(s) for s in sans],
                        'public_key_size': cert.public_key().key_size,
                        'signature_algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
                        'is_valid': cert.not_valid_after_utc > datetime.utcnow(),
                        'days_until_expiry': (cert.not_valid_after_utc - datetime.utcnow()).days,
                    }
                    
                    return result
        except Exception as e:
            logger.error(f"Certificate extraction error: {str(e)}")
            return None

    def scan_headers(self, target: str) -> dict:
        """
        Scan HTTP security headers
        """
        try:
            import requests
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
