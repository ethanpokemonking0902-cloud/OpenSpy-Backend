"""Domain DNS and WHOIS Scanner"""

import dns.resolver
import dns.rdatatype
import whois as whois_lib
from datetime import datetime
import logging
import socket

logger = logging.getLogger(__name__)

class DomainScanner:
    """Scan domains for DNS records and WHOIS information"""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
        
    def scan(self, domain: str) -> dict:
        """
        Scan domain for DNS and WHOIS data
        """
        try:
            result = {
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat(),
                'dns': self._get_dns_records(domain),
                'whois': self._get_whois(domain),
                'ip': self._get_ip(domain),
            }
            return result
        except Exception as e:
            logger.error(f"Domain scan error: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def scan_whois(self, domain: str) -> dict:
        """
        WHOIS only scan
        """
        try:
            result = {
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat(),
                'whois': self._get_whois(domain),
            }
            return result
        except Exception as e:
            logger.error(f"WHOIS scan error: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _get_dns_records(self, domain: str) -> dict:
        """Get DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)"""
        records = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                answers = self.dns_resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                records[record_type] = []
            except Exception as e:
                logger.debug(f"Error resolving {record_type}: {str(e)}")
                records[record_type] = []
        
        return records
    
    def _get_ip(self, domain: str) -> dict:
        """Get IP address(es) for domain"""
        try:
            ips = socket.getaddrinfo(domain, 443)
            ip_list = list(set([ip[4][0] for ip in ips]))
            return {
                'addresses': ip_list,
                'count': len(ip_list)
            }
        except Exception as e:
            logger.error(f"IP resolution error: {str(e)}")
            return {'error': str(e)}
    
    def _get_whois(self, domain: str) -> dict:
        """Get WHOIS information"""
        try:
            # WHOIS lookup can be slow, use short timeout
            w = whois_lib.query(domain)
            
            # Safely extract attributes
            result = {
                'domain': domain,
                'registrar': None,
                'creation_date': None,
                'expiration_date': None,
                'name_servers': [],
                'status': 'ok'
            }
            
            try:
                if hasattr(w, 'registrar'):
                    result['registrar'] = str(w.registrar)
            except:
                pass
            
            try:
                if hasattr(w, 'creation_date'):
                    result['creation_date'] = str(w.creation_date)
            except:
                pass
                
            try:
                if hasattr(w, 'expiration_date'):
                    result['expiration_date'] = str(w.expiration_date)
            except:
                pass
                
            try:
                if hasattr(w, 'name_servers') and w.name_servers:
                    result['name_servers'] = [str(ns) for ns in w.name_servers]
            except:
                pass
            
            return result
        except whois_lib.UnknownTld as e:
            logger.debug(f"Unknown TLD: {domain}")
            return {'domain': domain, 'error': f'Unknown TLD: {domain}', 'status': 'failed'}
        except whois_lib.FailedParsingWhoisOutput as e:
            logger.debug(f"WHOIS parsing failed: {str(e)}")
            return {'domain': domain, 'error': 'WHOIS parsing failed', 'status': 'failed'}
        except Exception as e:
            logger.error(f"WHOIS lookup error: {str(e)}")
            # Return DNS info as fallback
            try:
                dns_info = self._get_dns_records(domain)
                dns_info['whois_fallback'] = True
                return dns_info
            except:
                return {'domain': domain, 'error': str(e), 'status': 'error'}
    
    @staticmethod
    def _redact_email(email):
        """Redact email for privacy"""
        if not email:
            return None
        if isinstance(email, list):
            email = email[0] if email else None
        if email and '@' in str(email):
            parts = str(email).split('@')
            return f"{parts[0][:2]}***@{parts[1]}"
        return email
