"""Domain DNS and WHOIS Scanner

Uses multiple APIs:
- dns.resolver: DNS record lookups (free)
- whois: WHOIS lookups (free)
- IPQualityScore: URL/domain reputation, malware detection

Requires:
- IPQUALITYSCORE_KEY: https://www.ipqualityscore.com
"""

import dns.resolver
import dns.rdatatype
import whois as whois_lib
import requests
import os
from datetime import datetime
import logging
import socket

logger = logging.getLogger(__name__)

# Load API key from environment
IPQUALITYSCORE_KEY = os.getenv('IPQUALITYSCORE_KEY', '')

class DomainScanner:
    """Scan domains for DNS records, WHOIS information, and reputation"""
    
    def __init__(self):
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
        self.timeout = 10
        
    def scan(self, domain: str) -> dict:
        """
        Scan domain for DNS, WHOIS, and reputation data
        """
        try:
            result = {
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat(),
                'dns': self._get_dns_records(domain),
                'whois': self._get_whois(domain),
                'ip': self._get_ip(domain),
                'reputation': self._get_domain_reputation(domain),
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
    
    def _get_domain_reputation(self, domain: str) -> dict:
        """Get domain/URL reputation using IPQualityScore and VirusTotal"""
        reputation = {}
        
        # Try IPQualityScore first
        if IPQUALITYSCORE_KEY:
            try:
                url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_KEY}/{domain}"
                
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    
                    reputation['ipqualityscore'] = {
                        'domain': domain,
                        'fraud_score': data.get('fraud_score'),  # 0-100
                        'is_suspicious': data.get('suspicious'),
                        'phishing': data.get('phishing'),
                        'malware': data.get('malware'),
                        'parkingpage': data.get('parkingpage'),
                        'spyware': data.get('spyware'),
                        'dns_valid': data.get('dns_valid'),
                        'domain_age': data.get('domain_age'),  # in seconds
                        'domain_rank': data.get('domain_rank'),
                        'status': 'found'
                    }
            except Exception as e:
                logger.debug(f"IPQualityScore error: {str(e)}")
        
        # Try VirusTotal
        virustotal_key = os.getenv('VIRUSTOTAL_KEY', '')
        if virustotal_key:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {'x-apikey': virustotal_key}
                
                resp = requests.get(vt_url, headers=headers, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    
                    # Extract attributes
                    attrs = data.get('data', {}).get('attributes', {})
                    
                    reputation['virustotal'] = {
                        'domain': domain,
                        'last_dns_records': attrs.get('last_dns_records'),
                        'last_https_certificate': attrs.get('last_https_certificate'),
                        'last_analysis_stats': attrs.get('last_analysis_stats'),  # {malicious, suspicious, undetected, harmless}
                        'last_analysis_results': len(attrs.get('last_analysis_results', {})),
                        'reputation': attrs.get('reputation'),
                        'threat_names': attrs.get('threat_names', []),
                        'status': 'found'
                    }
            except Exception as e:
                logger.debug(f"VirusTotal error: {str(e)}")
        
        if reputation:
            reputation['status'] = 'found'
            return reputation
        
        return {'status': 'api_key_missing', 'note': 'Set IPQUALITYSCORE_KEY or VIRUSTOTAL_KEY in .env'}
    
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
