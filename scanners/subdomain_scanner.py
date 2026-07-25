"""Subdomain Enumeration Scanner"""

import dns.resolver
import dns.rdatatype
import requests
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

class SubdomainScanner:
    """Enumerate subdomains"""
    
    def __init__(self):
        self.timeout = 10
        # Common subdomains to check
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'mailserver', 'webserver', 'api', 'dev', 'staging', 'beta', 'alpha',
            'blog', 'cms', 'store', 'admin', 'images', 'assets', 'static',
            'cdn', 'git', 'jenkins', 'docker', 'app', 'apps', 'service',
            'services', 'vpn', 'proxy', 'lb', 'wiki', 'forum', 'chat',
            'email', 'calendar', 'docs', 'drive', 'photos', 'video',
        ]
    
    def scan(self, domain: str) -> dict:
        """
        Enumerate subdomains
        """
        try:
            result = {
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat(),
                'subdomains': self._enumerate_subdomains(domain),
                'cname_records': self._get_cname_records(domain),
            }
            return result
        except Exception as e:
            logger.error(f"Subdomain scan error: {str(e)}")
            return {
                'error': str(e),
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _enumerate_subdomains(self, domain: str) -> dict:
        """Try common subdomains"""
        found = []
        attempted = 0
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        
        for subdomain in self.common_subdomains:
            attempted += 1
            full_domain = f"{subdomain}.{domain}"
            
            try:
                answers = resolver.resolve(full_domain, 'A')
                ips = [str(rdata) for rdata in answers]
                found.append({
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'ips': ips,
                    'status': 'active'
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                logger.debug(f"Subdomain lookup error for {full_domain}: {str(e)}")
        
        return {
            'found': found,
            'count': len(found),
            'attempted': attempted,
        }
    
    def _get_cname_records(self, domain: str) -> list:
        """Get CNAME records that might reveal subdomains"""
        cnames = []
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        
        try:
            # Try to get CNAME for wildcard
            try:
                answers = resolver.resolve(f"*.{domain}", 'CNAME')
                for rdata in answers:
                    cnames.append({
                        'type': 'wildcard_cname',
                        'value': str(rdata)
                    })
            except:
                pass
            
            # Try SOA records which might reveal info
            try:
                answers = resolver.resolve(domain, 'SOA')
                for rdata in answers:
                    cnames.append({
                        'type': 'soa',
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname)
                    })
            except:
                pass
        except Exception as e:
            logger.debug(f"CNAME lookup error: {str(e)}")
        
        return cnames
