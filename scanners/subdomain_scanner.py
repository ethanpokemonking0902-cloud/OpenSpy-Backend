"""Subdomain Enumeration Scanner

Uses multiple APIs:
- dns.resolver: DNS lookups (free)
- IPQualityScore: Reputation checking for discovered subdomains

Requires:
- IPQUALITYSCORE_KEY: https://www.ipqualityscore.com
"""

import dns.resolver
import dns.rdatatype
import requests
import os
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

# Load API key from environment
IPQUALITYSCORE_KEY = os.getenv('IPQUALITYSCORE_KEY', '')

class SubdomainScanner:
    """Enumerate subdomains and check their reputation"""
    
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
        Enumerate subdomains and check reputation
        """
        try:
            subdomains_data = self._enumerate_subdomains(domain)
            
            # Check reputation for found subdomains
            if IPQUALITYSCORE_KEY and subdomains_data.get('found'):
                for subdomain in subdomains_data['found']:
                    subdomain['reputation'] = self._check_subdomain_reputation(subdomain['full_domain'])
            
            result = {
                'domain': domain,
                'timestamp': datetime.utcnow().isoformat(),
                'subdomains': subdomains_data,
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
    
    def _check_subdomain_reputation(self, subdomain: str) -> dict:
        """Check subdomain reputation using IPQualityScore"""
        try:
            # Remove www and get clean domain
            clean_domain = subdomain.replace('www.', '').split(':')[0]
            
            url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_KEY}/{clean_domain}"
            
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                
                return {
                    'fraud_score': data.get('fraud_score'),
                    'is_suspicious': data.get('suspicious'),
                    'phishing': data.get('phishing'),
                    'malware': data.get('malware'),
                    'domain_rank': data.get('domain_rank'),
                    'status': 'checked'
                }
            return {'status': 'error', 'error': f'API returned {resp.status_code}'}
        except Exception as e:
            logger.debug(f"Subdomain reputation check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
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
