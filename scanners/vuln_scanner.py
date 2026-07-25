"""Vulnerability Scanner

Uses multiple APIs:
- Shodan: IoT/service enumeration, exposed services
- CIRCL CVE: CVE/vulnerability search
- NVD: CVE details

Requires:
- SHODAN_KEY: https://www.shodan.io (for service enumeration)
"""

import requests
import os
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

# Load API keys from environment
SHODAN_KEY = os.getenv('SHODAN_KEY', '')

class VulnScanner:
    """Check for known vulnerabilities and exposed services"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, target: str) -> dict:
        """
        Check for known vulnerabilities and exposed services
        """
        try:
            # Ensure URL has scheme for misconfiguration checks
            if not target.startswith('http://') and not target.startswith('https://'):
                check_target = f'https://{target}'
            else:
                check_target = target
            
            result = {
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'vulnerabilities': self._check_vulns(check_target),
                'exposed_services': self._check_exposed_services(target),
                'common_issues': self._check_common_issues(check_target),
            }
            return result
        except Exception as e:
            logger.error(f"Vuln scan error: {str(e)}")
            return {
                'error': str(e),
                'target': target,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _check_exposed_services(self, target: str) -> dict:
        """Check for exposed services using Shodan"""
        if not SHODAN_KEY:
            return {'status': 'api_key_missing', 'note': 'Set SHODAN_KEY in .env'}
        
        try:
            # Extract IP or hostname
            import socket
            
            # Try to get IP
            try:
                if target.startswith('http'):
                    host = target.split('/')[2]
                else:
                    host = target
                
                ip = socket.gethostbyname(host)
            except:
                return {'status': 'resolution_failed', 'error': f'Could not resolve {target}'}
            
            # Query Shodan
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {
                'key': SHODAN_KEY
            }
            
            resp = requests.get(url, params=params, timeout=self.timeout)
            
            if resp.status_code == 200:
                data = resp.json()
                
                services = []
                for item in data.get('data', []):
                    services.append({
                        'port': item.get('port'),
                        'service': item.get('_shodan', {}).get('module', 'unknown'),
                        'product': item.get('product'),
                        'version': item.get('version'),
                        'severity': 'high' if item.get('vulns') else 'medium'
                    })
                
                return {
                    'ip': ip,
                    'hostname': data.get('hostnames', []),
                    'services': services,
                    'service_count': len(services),
                    'vulns': data.get('vulns', [])[:5],  # Top 5 vulns
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'ip': ip, 'status': 'not_found', 'services': []}
            else:
                return {'status': 'error', 'error': f'Shodan returned {resp.status_code}'}
        
        except Exception as e:
            logger.debug(f"Shodan service check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _check_vulns(self, target: str) -> dict:
        """Check vulnerabilities using public APIs"""
        vulns = {
            'known_cves': [],
            'exposed_services': [],
            'misconfigurations': [],
        }
        
        try:
            # Extract domain for CVE search
            if target.startswith('http'):
                domain = target.split('/')[2]
            else:
                domain = target
            
            # Check CIRCL CVE API
            cves = self._check_cve_search(domain)
            vulns['known_cves'] = cves
            
            # Check common misconfigurations
            misconfig = self._check_misconfigs(target)
            vulns['misconfigurations'] = misconfig
            
            return vulns
        except Exception as e:
            logger.error(f"Vulnerability check error: {str(e)}")
            return {'error': str(e)}
    
    def _check_cve_search(self, target: str) -> list:
        """Check for known CVEs"""
        cves = []
        
        try:
            # Use CIRCL CVE API (free, no key needed)
            url = f"https://cve.circl.lu/api/search/{target}"
            resp = requests.get(url, timeout=self.timeout)
            
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for cve in data[:10]:  # Limit to top 10
                        cves.append({
                            'id': cve.get('id'),
                            'summary': cve.get('summary', '')[:100],
                            'cvss': cve.get('cvss'),
                            'published': cve.get('published'),
                            'severity': 'critical' if cve.get('cvss', 0) >= 9 else 'high' if cve.get('cvss', 0) >= 7 else 'medium'
                        })
        except Exception as e:
            logger.debug(f"CVE search error: {str(e)}")
        
        return cves
    
    def _check_misconfigs(self, target: str) -> list:
        """Check for common misconfigurations"""
        misconfigs = []
        
        try:
            # Check for common paths/files
            common_paths = [
                '/.env',
                '/config.php',
                '/.git/config',
                '/web.config',
                '/.well-known/security.txt',
                '/robots.txt',
                '/sitemap.xml',
                '/.htaccess',
                '/admin',
                '/wp-admin',
                '/.aws/credentials',
                '/backup',
                '/old',
                '/test',
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            for path in common_paths:
                try:
                    url = f"{target}{path}"
                    resp = requests.head(url, headers=headers, timeout=3, allow_redirects=False)
                    
                    if resp.status_code in [200, 301, 302]:
                        severity = 'critical' if path in ['/.env', '/.aws/credentials', '/config.php', '/.git/config'] else 'high' if path in ['/admin', '/wp-admin'] else 'low'
                        misconfigs.append({
                            'path': path,
                            'status': resp.status_code,
                            'severity': severity,
                            'description': f"Accessible path: {path}"
                        })
                except:
                    pass
        except Exception as e:
            logger.debug(f"Misconfiguration check error: {str(e)}")
        
        return misconfigs
    
    def _check_common_issues(self, target: str) -> dict:
        """Check for common security issues"""
        issues = {
            'ssl_issues': [],
            'header_issues': [],
            'security_findings': [],
        }
        
        try:
            # Extract domain
            if target.startswith('http'):
                target_domain = target.split('/')[2]
            else:
                target_domain = target
            
            # Check for SSL certificate issues
            try:
                resp = requests.get(f"https://{target_domain}", verify=False, timeout=5)
                issues['ssl_issues'].append({
                    'type': 'https',
                    'status': 'ok' if resp.status_code < 400 else 'warning',
                    'message': f"HTTPS available with status {resp.status_code}"
                })
            except Exception as e:
                issues['ssl_issues'].append({
                    'type': 'https_unavailable',
                    'severity': 'high',
                    'message': f'HTTPS not available: {str(e)}'
                })
            
            # Check for security headers
            try:
                resp = requests.head(target, timeout=5, allow_redirects=True)
                
                security_headers = {
                    'Strict-Transport-Security': 'high',
                    'X-Frame-Options': 'medium',
                    'X-Content-Type-Options': 'medium',
                    'Content-Security-Policy': 'medium'
                }
                
                for header, severity in security_headers.items():
                    if header not in resp.headers:
                        issues['header_issues'].append({
                            'type': f'missing_{header.lower().replace("-", "_")}',
                            'severity': severity,
                            'message': f'Missing security header: {header}'
                        })
            except Exception as e:
                logger.debug(f"Header check error: {str(e)}")
            
            return issues
        except Exception as e:
            logger.error(f"Common issues check error: {str(e)}")
            return {'error': str(e)}
