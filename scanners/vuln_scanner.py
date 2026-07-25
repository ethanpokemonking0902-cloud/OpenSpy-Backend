"""Vulnerability Scanner"""

import requests
from datetime import datetime
import logging
import json

logger = logging.getLogger(__name__)

class VulnScanner:
    """Check for known vulnerabilities"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, target: str) -> dict:
        """
        Check for known vulnerabilities
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
    
    def _check_vulns(self, target: str) -> dict:
        """Check vulnerabilities using public APIs"""
        vulns = {
            'known_cves': [],
            'exposed_services': [],
            'misconfigurations': [],
        }
        
        try:
            # Check Shodan (if API key available - free tier)
            cves = self._check_cve_search(target)
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
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            for path in common_paths:
                try:
                    url = f"{target}{path}"
                    resp = requests.head(url, headers=headers, timeout=5, allow_redirects=False)
                    
                    if resp.status_code in [200, 301, 302]:
                        misconfigs.append({
                            'path': path,
                            'status': resp.status_code,
                            'severity': 'high' if path in ['/.env', '/config.php', '/.git/config'] else 'low',
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
            'known_vulnerabilities': [],
        }
        
        try:
            # Check SSL via crt.sh
            if target.startswith('http'):
                target_domain = target.split('/')[2]
            else:
                target_domain = target
            
            # Check for SSL certificate issues
            try:
                resp = requests.get(f"https://{target_domain}", verify=False, timeout=5)
                issues['header_issues'].append({
                    'type': 'https',
                    'status': 'ok' if resp.status_code < 400 else 'warning',
                    'message': f"HTTPS available with status {resp.status_code}"
                })
            except:
                issues['ssl_issues'].append({
                    'type': 'https_unavailable',
                    'severity': 'high',
                    'message': 'HTTPS not available'
                })
            
            # Check for security headers
            try:
                resp = requests.head(target, timeout=5, allow_redirects=True)
                
                security_headers = [
                    'Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Content-Security-Policy'
                ]
                
                missing_headers = [h for h in security_headers if h not in resp.headers]
                
                if missing_headers:
                    issues['header_issues'].append({
                        'type': 'missing_security_headers',
                        'severity': 'medium',
                        'headers': missing_headers
                    })
            except Exception as e:
                logger.debug(f"Header check error: {str(e)}")
            
            return issues
        except Exception as e:
            logger.error(f"Common issues check error: {str(e)}")
            return {'error': str(e)}
