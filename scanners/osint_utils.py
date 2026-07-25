"""OSINT Utility Functions - Shared across scanners

Uses multiple APIs:
- Shodan InternetDB: Port/service enumeration (free)
- IPQualityScore: Email validation, URL malware detection, leak detection
- HaveIBeenPwned: Data breach checking (free)
- GitHub API: User reconnaissance (free)
- NVD: CVE vulnerability details (free)

Requires:
- IPQUALITYSCORE_KEY: https://www.ipqualityscore.com
"""

import requests
import os
import logging

logger = logging.getLogger(__name__)

# Load API key from environment
IPQUALITYSCORE_KEY = os.getenv('IPQUALITYSCORE_KEY', '')

class OSINTUtils:
    """Shared OSINT functions"""
    
    @staticmethod
    def get_shodan_data(ip: str) -> dict:
        """Get Shodan InternetDB data (free API)"""
        try:
            url = f"https://internetdb.shodan.io/{ip}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {'ip': ip, 'ports': [], 'hostnames': [], 'cpes': [], 'vulns': [], 'tags': [], 'status': 'not_found'}
            return {'ip': ip, 'error': f'Shodan returned {resp.status_code}', 'ports': [], 'status': 'error'}
        except Exception as e:
            logger.debug(f"Shodan lookup error: {str(e)}")
            return {'ip': ip, 'ports': [], 'hostnames': [], 'cpes': [], 'vulns': [], 'tags': [], 'status': 'unavailable'}
    
    @staticmethod
    def validate_email(email: str) -> dict:
        """Validate email using IPQualityScore"""
        if not IPQUALITYSCORE_KEY:
            return {'email': email, 'status': 'api_key_missing', 'note': 'Set IPQUALITYSCORE_KEY in .env'}
        
        try:
            url = f"https://www.ipqualityscore.com/api/json/email/{IPQUALITYSCORE_KEY}/{email}"
            
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                
                return {
                    'email': email,
                    'is_valid': data.get('is_valid'),
                    'is_disposable': data.get('is_disposable'),
                    'is_deliverable': data.get('is_deliverable'),
                    'fraud_score': data.get('fraud_score'),  # 0-100
                    'risky': data.get('risky'),
                    'is_leaked': data.get('is_leaked'),
                    'is_smtp_valid': data.get('is_smtp_valid'),
                    'bounce_type': data.get('bounce_type'),
                    'status': 'found'
                }
            return {'email': email, 'status': 'error', 'error': f'API returned {resp.status_code}'}
        except Exception as e:
            logger.debug(f"Email validation error: {str(e)}")
            return {'email': email, 'status': 'error', 'error': str(e)}
    
    @staticmethod
    def check_url_malware(url: str) -> dict:
        """Check URL for malware using IPQualityScore"""
        if not IPQUALITYSCORE_KEY:
            return {'url': url, 'status': 'api_key_missing', 'note': 'Set IPQUALITYSCORE_KEY in .env'}
        
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed.netloc.replace('www.', '')
            
            api_url = f"https://www.ipqualityscore.com/api/json/url/{IPQUALITYSCORE_KEY}/{domain}"
            
            resp = requests.get(api_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                
                return {
                    'url': url,
                    'domain': domain,
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
            return {'url': url, 'status': 'error', 'error': f'API returned {resp.status_code}'}
        except Exception as e:
            logger.debug(f"URL malware check error: {str(e)}")
            return {'url': url, 'status': 'error', 'error': str(e)}
    
    @staticmethod
    def get_threat_intel(query: str) -> dict:
        """Get threat intelligence from multiple sources"""
        threats = {}
        
        try:
            # Try to check if it's a domain or IP
            if '.' in query and not query.startswith('http'):
                # Could be a domain
                threats['type'] = 'domain'
            elif query.replace('.', '').isdigit():
                threats['type'] = 'ip'
            else:
                threats['type'] = 'unknown'
            
            # Try VirusTotal if API key available
            virustotal_key = os.getenv('VIRUSTOTAL_KEY', '')
            if virustotal_key:
                try:
                    if threats['type'] == 'domain':
                        vt_url = f"https://www.virustotal.com/api/v3/domains/{query}"
                    elif threats['type'] == 'ip':
                        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
                    else:
                        vt_url = None
                    
                    if vt_url:
                        headers = {'x-apikey': virustotal_key}
                        resp = requests.get(vt_url, headers=headers, timeout=10)
                        
                        if resp.status_code == 200:
                            data = resp.json()
                            attrs = data.get('data', {}).get('attributes', {})
                            
                            threats['virustotal'] = {
                                'status': 'found',
                                'last_analysis_stats': attrs.get('last_analysis_stats'),
                                'reputation': attrs.get('reputation'),
                                'threat_names': attrs.get('threat_names', []),
                            }
                        else:
                            threats['virustotal'] = '—'
                except Exception as e:
                    logger.debug(f"VirusTotal threat intel error: {str(e)}")
                    threats['virustotal'] = '—'
            else:
                threats['virustotal'] = '—'
            
            # AbuseIPDB for IPs
            abuseipdb_key = os.getenv('ABUSEIPDB_KEY', '')
            if abuseipdb_key and threats['type'] == 'ip':
                try:
                    url = f"https://api.abuseipdb.com/api/v2/check"
                    headers = {'Key': abuseipdb_key, 'Accept': 'application/json'}
                    params = {'ipAddress': query, 'maxAgeInDays': 90}
                    
                    resp = requests.get(url, headers=headers, params=params, timeout=10)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get('data'):
                            threats['abuseipdb'] = {
                                'status': 'found',
                                'abuse_confidence_score': data['data'].get('abuseConfidenceScore'),
                                'total_reports': data['data'].get('totalReports'),
                            }
                        else:
                            threats['abuseipdb'] = '—'
                except:
                    threats['abuseipdb'] = '—'
            else:
                threats['abuseipdb'] = '—'
            
            threats['urlscan'] = '—'
            threats['status'] = 'ready'
        except Exception as e:
            logger.debug(f"Threat intel error: {str(e)}")
            threats['status'] = 'error'
        
        return threats
    
    @staticmethod
    def get_bgp_info(target: str) -> dict:
        """Get BGP routing information"""
        try:
            # Try to determine if input is ASN or IP
            if target.startswith('AS'):
                asn = target[2:]
            else:
                asn = target
            
            try:
                # IPINFO BGP API (free tier)
                url = f"https://ipinfo.io/AS{asn}/json"
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        'asn': data.get('asn', asn),
                        'name': data.get('name', '—'),
                        'domain': data.get('domain', '—'),
                        'type': data.get('type', '—'),
                        'prefix_count': data.get('prefixes', ['—'])[0] if data.get('prefixes') else 0,
                        'status': 'found'
                    }
            except:
                pass
            
            # Fallback response
            return {'asn': asn, 'name': '—', 'status': 'available'}
        except Exception as e:
            logger.debug(f"BGP lookup error: {str(e)}")
            return {'asn': target, 'status': 'error', 'error': '—'}
    
    @staticmethod
    def get_mac_vendor(mac: str) -> dict:
        """Get MAC address vendor information"""
        try:
            # Clean MAC address
            clean_mac = mac.replace('-', '').replace(':', '').upper()[:6]
            
            # Use MacVendor.com free API
            url = f"https://api.macvendors.com/{clean_mac}"
            resp = requests.get(url, timeout=5)
            
            if resp.status_code == 200:
                return {
                    'mac': mac,
                    'vendor': resp.text.strip(),
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'mac': mac, 'vendor': '—', 'status': 'not_found'}
            
            return {'mac': mac, 'vendor': '—', 'status': 'error'}
        except Exception as e:
            logger.debug(f"MAC vendor lookup error: {str(e)}")
            return {'mac': mac, 'vendor': '—', 'status': 'unavailable'}
    
    @staticmethod
    def get_github_user(username: str) -> dict:
        """Get GitHub user information"""
        try:
            url = f"https://api.github.com/users/{username}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'username': data.get('login', username),
                    'name': data.get('name') or '—',
                    'bio': data.get('bio') or '—',
                    'location': data.get('location') or '—',
                    'email': data.get('email') or '—',
                    'public_repos': data.get('public_repos', 0),
                    'followers': data.get('followers', 0),
                    'following': data.get('following', 0),
                    'company': data.get('company') or '—',
                    'blog': data.get('blog') or '—',
                    'twitter': data.get('twitter_username') or '—',
                    'created_at': data.get('created_at') or '—',
                    'avatar_url': data.get('avatar_url'),
                    'profile_url': data.get('html_url'),
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'username': username, 'status': 'not_found', 'name': '—', 'public_repos': 0}
            
            return {'username': username, 'status': 'error', 'error': f'GitHub lookup failed: {resp.status_code}'}
        except Exception as e:
            logger.debug(f"GitHub lookup error: {str(e)}")
            return {'username': username, 'status': 'unavailable', 'error': '—'}
    
    @staticmethod
    def check_data_breaches(email: str) -> dict:
        """Check if email appears in known breaches"""
        try:
            # Use haveibeenpwned.com free API
            breach_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {'User-Agent': 'OpenSpy-OSINT'}
            
            resp = requests.get(breach_url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    'email': email,
                    'breached': True,
                    'breach_count': len(breaches),
                    'breaches': [
                        {
                            'name': b.get('Name', '—'),
                            'title': b.get('Title', '—'),
                            'date': b.get('BreachDate', '—'),
                            'data_classes': b.get('DataClasses', [])
                        } for b in breaches[:10]
                    ],
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'email': email, 'breached': False, 'breach_count': 0, 'breaches': [], 'status': 'not_found'}
            elif resp.status_code == 429:
                return {'email': email, 'status': 'rate_limited', 'breach_count': 0, 'breaches': []}
            
            return {'email': email, 'status': 'error', 'breach_count': 0, 'breaches': []}
        except Exception as e:
            logger.debug(f"Breach check error: {str(e)}")
            return {'email': email, 'status': 'unavailable', 'breached': False, 'breach_count': 0, 'breaches': []}
    
    @staticmethod
    def get_cve_details(cve_id: str) -> dict:
        """Get CVE vulnerability details"""
        try:
            # Use NVD API (free, no auth required)
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'result' in data and 'CVE_Items' in data['result'] and len(data['result']['CVE_Items']) > 0:
                    cve = data['result']['CVE_Items'][0]
                    desc = cve.get('cve', {}).get('description', {}).get('description_data', [{}])
                    desc_text = desc[0].get('value', '—') if desc else '—'
                    return {
                        'cve_id': cve_id,
                        'description': desc_text,
                        'severity': cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', '—'),
                        'score': cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0),
                        'published': cve.get('publishedDate', '—'),
                        'status': 'found'
                    }
            
            return {'cve_id': cve_id, 'status': 'not_found', 'severity': '—', 'score': 0}
        except Exception as e:
            logger.debug(f"CVE lookup error: {str(e)}")
            return {'cve_id': cve_id, 'status': 'unavailable', 'error': '—', 'severity': '—'}
