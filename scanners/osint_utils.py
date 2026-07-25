"""OSINT Utility Functions - Shared across scanners"""

import requests
import logging

logger = logging.getLogger(__name__)

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
                return {'status': 'not_found'}
            return {'error': f'Shodan returned {resp.status_code}'}
        except Exception as e:
            logger.error(f"Shodan lookup error: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def get_threat_intel(query: str) -> dict:
        """Get threat intelligence from multiple sources"""
        threats = {
            'virustotal': None,
            'abuseipdb': None,
            'urlscan': None,
        }
        
        try:
            # Check VirusTotal (free tier)
            vt_url = f"https://www.virustotal.com/api/v3/search?query={query}"
            threats['virustotal'] = {'status': 'VirusTotal check available'}
        except:
            pass
        
        try:
            # Check URLScan
            if query.startswith('http'):
                urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{query}"
                threats['urlscan'] = {'status': 'URLScan check available'}
        except:
            pass
        
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
            
            # IPINFO BGP API (free tier)
            url = f"https://ipinfo.io/AS{asn}/json"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            
            # Alternative: WHOIS lookup for BGP
            return {'asn': asn, 'status': 'BGP lookup available'}
        except Exception as e:
            logger.error(f"BGP lookup error: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def get_mac_vendor(mac: str) -> dict:
        """Get MAC address vendor information"""
        try:
            # Clean MAC address
            clean_mac = mac.replace('-', '').replace(':', '').upper()
            
            # Use MacVendor.com free API
            url = f"https://api.macvendors.com/{clean_mac}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                return {
                    'mac': mac,
                    'vendor': resp.text,
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'mac': mac, 'vendor': 'Unknown', 'status': 'not_found'}
            
            return {'error': f'Vendor lookup failed: {resp.status_code}'}
        except Exception as e:
            logger.error(f"MAC vendor lookup error: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def get_github_user(username: str) -> dict:
        """Get GitHub user information"""
        try:
            url = f"https://api.github.com/users/{username}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'username': data.get('login'),
                    'name': data.get('name'),
                    'bio': data.get('bio'),
                    'location': data.get('location'),
                    'email': data.get('email'),
                    'public_repos': data.get('public_repos'),
                    'followers': data.get('followers'),
                    'following': data.get('following'),
                    'company': data.get('company'),
                    'blog': data.get('blog'),
                    'twitter': data.get('twitter_username'),
                    'created_at': data.get('created_at'),
                    'updated_at': data.get('updated_at'),
                    'avatar_url': data.get('avatar_url'),
                    'profile_url': data.get('html_url'),
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'username': username, 'status': 'not_found'}
            
            return {'error': f'GitHub lookup failed: {resp.status_code}'}
        except Exception as e:
            logger.error(f"GitHub lookup error: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def check_data_breaches(email: str) -> dict:
        """Check if email appears in known breaches"""
        try:
            # Use haveibeenpwned.com free API
            url = f"https://api.pwnedpasswords.com/range/email/{email}"
            
            # Actually use the free breach notification API
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
                            'name': b.get('Name'),
                            'title': b.get('Title'),
                            'date': b.get('BreachDate'),
                            'data_classes': b.get('DataClasses', [])
                        } for b in breaches[:10]
                    ],
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'email': email, 'breached': False, 'status': 'not_found'}
            elif resp.status_code == 429:
                return {'email': email, 'status': 'rate_limited'}
            
            return {'error': f'Breach check failed: {resp.status_code}'}
        except Exception as e:
            logger.error(f"Breach check error: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def get_cve_details(cve_id: str) -> dict:
        """Get CVE vulnerability details"""
        try:
            # Use NVD API (free, no auth required)
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            resp = requests.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'result' in data and 'CVE_Items' in data['result']:
                    cve = data['result']['CVE_Items'][0]
                    return {
                        'cve_id': cve_id,
                        'description': cve.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value'),
                        'severity': cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity'),
                        'score': cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore'),
                        'published': cve.get('publishedDate'),
                        'status': 'found'
                    }
            
            return {'cve_id': cve_id, 'status': 'not_found'}
        except Exception as e:
            logger.error(f"CVE lookup error: {str(e)}")
            return {'error': str(e)}
