"""IP Geolocation and Reputation Scanner"""

import requests
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class IPScanner:
    """Scan IP addresses for geolocation and reputation data"""
    
    def __init__(self):
        self.timeout = 10
        
    def scan(self, ip: str) -> dict:
        """
        Scan IP address using multiple free APIs
        """
        try:
            result = {
                'ip': ip,
                'timestamp': datetime.utcnow().isoformat(),
                'geolocation': self._get_geolocation(ip),
                'reputation': self._get_reputation(ip),
                'asn': self._get_asn(ip),
            }
            return result
        except Exception as e:
            logger.error(f"IP scan error: {str(e)}")
            return {
                'error': str(e),
                'ip': ip,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _get_geolocation(self, ip: str) -> dict:
        """Get IP geolocation from ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
            resp = requests.get(url, timeout=self.timeout)
            data = resp.json()
            
            if data.get('status') == 'success':
                return {
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'asn': data.get('as'),
                    'mobile': data.get('mobile'),
                    'proxy': data.get('proxy'),
                    'hosting': data.get('hosting'),
                }
            return {'error': 'Geolocation lookup failed'}
        except Exception as e:
            logger.error(f"Geolocation error: {str(e)}")
            return {'error': str(e)}
    
    def _get_reputation(self, ip: str) -> dict:
        """Check IP reputation from abuseipdb"""
        try:
            # Using a free tier endpoint
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': 'free-api-key',  # Would need real key in production
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('data'):
                    return {
                        'abuse_confidence_score': data['data'].get('abuseConfidenceScore'),
                        'total_reports': data['data'].get('totalReports'),
                        'usage_type': data['data'].get('usageType'),
                        'is_whitelisted': data['data'].get('isWhitelisted'),
                        'is_blacklisted': data['data'].get('isBlacklisted'),
                    }
            return {'status': 'unknown'}
        except Exception as e:
            logger.error(f"Reputation check error: {str(e)}")
            return {'status': 'error'}
    
    def _get_asn(self, ip: str) -> dict:
        """Get ASN information - gracefully handle failures"""
        try:
            # Try multiple ASN lookup services
            urls = [
                f"https://api.asn.cymru.com/v1/ip/{ip}.json",
                f"https://ipinfo.io/{ip}/json?token=free",
            ]
            
            for url in urls:
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0 and data[0].get('asn'):
                            return {
                                'asn': data[0].get('asn'),
                                'prefix': data[0].get('prefix'),
                                'country_code': data[0].get('country_code'),
                                'registry': data[0].get('registry'),
                                'allocated': data[0].get('allocated'),
                                'name': data[0].get('name'),
                            }
                        elif 'asn' in data:
                            return {
                                'asn': data.get('asn'),
                                'name': data.get('org', data.get('company', '')),
                                'country_code': data.get('country'),
                            }
                except:
                    continue
            
            # Return empty if all fail - don't crash
            return {}
        except Exception as e:
            logger.debug(f"ASN lookup error: {str(e)}")
            return {}
