"""IP Geolocation and Reputation Scanner

Uses multiple free & paid APIs:
- ip-api.com: Geolocation (free, 45 req/min)
- IPQualityScore: IP Reputation, proxy/VPN detection, threat data
- ASN lookup: BGP routing information

Requires:
- IPQUALITYSCORE_KEY: https://www.ipqualityscore.com
"""

import requests
import json
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Load API key from environment
IPQUALITYSCORE_KEY = os.getenv('IPQUALITYSCORE_KEY', '')

class IPScanner:
    """Scan IP addresses for geolocation and reputation data"""
    
    def __init__(self):
        self.timeout = 10
        
    def scan(self, ip: str) -> dict:
        """
        Scan IP address using multiple APIs
        """
        try:
            result = {
                'ip': ip,
                'timestamp': datetime.utcnow().isoformat(),
                'geolocation': self._get_geolocation(ip),
                'reputation': self._get_reputation(ip),
                'threat_data': self._get_threat_data(ip),
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
            # Use HTTPS instead of HTTP
            url = f"https://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting"
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
                    'status': 'found'
                }
            return {'error': 'Geolocation lookup failed', 'status': 'failed'}
        except Exception as e:
            logger.error(f"Geolocation error: {str(e)}")
            return {'error': str(e), 'status': 'error'}
    
    def _get_reputation(self, ip: str) -> dict:
        """Check IP reputation using IPQualityScore"""
        if not IPQUALITYSCORE_KEY:
            return {'status': 'api_key_missing', 'note': 'Set IPQUALITYSCORE_KEY in .env'}
        
        try:
            url = f"https://ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_KEY}/{ip}"
            
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                
                return {
                    'fraud_score': data.get('fraud_score'),  # 0-100
                    'is_crawler': data.get('is_crawler'),
                    'is_bot': data.get('is_bot'),
                    'is_vpn': data.get('is_vpn'),
                    'is_proxy': data.get('is_proxy'),
                    'is_tor': data.get('is_tor'),
                    'is_datacenter': data.get('is_datacenter'),
                    'recent_abuse': data.get('recent_abuse'),
                    'is_blacklisted': data.get('is_blacklisted'),
                    'threat_level': data.get('threat_level'),  # low, medium, high
                    'status': 'found'
                }
            return {'status': 'error', 'error': f'API returned {resp.status_code}'}
        except Exception as e:
            logger.error(f"Reputation check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _get_threat_data(self, ip: str) -> dict:
        """Get additional threat/abuse data"""
        try:
            # Try to get abuse data from AbuseIPDB if key available
            abuseipdb_key = os.getenv('ABUSEIPDB_KEY', '')
            if abuseipdb_key:
                try:
                    url = f"https://api.abuseipdb.com/api/v2/check"
                    headers = {
                        'Key': abuseipdb_key,
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
                                'source': 'abuseipdb',
                                'abuse_confidence_score': data['data'].get('abuseConfidenceScore'),
                                'total_reports': data['data'].get('totalReports'),
                                'usage_type': data['data'].get('usageType'),
                                'is_whitelisted': data['data'].get('isWhitelisted'),
                                'is_blacklisted': data['data'].get('isBlacklisted'),
                                'status': 'found'
                            }
                except Exception as e:
                    logger.debug(f"AbuseIPDB error: {str(e)}")
            
            return {'status': 'unavailable', 'note': 'Set ABUSEIPDB_KEY for enhanced threat data'}
        except Exception as e:
            logger.debug(f"Threat data error: {str(e)}")
            return {'status': 'error'}
    
    def _get_asn(self, ip: str) -> dict:
        """Get ASN information"""
        try:
            urls = [
                f"https://api.asn.cymru.com/v1/ip/{ip}.json",
                f"https://ipinfo.io/{ip}/json",
            ]
            
            for url in urls:
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        
                        # Handle Cymru format
                        if isinstance(data, list) and len(data) > 0 and data[0].get('asn'):
                            return {
                                'asn': data[0].get('asn'),
                                'prefix': data[0].get('prefix'),
                                'country_code': data[0].get('country_code'),
                                'registry': data[0].get('registry'),
                                'allocated': data[0].get('allocated'),
                                'name': data[0].get('name'),
                                'source': 'cymru',
                                'status': 'found'
                            }
                        
                        # Handle IPInfo format
                        elif data.get('asn'):
                            return {
                                'asn': data.get('asn'),
                                'name': data.get('org'),
                                'country_code': data.get('country'),
                                'source': 'ipinfo',
                                'status': 'found'
                            }
                except:
                    continue
            
            return {'status': 'unavailable'}
        except Exception as e:
            logger.debug(f"ASN lookup error: {str(e)}")
            return {'status': 'error'}
