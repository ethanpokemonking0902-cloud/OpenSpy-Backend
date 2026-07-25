"""Geolocation Scanner"""

import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class GeolocScanner:
    """Get geolocation and ISP information for IP addresses"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, target: str) -> dict:
        """
        Geolocation scan - get IP location, ISP, and threat data
        """
        try:
            result = {
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'geolocation': self._get_geolocation(target),
                'threat_data': self._get_threat_data(target)
            }
            return result
        except Exception as e:
            logger.error(f"Geolocation scan error: {str(e)}")
            return {
                'error': str(e),
                'target': target,
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
    
    def _get_threat_data(self, ip: str) -> dict:
        """Get threat/reputation data (lightweight)"""
        try:
            # Use a lightweight reputation check
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
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
                        'abuse_confidence_score': data['data'].get('abuseConfidenceScore', 0),
                        'total_reports': data['data'].get('totalReports', 0),
                        'usage_type': data['data'].get('usageType', 'unknown'),
                    }
            return {'status': 'unknown'}
        except Exception as e:
            logger.error(f"Threat data error: {str(e)}")
            return {'status': 'error'}
