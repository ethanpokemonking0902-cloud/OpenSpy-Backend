"""Phone Number Intelligence Scanner"""

import requests
import re
from datetime import datetime
import logging
from phonenumbers import phonenumberutil
import phonenumbers

logger = logging.getLogger(__name__)

class PhoneScanner:
    """Scan phone numbers for real geolocation and carrier data"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, phone_number: str) -> dict:
        """
        Full phone number reconnaissance with geolocation
        """
        try:
            # Clean phone number
            phone = self._clean_phone(phone_number)
            
            if not phone:
                return {'error': 'Invalid phone number format', 'status': 'failed'}
            
            result = {
                'phone': phone,
                'timestamp': datetime.utcnow().isoformat(),
                'parsed': self._parse_phone(phone),
                'carrier': self._get_carrier_info(phone),
                'geolocation': self._get_geolocation(phone),
                'lookup': self._reverse_lookup(phone),
                'status': 'ok'
            }
            return result
        except Exception as e:
            logger.error(f"Phone scan error: {str(e)}")
            return {
                'error': str(e),
                'phone': phone_number,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'error'
            }
    
    def _clean_phone(self, phone: str) -> str:
        """Clean and validate phone number"""
        try:
            # Remove common separators
            cleaned = re.sub(r'[\s\-\(\)\+\.]', '', phone)
            # Ensure it's digits only
            if not re.match(r'^\+?1?\d{10,15}$', cleaned):
                return None
            # Add + if missing
            if not cleaned.startswith('+'):
                if cleaned.startswith('1'):
                    cleaned = '+' + cleaned
                else:
                    cleaned = '+1' + cleaned
            return cleaned
        except:
            return None
    
    def _parse_phone(self, phone: str) -> dict:
        """Parse phone number with phonenumbers library"""
        try:
            parsed = phonenumbers.parse(phone, None)
            
            return {
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'country': phonenumbers.region_code_for_number(parsed),
                'type': self._get_phone_type(parsed),
                'valid': phonenumbers.is_valid_number(parsed),
                'possible': phonenumbers.is_possible_number(parsed),
                'formatted': phonenumbers.format_number(parsed, phonenumberutil.PhoneNumberFormat.INTERNATIONAL),
                'e164': phonenumbers.format_number(parsed, phonenumberutil.PhoneNumberFormat.E164),
            }
        except Exception as e:
            logger.error(f"Phone parsing error: {str(e)}")
            return {'error': str(e)}
    
    def _get_phone_type(self, parsed_number) -> str:
        """Determine phone number type"""
        try:
            phone_type = phonenumbers.number_type(parsed_number)
            type_map = {
                0: 'fixed_line',
                1: 'mobile',
                2: 'fixed_line_or_mobile',
                3: 'toll_free',
                4: 'premium_rate',
                5: 'shared_cost',
                6: 'voip',
                7: 'personal_number',
                8: 'pager',
                9: 'uan',
                10: 'voicemail',
                11: 'unknown'
            }
            return type_map.get(phone_type, 'unknown')
        except:
            return 'unknown'
    
    def _get_carrier_info(self, phone: str) -> dict:
        """Get carrier information from numlookup API"""
        try:
            # Using free numverify-like API
            url = f"https://api.numverify.com/validate?number={phone}&access_key=free"
            resp = requests.get(url, timeout=self.timeout)
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'carrier': data.get('carrier', 'Unknown'),
                    'line_type': data.get('line_type', 'Unknown'),
                    'country_name': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'timezone': data.get('timezone'),
                }
        except:
            pass
        
        # Fallback: Try telnyx API (free tier)
        try:
            url = f"https://api.telnyx.com/v2/number_lookup?phone_number={phone}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data:
                    return {
                        'carrier': data['data'].get('carrier_name', 'Unknown'),
                        'line_type': data['data'].get('line_type', 'Unknown'),
                        'country': data['data'].get('country_code'),
                    }
        except:
            pass
        
        return {'status': 'carrier_lookup_unavailable'}
    
    def _get_geolocation(self, phone: str) -> dict:
        """Get geolocation for phone number"""
        try:
            parsed = phonenumbers.parse(phone, None)
            geocoder = phonenumbers.geocoder.description_for_number(parsed, "en")
            
            # Get timezone
            timezone = phonenumbers.timezone.time_zones_for_number(parsed)
            
            # Try to get coordinates via area code / region
            area = phonenumbers.area_code_for_number(parsed)
            
            return {
                'area': geocoder,
                'timezone': timezone[0] if timezone else 'Unknown',
                'region': geocoder,
            }
        except Exception as e:
            logger.debug(f"Geolocation error: {str(e)}")
            return {}
    
    def _reverse_lookup(self, phone: str) -> dict:
        """Reverse lookup phone number"""
        try:
            # Try Google Voice API lookup (free)
            url = "https://www.truecaller.com/api/v1/searchPhoneNumber"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            params = {'phoneNumber': phone, 'countryCode': 'US'}
            
            resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data:
                    return {
                        'name': data['data'].get('name'),
                        'type': data['data'].get('type'),
                        'spam_status': data['data'].get('spamStatus'),
                    }
        except:
            pass
        
        # Try reverse phone lookup API
        try:
            url = f"https://freeapi.ipwhois.io/phone_lookup?phone={phone}"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'name': data.get('name'),
                    'address': data.get('address'),
                    'type': data.get('type'),
                }
        except:
            pass
        
        return {'status': 'reverse_lookup_unavailable'}
    
    def ping(self, phone: str) -> dict:
        """
        Ping/probe phone number for activity
        Check if number is active and can receive messages
        """
        try:
            result = {
                'phone': phone,
                'timestamp': datetime.utcnow().isoformat(),
                'ping_status': 'attempted',
            }
            
            # Parse number first
            parsed = phonenumbers.parse(phone, None)
            valid = phonenumbers.is_valid_number(parsed)
            
            result['valid_number'] = valid
            
            if valid:
                # Check if number is reachable (possible)
                result['possible'] = phonenumbers.is_possible_number(parsed)
                
                # Check carrier status
                carrier = self._get_carrier_info(phone)
                result['carrier'] = carrier
                
                # Determine if likely active (if carrier responds = active)
                result['likely_active'] = bool(carrier.get('carrier') and carrier.get('carrier') != 'Unknown')
            
            return result
        except Exception as e:
            logger.error(f"Ping error: {str(e)}")
            return {
                'error': str(e),
                'status': 'ping_failed'
            }
