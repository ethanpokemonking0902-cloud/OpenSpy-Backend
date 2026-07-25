"""
Phone Number Intelligence Scanner

Provides phone number validation, carrier lookup, geolocation, and reverse lookup
using NumLookup API + free APIs and the open-source phonenumbers library.

⭐ Primary Data Source:
─────────────────────
NumLookup API (https://www.numlookup.com)
- Carrier/operator name
- Line type detection
- Comprehensive validation
- Requires API key: NUMLOOKUP_KEY

⭐ Fallback/Free Data Sources:
─────────────────────────────
1. phonenumbers library (no auth needed)
   - Number parsing and validation
   - International format conversion
   - Phone type detection (mobile, landline, VoIP, etc.)
   - Timezone and area detection

2. MCC-MNC-Lookup (limited free calls)
   - Operator/carrier lookup fallback
   - Number type information

3. AnyWho / Quicksearch (free web scraping)
   - US reverse phone lookup (limited)

🔧 Setup:
─────────
1. Set NUMLOOKUP_KEY in .env file
2. API key format: num_live_XXXXXXXXXXXXXXXX

📊 Response Data with NumLookup:
─────────────────────────────────
{
  "phone": "+14159929960",
  "parsed": {
    "country_code": 1,
    "national_number": 4159929960,
    "country": "US",
    "type": "mobile",
    "valid": true,
    "formatted": "+1 415-992-9960",
    "e164": "+14159929960"
  },
  "carrier": {
    "carrier": "AT&T",
    "country": "US",
    "country_code": "1",
    "type": "mobile",
    "is_valid": true,
    "status": "found"
  },
  "geolocation": {
    "area": "San Francisco, CA",
    "timezone": "America/Los_Angeles",
    "country_code": "US"
  }
}

⚠️  Rate Limiting:
──────────────────
NumLookup API may have request limits based on your account plan.
Implement caching for production environments.
"""

import requests
import re
import os
from datetime import datetime
import logging
from phonenumbers import phonenumberutil
import phonenumbers

logger = logging.getLogger(__name__)

# Load API key from environment
NUMLOOKUP_KEY = os.getenv('NUMLOOKUP_KEY', '')

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
        """Clean and validate phone number - handles international formats"""
        try:
            # Remove common separators but keep + prefix
            if phone.startswith('+'):
                # International format - preserve +
                cleaned = '+' + re.sub(r'[\s\-\(\)\.]', '', phone[1:])
            else:
                # Domestic format - just clean
                cleaned = re.sub(r'[\s\-\(\)\.]', '', phone)
                # If it's all digits and looks international (10-15 digits), add +
                if re.match(r'^\d{10,15}$', cleaned):
                    cleaned = '+' + cleaned
            
            # Verify format: + followed by 10-15 digits
            if not re.match(r'^\+\d{10,15}$', cleaned):
                return None
            
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
        """Get carrier information from NumLookup API (primary) + fallback APIs"""
        
        # Try NumLookup API first (paid, much better data)
        if NUMLOOKUP_KEY:
            try:
                # Format: +1234567890 or 1234567890
                clean_phone = phone if phone.startswith('+') else '+' + phone.lstrip('+')
                
                url = f"https://api.numlookupapi.com/v1/validate/{clean_phone}"
                params = {
                    'apikey': NUMLOOKUP_KEY
                }
                
                resp = requests.get(url, params=params, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('valid'):
                        return {
                            'carrier': data.get('carrier', 'Unknown'),
                            'country': data.get('country', 'Unknown'),
                            'country_code': data.get('country_code'),
                            'line_type': data.get('line_type'),
                            'is_valid': data.get('valid', True),
                            'status': 'found'
                        }
            except Exception as e:
                logger.debug(f"NumLookup API error: {str(e)}")
        
        # Fallback: Try MCC-MNC-Lookup (free, limited)
        try:
            parsed = phonenumbers.parse(phone, None)
            country = phonenumbers.region_code_for_number(parsed)
            clean_phone = phone.replace('+', '').replace(' ', '').replace('-', '')
            
            url = "https://mcc-mnc-lookup.com/api"
            params = {
                'number': clean_phone,
                'country': country
            }
            
            resp = requests.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('data'):
                    carrier_data = data.get('data', {})
                    return {
                        'carrier': carrier_data.get('operator') or carrier_data.get('carrier') or 'Unknown',
                        'country': country,
                        'country_code': parsed.country_code,
                        'number_type': self._get_phone_type(parsed),
                        'status': 'found'
                    }
        except Exception as e:
            logger.debug(f"MCC-MNC lookup error: {str(e)}")
        
        # Fallback: Return parsed number metadata
        try:
            parsed = phonenumbers.parse(phone, None)
            return {
                'country': phonenumbers.region_code_for_number(parsed),
                'country_code': parsed.country_code,
                'number_type': self._get_phone_type(parsed),
                'status': 'parsed_only',
                'note': 'External APIs unavailable; using local validation only'
            }
        except Exception as e:
            logger.debug(f"Fallback parsing failed: {str(e)}")
            return {
                'status': 'carrier_lookup_unavailable',
                'note': 'No carrier data available'
            }
    
    def _get_geolocation(self, phone: str) -> dict:
        """Get geolocation for phone number using multiple methods"""
        try:
            parsed = phonenumbers.parse(phone, None)
            
            # Get area description from phonenumbers library
            try:
                from phonenumbers import geocoder
                area = geocoder.description_for_number(parsed, "en")
            except:
                area = None
            
            # Get timezone
            try:
                from phonenumbers import timezone
                timezones = timezone.time_zones_for_number(parsed)
                tz = timezones[0] if timezones else 'Unknown'
            except:
                tz = 'Unknown'
            
            # Get country code
            country = phonenumbers.region_code_for_number(parsed)
            
            result = {
                'area': area or f"Country code {parsed.country_code}",
                'region': area or 'Unknown',
                'timezone': tz,
                'country_code': country,
                'country_dialing_code': f"+{parsed.country_code}"
            }
            
            return result
        except Exception as e:
            logger.debug(f"Geolocation error: {str(e)}")
            return {'status': 'geolocation_unavailable', 'error': str(e)}
    
    def _reverse_lookup(self, phone: str) -> dict:
        """Reverse lookup phone number from free sources"""
        try:
            clean_phone = phone.replace('+', '').lstrip('1') if phone.startswith(('+1', '1')) else phone.replace('+', '')
            
            # Try AnyWho free API (US numbers)
            url = f"https://www.anywho.com/phonelookup"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            params = {'phonenumber': clean_phone}
            
            resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            if resp.status_code == 200 and 'person' in resp.text.lower():
                # Basic scraping to detect if result found
                return {
                    'name': 'Found (name hidden)',
                    'status': 'found_limited',
                    'note': 'Detailed name lookup requires active subscription'
                }
        except Exception as e:
            logger.debug(f"AnyWho reverse lookup failed: {str(e)}")
        
        # Fallback: Try free reverse lookup aggregator
        try:
            url = f"https://quicksearch.com.au/phone/{clean_phone}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            
            if resp.status_code == 200:
                # Check if we get result
                if 'not found' not in resp.text.lower():
                    return {
                        'status': 'found_limited',
                        'note': 'Reverse lookup available (limited free data)'
                    }
        except Exception as e:
            logger.debug(f"Reverse lookup attempt 2 failed: {str(e)}")
        
        return {
            'status': 'reverse_lookup_unavailable',
            'note': 'Most reverse lookups require paid subscription or API key'
        }
    
    def ping(self, phone: str) -> dict:
        """
        Check phone number validity and carrier status
        Returns validation info and whether carrier data is available
        """
        try:
            phone = self._clean_phone(phone)
            if not phone:
                return {'error': 'Invalid phone number format', 'status': 'failed'}
            
            result = {
                'phone': phone,
                'timestamp': datetime.utcnow().isoformat(),
            }
            
            # Parse number for validation
            parsed = phonenumbers.parse(phone, None)
            result['valid'] = phonenumbers.is_valid_number(parsed)
            result['possible'] = phonenumbers.is_possible_number(parsed)
            
            # Get carrier info
            carrier = self._get_carrier_info(phone)
            result['carrier'] = carrier
            
            # Determine if number is likely active (has carrier data)
            has_carrier_data = (
                carrier.get('status') == 'found' or 
                (carrier.get('carrier') and carrier.get('carrier') != 'Unknown')
            )
            result['likely_active'] = has_carrier_data
            result['status'] = 'ok'
            
            return result
        except Exception as e:
            logger.error(f"Ping error: {str(e)}")
            return {
                'error': str(e),
                'phone': phone if 'phone' in locals() else 'unknown',
                'status': 'failed'
            }
