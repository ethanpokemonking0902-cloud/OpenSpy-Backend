"""Technology Detection Scanner"""

import requests
from datetime import datetime
import logging
import re
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class TechScanner:
    """Detect technologies used on a website"""
    
    def __init__(self):
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def scan(self, url: str) -> dict:
        """
        Detect technologies on a website
        """
        try:
            # Ensure URL has scheme
            if not url.startswith('http://') and not url.startswith('https://'):
                url = f'https://{url}'
            
            result = {
                'url': url,
                'timestamp': datetime.utcnow().isoformat(),
                'technologies': self._detect_technologies(url),
                'headers': self._analyze_headers(url),
            }
            return result
        except Exception as e:
            logger.error(f"Tech scan error: {str(e)}")
            return {
                'error': str(e),
                'url': url,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _detect_technologies(self, url: str) -> dict:
        """Detect technologies from HTML"""
        techs = {
            'cms': [],
            'frameworks': [],
            'servers': [],
            'javascript_libs': [],
            'analytics': [],
            'cdn': [],
        }
        
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)
            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check for common patterns
            detections = {
                'WordPress': r'wp-content|wp-includes|wp-json',
                'Drupal': r'drupal|sites/default/files',
                'Joomla': r'joomla|components/com_',
                'React': r'react|__react|_react_root',
                'Vue.js': r'vue|__vue__|v-app',
                'Angular': r'ng-app|angular',
                'jQuery': r'jquery|jQuery|\\$',
                'Bootstrap': r'bootstrap',
                'Apache': r'apache',
                'Nginx': r'nginx',
                'IIS': r'iis|asp.net',
                'Google Analytics': r'google-analytics|gtag|GA',
                'Cloudflare': r'cloudflare|cf-ray',
                'Akamai': r'akamai',
            }
            
            for tech, pattern in detections.items():
                if re.search(pattern, html, re.IGNORECASE):
                    # Categorize
                    if tech in ['WordPress', 'Drupal', 'Joomla']:
                        techs['cms'].append(tech)
                    elif tech in ['React', 'Vue.js', 'Angular']:
                        techs['frameworks'].append(tech)
                    elif tech in ['jQuery', 'Bootstrap']:
                        techs['javascript_libs'].append(tech)
                    elif tech in ['Apache', 'Nginx', 'IIS']:
                        techs['servers'].append(tech)
                    elif 'Analytics' in tech:
                        techs['analytics'].append(tech)
                    elif tech in ['Cloudflare', 'Akamai']:
                        techs['cdn'].append(tech)
            
            # Check meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                
                if 'generator' in name:
                    techs['cms'].append(f"Generator: {content}")
                if 'powered-by' in name:
                    techs['cms'].append(f"Powered by: {content}")
            
            # Check script sources
            for script in soup.find_all('script'):
                src = script.get('src', '')
                if 'google-analytics' in src or 'gtag' in src:
                    techs['analytics'].append('Google Analytics')
                if 'facebook' in src:
                    techs['analytics'].append('Facebook Pixel')
                if 'cdn' in src or 'cloudflare' in src:
                    techs['cdn'].append('CDN Detected')
            
            return techs
        except Exception as e:
            logger.error(f"Technology detection error: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_headers(self, url: str) -> dict:
        """Analyze response headers"""
        try:
            resp = requests.head(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            
            headers_of_interest = [
                'Server', 'X-Powered-By', 'X-Frame-Options', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy', 'Via',
                'X-Served-By', 'X-Cache'
            ]
            
            result = {}
            for header in headers_of_interest:
                if header in resp.headers:
                    result[header] = resp.headers[header]
            
            return result
        except Exception as e:
            logger.error(f"Header analysis error: {str(e)}")
            return {}
