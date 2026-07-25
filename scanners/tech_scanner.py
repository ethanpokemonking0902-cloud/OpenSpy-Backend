"""Technology Detection Scanner

Detects web technologies via:
- HTML/Meta tag analysis
- Response header detection
- JavaScript library fingerprinting
- Server detection

Provides:
- CMS detection (WordPress, Drupal, Joomla, etc.)
- Frameworks (React, Vue, Angular, etc.)
- Server software & versions
- CDN & hosting detection
- Analytics platforms
- Security headers analysis
"""

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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Comprehensive tech detection patterns
        self.tech_patterns = {
            'cms': {
                'WordPress': [r'wp-content', r'wp-includes', r'wp-json', r'wordpress', r'/wp-', r'__wp'],
                'Drupal': [r'drupal', r'sites/default/files', r'/sites/all/', r'/modules/'],
                'Joomla': [r'joomla', r'components/com_', r'Joomla!'],
                'Magento': [r'magento', r'Varien_Js_Cookie', r'/skin/'],
                'Shopify': [r'shopify', r'cdn.shopify.com', r'Shopify.shop'],
            },
            'frameworks': {
                'React': [r'react', r'__react', r'_react_root', r'react-app', r'ReactDOM'],
                'Vue.js': [r'vue', r'__vue__', r'v-app', r'vuex'],
                'Angular': [r'ng-app', r'angular', r'AngularJS', r'ng-'],
                'Next.js': [r'next', r'__NEXT', r'_next/'],
                'ASP.NET': [r'asp.net', r'__ViewState', r'__EVENTVALIDATION'],
            },
            'javascript_libs': {
                'jQuery': [r'jquery', r'jQuery', r'\$\(\)'],
                'Bootstrap': [r'bootstrap\.(min\.)?css', r'bootstrap\.(min\.)?js'],
                'Material': [r'material', r'materialize'],
                'Foundation': [r'foundation'],
                'Lodash': [r'lodash', r'_.'],
            },
            'servers': {
                'Apache': [r'Apache', r'httpd'],
                'Nginx': [r'nginx'],
                'IIS': [r'IIS', r'Microsoft-IIS', r'asp.net'],
                'LiteSpeed': [r'LiteSpeed'],
                'Cloudflare': [r'cloudflare', r'cf-ray'],
            },
            'analytics': {
                'Google Analytics': [r'google-analytics', r'gtag', r'GA_ID', r'_gat', r'analytics.google'],
                'Facebook Pixel': [r'facebook.com/tr', r'fbq\('],
                'Segment': [r'segment', r'analytics.js'],
                'Mixpanel': [r'mixpanel'],
                'Hotjar': [r'hotjar'],
            },
            'cdn': {
                'Cloudflare': [r'cloudflare', r'cdnjs.cloudflare.com'],
                'Akamai': [r'akamai'],
                'CloudFront': [r'cloudfront'],
                'jsDelivr': [r'cdn.jsdelivr.net'],
                'cdnjs': [r'cdnjs.cloudflare.com'],
            },
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
                'security_findings': self._analyze_security(url),
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
        """Detect technologies from HTML and headers"""
        techs = {
            'cms': [],
            'frameworks': [],
            'servers': [],
            'javascript_libs': [],
            'analytics': [],
            'cdn': [],
            'other': [],
        }
        
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            html = resp.text
            headers = resp.headers
            
            # Check all patterns
            for category, patterns_dict in self.tech_patterns.items():
                for tech, patterns in patterns_dict.items():
                    for pattern in patterns:
                        if re.search(pattern, html, re.IGNORECASE):
                            if tech not in techs[category]:
                                techs[category].append(tech)
                            break
            
            # Check meta tags
            soup = BeautifulSoup(html, 'html.parser')
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                
                if 'generator' in name and content:
                    techs['cms'].append(f"Generated by: {content}")
                if 'powered-by' in name and content:
                    techs['cms'].append(f"Powered by: {content}")
            
            # Check script sources
            for script in soup.find_all('script'):
                src = script.get('src', '')
                if src:
                    if 'google-analytics' in src or 'gtag' in src:
                        if 'Google Analytics' not in techs['analytics']:
                            techs['analytics'].append('Google Analytics')
                    if 'facebook' in src:
                        if 'Facebook' not in techs['analytics']:
                            techs['analytics'].append('Facebook Pixel')
                    if 'cdn' in src or 'cloudflare' in src:
                        if 'CDN' not in techs['cdn']:
                            techs['cdn'].append('CDN Detected')
            
            # Clean up empty arrays
            techs = {k: v for k, v in techs.items() if v}
            
            return techs
        except Exception as e:
            logger.error(f"Technology detection error: {str(e)}")
            return {'error': str(e)}
    
    def _analyze_headers(self, url: str) -> dict:
        """Analyze response headers for tech info"""
        try:
            resp = requests.head(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            headers_of_interest = [
                'Server', 'X-Powered-By', 'X-Frame-Options', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy', 'Via',
                'X-Served-By', 'X-Cache', 'X-AspNet-Version', 'X-Runtime'
            ]
            
            result = {}
            for header in headers_of_interest:
                if header in resp.headers:
                    result[header] = resp.headers[header]
            
            return result
        except Exception as e:
            logger.debug(f"Header analysis error: {str(e)}")
            return {}
    
    def _analyze_security(self, url: str) -> dict:
        """Analyze security posture"""
        findings = {
            'secure_headers_present': [],
            'secure_headers_missing': [],
            'https': False,
            'issues': []
        }
        
        try:
            resp = requests.head(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Check HTTPS
            findings['https'] = url.startswith('https://')
            
            # Check security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'Content-Security-Policy': 'XSS Protection',
            }
            
            for header, description in security_headers.items():
                if header in resp.headers:
                    findings['secure_headers_present'].append({
                        'header': header,
                        'description': description,
                        'value': resp.headers[header][:50]  # Truncate
                    })
                else:
                    findings['secure_headers_missing'].append({
                        'header': header,
                        'description': description,
                        'severity': 'medium'
                    })
            
            # Check for common issues
            if not findings['https']:
                findings['issues'].append({
                    'issue': 'No HTTPS',
                    'severity': 'high',
                    'recommendation': 'Enable HTTPS/SSL'
                })
            
            if len(findings['secure_headers_missing']) > 2:
                findings['issues'].append({
                    'issue': 'Missing multiple security headers',
                    'severity': 'high',
                    'recommendation': 'Implement security headers'
                })
            
            return findings
        except Exception as e:
            logger.debug(f"Security analysis error: {str(e)}")
            return {'error': str(e)}
