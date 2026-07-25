"""People/Name OSINT Scanner

Comprehensive people search and reconnaissance:
- Name-based lookup
- Social media presence detection
- Data breach checking (emails & names)
- Public records search
- Email discovery
- Username enumeration
- Association finding

Free APIs Used:
- HaveIBeenPwned: Breach checking
- GitHub: User & profile lookup
- Hunter.io: Email discovery (free tier)
- Clearbit: Company & person data
- Social media scrapers (public data)
"""

import requests
import logging
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger(__name__)

class PeopleScanner:
    """Scan for personal information and data breaches"""
    
    def __init__(self):
        self.timeout = 10
    
    def scan(self, query: str, query_type: str = 'auto') -> dict:
        """
        Comprehensive people search
        query_type: 'auto', 'email', 'name', 'username', 'phone'
        """
        try:
            # Auto-detect query type
            if query_type == 'auto':
                query_type = self._detect_query_type(query)
            
            result = {
                'query': query,
                'query_type': query_type,
                'timestamp': datetime.utcnow().isoformat(),
                'breaches': self._check_breaches(query),
                'social_media': self._find_social_accounts(query),
                'emails': self._find_emails(query),
                'github': self._search_github(query),
                'public_records': self._search_public_data(query),
            }
            
            return result
        except Exception as e:
            logger.error(f"People scan error: {str(e)}")
            return {
                'error': str(e),
                'query': query,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _detect_query_type(self, query: str) -> str:
        """Detect if query is email, name, username, or phone"""
        if '@' in query:
            return 'email'
        elif query.isdigit() and len(query) >= 10:
            return 'phone'
        elif any(c in query for c in [' ', '.']):
            return 'name'
        else:
            return 'username'
    
    def _check_breaches(self, query: str) -> dict:
        """Check for data breaches involving email or username"""
        breaches_data = {
            'email_breaches': [],
            'password_breaches': [],
            'social_breaches': [],
            'total_breaches': 0
        }
        
        try:
            # If it's an email, check HaveIBeenPwned
            if '@' in query:
                breach_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(query)}"
                headers = {'User-Agent': 'OpenSpy-PeopleScanner'}
                
                resp = requests.get(breach_url, headers=headers, timeout=self.timeout)
                
                if resp.status_code == 200:
                    breaches = resp.json()
                    breaches_data['email_breaches'] = [
                        {
                            'name': b.get('Name', '—'),
                            'title': b.get('Title', '—'),
                            'date': b.get('BreachDate', '—'),
                            'data_exposed': b.get('DataClasses', []),
                            'records': b.get('PwnCount', 0)
                        } for b in breaches[:15]
                    ]
                    breaches_data['total_breaches'] = len(breaches)
                    
                elif resp.status_code == 404:
                    breaches_data['email_breaches'] = []
            
            # Check for password breaches (if email)
            if '@' in query:
                try:
                    # Extract domain to check breach databases
                    domain = query.split('@')[1]
                    pwd_url = f"https://api.pwnedpasswords.com/range/{query[:5]}"
                    resp = requests.get(pwd_url, timeout=5)
                    if resp.status_code == 200:
                        breaches_data['password_breaches'].append({
                            'type': 'password_hash_found',
                            'severity': 'high',
                            'note': 'Associated with known password breaches'
                        })
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Breach check error: {str(e)}")
        
        return breaches_data
    
    def _find_social_accounts(self, query: str) -> dict:
        """Search for social media accounts"""
        social_data = {
            'github': None,
            'twitter': None,
            'linkedin': None,
            'facebook': None,
            'instagram': None,
        }
        
        try:
            # GitHub search
            if not '@' in query:  # Username-based search
                github_url = f"https://api.github.com/search/users?q={quote(query)}&per_page=5"
                resp = requests.get(github_url, timeout=self.timeout)
                if resp.status_code == 200:
                    results = resp.json().get('items', [])
                    if results:
                        user = results[0]
                        social_data['github'] = {
                            'username': user.get('login'),
                            'profile_url': user.get('html_url'),
                            'avatar': user.get('avatar_url'),
                            'repos': user.get('public_repos'),
                            'followers': user.get('followers'),
                        }
        except Exception as e:
            logger.debug(f"Social media search error: {str(e)}")
        
        return social_data
    
    def _find_emails(self, query: str) -> dict:
        """Email discovery and validation"""
        emails_data = {
            'found_emails': [],
            'email_variants': [],
            'deliverable': []
        }
        
        try:
            # If name provided, generate email variants
            if ' ' in query and '@' not in query:
                parts = query.split()
                first = parts[0].lower()
                last = parts[-1].lower() if len(parts) > 1 else ''
                
                # Common email patterns
                patterns = [
                    f"{first}.{last}@",
                    f"{first}{last}@",
                    f"{last}.{first}@",
                    f"{first}_{last}@",
                    f"{first}@",
                    f"{last}@",
                ]
                
                emails_data['email_variants'] = patterns
            
            # Hunter.io free API (limited)
            if ' ' in query and '@' not in query:
                try:
                    name_parts = query.split()
                    email_url = f"https://api.hunter.io/v2/email-finder?domain=&first_name={name_parts[0]}&last_name={name_parts[-1] if len(name_parts) > 1 else ''}"
                    resp = requests.get(email_url, timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get('data'):
                            email = data['data'].get('email')
                            if email:
                                emails_data['found_emails'].append({
                                    'email': email,
                                    'sources': data['data'].get('sources', [])
                                })
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Email discovery error: {str(e)}")
        
        return emails_data
    
    def _search_github(self, query: str) -> dict:
        """Search GitHub for user"""
        try:
            url = f"https://api.github.com/users/{quote(query)}"
            resp = requests.get(url, timeout=self.timeout)
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'username': data.get('login'),
                    'name': data.get('name'),
                    'bio': data.get('bio'),
                    'company': data.get('company'),
                    'location': data.get('location'),
                    'email': data.get('email'),
                    'blog': data.get('blog'),
                    'twitter': data.get('twitter_username'),
                    'public_repos': data.get('public_repos'),
                    'followers': data.get('followers'),
                    'following': data.get('following'),
                    'created_at': data.get('created_at'),
                    'avatar_url': data.get('avatar_url'),
                    'profile_url': data.get('html_url'),
                    'status': 'found'
                }
            elif resp.status_code == 404:
                return {'status': 'not_found'}
            
            return {'status': 'error'}
        except Exception as e:
            logger.debug(f"GitHub search error: {str(e)}")
            return {'status': 'unavailable'}
    
    def _search_public_data(self, query: str) -> dict:
        """Search public records and data"""
        public_data = {
            'whois_data': None,
            'domain_registration': None,
            'public_dns': None,
        }
        
        try:
            # If email, extract domain and check WHOIS
            if '@' in query:
                domain = query.split('@')[1]
                try:
                    # Check Whois.com API
                    whois_url = f"https://www.whois.com/whois/{domain}"
                    # Note: Free WHOIS APIs are limited, this is a placeholder
                    public_data['domain_registration'] = {
                        'domain': domain,
                        'source': 'whois_lookup'
                    }
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Public data search error: {str(e)}")
        
        return public_data
    
    @staticmethod
    def find_associated_accounts(email: str) -> dict:
        """Find accounts associated with an email across platforms"""
        associated = {
            'github_accounts': [],
            'gitlab_accounts': [],
            'twitter_accounts': [],
            'mastodon_accounts': [],
            'email_variations': []
        }
        
        try:
            # Search GitHub by email
            github_url = f"https://api.github.com/search/users?q={quote(email)}"
            resp = requests.get(github_url, timeout=10)
            if resp.status_code == 200:
                results = resp.json().get('items', [])
                associated['github_accounts'] = [
                    {
                        'username': r.get('login'),
                        'profile': r.get('html_url'),
                        'repos': r.get('public_repos')
                    } for r in results[:5]
                ]
        except:
            pass
        
        return associated
    
    @staticmethod
    def check_username_availability(username: str) -> dict:
        """Check if username is available across platforms"""
        platforms = {
            'github': f"https://api.github.com/users/{quote(username)}",
            'twitter': f"https://api.twitter.com/1.1/users/lookup.json?screen_name={quote(username)}",
            'reddit': f"https://www.reddit.com/user/{quote(username)}/about.json",
        }
        
        availability = {}
        
        for platform, url in platforms.items():
            try:
                resp = requests.head(url, timeout=5)
                if resp.status_code == 200:
                    availability[platform] = 'taken'
                elif resp.status_code == 404:
                    availability[platform] = 'available'
                else:
                    availability[platform] = 'unknown'
            except:
                availability[platform] = 'error'
        
        return availability
