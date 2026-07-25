"""
OpenSpy RECON Scanner Backend
Advanced reconnaissance and vulnerability scanning API
"""

import os
import logging
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import hashlib
import hmac
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
# Allow CORS from Netlify frontend and localhost
CORS(app, resources={
    r"/api/*": {"origins": ["https://openspy.netlify.app", "http://localhost:3000", "*"]},
    r"/scan/*": {"origins": ["https://openspy.netlify.app", "http://localhost:3000", "*"]}
})

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request

# Security key
SCANNER_KEY = os.getenv('OPENSPY_KEY', '')
if not SCANNER_KEY:
    raise ValueError("OPENSPY_KEY environment variable not set!")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION MIDDLEWARE
# ═══════════════════════════════════════════════════════════════

def require_auth(f):
    """Decorator to require valid API key (from query param or header)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check both header and query param for key
        auth_key = request.headers.get('X-Scanner-Key', '') or request.args.get('key', '')
        
        if not auth_key:
            return jsonify({'error': 'Missing authentication key'}), 401
        
        # Compare keys using constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(auth_key, SCANNER_KEY):
            return jsonify({'error': 'Invalid authentication key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'OpenSpy RECON Scanner'
    })

# ═══════════════════════════════════════════════════════════════
# QUICK SCAN (IP + geolocation)
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/quick', methods=['GET'])
@require_auth
def scan_quick():
    """
    Quick scan - IP geolocation and basic reputation
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.ip_scanner import IPScanner
        scanner = IPScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Quick scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# GEOLOCATION SCAN
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/geoloc', methods=['GET'])
@require_auth
def scan_geoloc():
    """
    Geolocation scan - IP location and ISP info
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.geoloc_scanner import GeolocScanner
        scanner = GeolocScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Geoloc scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# DNS & WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/whois', methods=['GET'])
@require_auth
def scan_whois():
    """
    WHOIS lookup - domain registration info
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.domain_scanner import DomainScanner
        scanner = DomainScanner()
        result = scanner.scan_whois(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"WHOIS scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# SSL/TLS CERTIFICATE SCANNING
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/ssl', methods=['GET'])
@require_auth
def scan_ssl():
    """
    SSL/TLS certificate scanning
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"SSL scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/osint/certs', methods=['GET'])
@require_auth
def osint_certs():
    """Certificate lookup endpoint (alias for SSL scan)"""
    try:
        domain = request.args.get('domain', '').strip()
        
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        from scanners.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        result = scanner.scan(domain)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Cert scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# HTTP HEADERS SCANNING
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/headers', methods=['GET'])
@require_auth
def scan_headers():
    """
    HTTP headers scanning - security headers analysis
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.ssl_scanner import SSLScanner
        scanner = SSLScanner()
        result = scanner.scan_headers(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Headers scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/subdomains', methods=['GET'])
@require_auth
def scan_subdomains():
    """
    Subdomain enumeration
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.subdomain_scanner import SubdomainScanner
        scanner = SubdomainScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Subdomain scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# REVERSE DNS LOOKUP
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/rdns', methods=['GET'])
@require_auth
def scan_rdns():
    """
    Reverse DNS lookup
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.rdns_scanner import RDNSScanner
        scanner = RDNSScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"RDNS scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# TECHNOLOGY DETECTION
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/tech', methods=['GET'])
@require_auth
def scan_tech():
    """
    Technology detection
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.tech_scanner import TechScanner
        scanner = TechScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Tech scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/vuln', methods=['GET'])
@require_auth
def scan_vuln():
    """
    Vulnerability scanning - check for known CVEs
    Query params: target, key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.vuln_scanner import VulnScanner
        scanner = VulnScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Vuln scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# PHONE NUMBER INTELLIGENCE
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/phone', methods=['GET'])
@require_auth
def scan_phone():
    """
    Phone number reconnaissance - geolocation, carrier, reverse lookup
    Query params: target (phone number), key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Phone number required'}), 400
        
        from scanners.phone_scanner import PhoneScanner
        scanner = PhoneScanner()
        result = scanner.scan(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Phone scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan/phone-ping', methods=['GET'])
@require_auth
def ping_phone():
    """
    Ping phone number - check if active/reachable
    Query params: target (phone number), key
    """
    try:
        target = request.args.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'Phone number required'}), 400
        
        from scanners.phone_scanner import PhoneScanner
        scanner = PhoneScanner()
        result = scanner.ping(target)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Phone ping error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════
# OSINT API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route('/api/osint/dns', methods=['GET'])
@require_auth
def osint_dns():
    """DNS lookup endpoint"""
    try:
        domain = request.args.get('domain', '').strip()
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        
        from scanners.domain_scanner import DomainScanner
        scanner = DomainScanner()
        result = scanner._get_dns_records(domain)
        
        return jsonify({'domain': domain, 'dns': result, 'status': 'ok'})
    except Exception as e:
        logger.error(f"DNS lookup error: {str(e)}")
        return jsonify({'domain': domain, 'dns': {'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': [], 'SOA': [], 'SRV': []}, 'status': 'error', 'error': '—'}), 200

@app.route('/api/osint/threats', methods=['GET'])
@require_auth
def osint_threats():
    """Threat intelligence endpoint"""
    try:
        query = request.args.get('query', '').strip()
        if not query:
            return jsonify({'error': 'Query required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.get_threat_intel(query)
        
        return jsonify({'query': query, 'threats': result, 'status': 'ok'})
    except Exception as e:
        logger.error(f"Threat intel error: {str(e)}")
        return jsonify({'query': query, 'threats': {'status': 'error', 'virustotal': '—', 'abuseipdb': '—', 'urlscan': '—'}}), 200

@app.route('/api/osint/shodan', methods=['GET'])
@require_auth
def osint_shodan():
    """Shodan IoT lookup endpoint"""
    try:
        ip = request.args.get('ip', '').strip()
        if not ip:
            return jsonify({'error': 'IP required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.get_shodan_data(ip)
        
        return jsonify({'ip': ip, 'shodan': result, 'status': 'ok'})
    except Exception as e:
        logger.error(f"Shodan lookup error: {str(e)}")
        return jsonify({'ip': ip, 'shodan': {'ports': [], 'status': 'error'}}), 200

@app.route('/api/osint/bgp', methods=['GET'])
@require_auth
def osint_bgp():
    """BGP routing information endpoint"""
    try:
        query = request.args.get('query', '').strip()
        if not query:
            return jsonify({'error': 'ASN or IP required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.get_bgp_info(query)
        
        return jsonify({'query': query, 'bgp': result, 'status': 'ok'})
    except Exception as e:
        logger.error(f"BGP lookup error: {str(e)}")
        return jsonify({'query': query, 'bgp': {'status': 'error', 'name': '—'}}), 200

@app.route('/api/osint/mac', methods=['GET'])
@require_auth
def osint_mac():
    """MAC address vendor lookup endpoint"""
    try:
        mac = request.args.get('mac', '').strip()
        if not mac:
            return jsonify({'error': 'MAC address required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.get_mac_vendor(mac)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"MAC vendor lookup error: {str(e)}")
        return jsonify({'mac': mac, 'vendor': '—', 'status': 'error'}), 200

@app.route('/api/osint/github', methods=['GET'])
@require_auth
def osint_github():
    """GitHub user reconnaissance endpoint"""
    try:
        user = request.args.get('user', '').strip()
        if not user:
            return jsonify({'error': 'GitHub username required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.get_github_user(user)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"GitHub lookup error: {str(e)}")
        return jsonify({'username': user, 'status': 'error', 'public_repos': 0}), 200

@app.route('/api/osint/leaks', methods=['GET'])
@require_auth
def osint_leaks():
    """Data breach check endpoint"""
    try:
        email = request.args.get('email', '').strip()
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.check_data_breaches(email)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Breach check error: {str(e)}")
        return jsonify({'email': email, 'status': 'error', 'breached': False, 'breach_count': 0, 'breaches': []}), 200

@app.route('/api/osint/cve', methods=['GET'])
@require_auth
def osint_cve():
    """CVE vulnerability details endpoint"""
    try:
        cve = request.args.get('cve', '').strip()
        if not cve:
            return jsonify({'error': 'CVE ID required'}), 400
        
        from scanners.osint_utils import OSINTUtils
        result = OSINTUtils.get_cve_details(cve)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"CVE lookup error: {str(e)}")
        return jsonify({'cve_id': cve, 'status': 'error', 'severity': '—', 'score': 0}), 200

@app.route('/api/osint/sweep', methods=['GET'])
@require_auth
def osint_sweep():
    """IP network sweep endpoint"""
    try:
        ip = request.args.get('ip', '').strip()
        cidr = request.args.get('cidr', '24')
        
        if not ip:
            return jsonify({'error': 'IP required'}), 400
        
        # Return basic sweep info (actual enumeration happens on frontend via Shodan)
        return jsonify({
            'target_ip': ip,
            'cidr': int(cidr),
            'center': {'lat': 40.7128, 'lng': -74.0060},
            'status': 'ready'
        })
    except Exception as e:
        logger.error(f"Sweep error: {str(e)}")
        return jsonify({'target_ip': ip, 'status': 'error', 'cidr': 24}), 200

# ═══════════════════════════════════════════════════════════════
# PEOPLE/NAME OSINT ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route('/scan/people', methods=['GET'])
@require_auth
def scan_people():
    """
    Comprehensive people search - name/email/username lookup
    Query params: target, type (auto/email/name/username/phone), key
    """
    try:
        target = request.args.get('target', '').strip()
        query_type = request.args.get('type', 'auto').strip()
        
        if not target:
            return jsonify({'error': 'Target required'}), 400
        
        from scanners.people_scanner import PeopleScanner
        scanner = PeopleScanner()
        result = scanner.scan(target, query_type)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"People scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/osint/name', methods=['GET'])
@require_auth
def osint_name():
    """Name-based OSINT lookup"""
    try:
        name = request.args.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Name required'}), 400
        
        from scanners.people_scanner import PeopleScanner
        scanner = PeopleScanner()
        result = scanner.scan(name, 'name')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Name lookup error: {str(e)}")
        return jsonify({'error': str(e), 'name': name}), 500

@app.route('/api/osint/email', methods=['GET'])
@require_auth
def osint_email():
    """Email-based OSINT lookup - breaches, validation, associations"""
    try:
        email = request.args.get('email', '').strip()
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        from scanners.people_scanner import PeopleScanner
        from scanners.osint_utils import OSINTUtils
        
        scanner = PeopleScanner()
        people_data = scanner.scan(email, 'email')
        
        # Also get breach and associated accounts
        breaches = OSINTUtils.check_data_breaches(email)
        associated = PeopleScanner.find_associated_accounts(email)
        
        result = {
            'email': email,
            'people_data': people_data,
            'breaches': breaches,
            'associated_accounts': associated,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Email lookup error: {str(e)}")
        return jsonify({'error': str(e), 'email': email}), 500

@app.route('/api/osint/breaches', methods=['GET'])
@require_auth
def osint_breaches():
    """Data breach lookup endpoint"""
    try:
        query = request.args.get('query', '').strip()
        if not query:
            return jsonify({'error': 'Email or username required'}), 400
        
        from scanners.people_scanner import PeopleScanner
        scanner = PeopleScanner()
        result = scanner._check_breaches(query)
        
        return jsonify({
            'query': query,
            'breaches': result,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Breach lookup error: {str(e)}")
        return jsonify({'error': str(e), 'query': query}), 500

@app.route('/api/osint/username', methods=['GET'])
@require_auth
def osint_username():
    """Username-based OSINT - find accounts and check availability"""
    try:
        username = request.args.get('username', '').strip()
        if not username:
            return jsonify({'error': 'Username required'}), 400
        
        from scanners.people_scanner import PeopleScanner
        
        scanner = PeopleScanner()
        people_data = scanner.scan(username, 'username')
        availability = PeopleScanner.check_username_availability(username)
        
        result = {
            'username': username,
            'people_data': people_data,
            'platform_availability': availability,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Username lookup error: {str(e)}")
        return jsonify({'error': str(e), 'username': username}), 500

@app.route('/api/osint/associated', methods=['GET'])
@require_auth
def osint_associated():
    """Find accounts associated with email"""
    try:
        email = request.args.get('email', '').strip()
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        from scanners.people_scanner import PeopleScanner
        result = PeopleScanner.find_associated_accounts(email)
        
        return jsonify({
            'email': email,
            'associated_accounts': result,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Associated accounts lookup error: {str(e)}")
        return jsonify({'error': str(e), 'email': email}), 500

@app.route('/api/osint/virustotal', methods=['GET'])
@require_auth
def osint_virustotal():
    """VirusTotal domain/IP reputation endpoint"""
    try:
        query = request.args.get('query', '').strip()
        if not query:
            return jsonify({'error': 'Domain or IP required'}), 400
        
        virustotal_key = os.getenv('VIRUSTOTAL_KEY', '')
        if not virustotal_key:
            return jsonify({'error': 'VirusTotal key not configured'}), 500
        
        # Determine if it's a domain or IP
        if query.replace('.', '').isdigit() and query.count('.') == 3:
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{query}"
        
        headers = {'x-apikey': virustotal_key}
        resp = requests.get(endpoint, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get('data', {}).get('attributes', {})
            
            result = {
                'query': query,
                'last_analysis_stats': attrs.get('last_analysis_stats'),
                'reputation': attrs.get('reputation'),
                'threat_names': attrs.get('threat_names', []),
                'categories': attrs.get('categories'),
                'status': 'found',
                'timestamp': datetime.utcnow().isoformat()
            }
            return jsonify(result)
        elif resp.status_code == 404:
            return jsonify({'query': query, 'status': 'not_found'}), 200
        else:
            return jsonify({'error': f'VirusTotal API error: {resp.status_code}'}), 500
    
    except Exception as e:
        logger.error(f"VirusTotal lookup error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/osint/abuseipdb', methods=['GET'])
@require_auth
def osint_abuseipdb():
    """AbuseIPDB IP reputation endpoint"""
    try:
        ip = request.args.get('ip', '').strip()
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        abuseipdb_key = os.getenv('ABUSEIPDB_KEY', '')
        if not abuseipdb_key:
            return jsonify({'error': 'AbuseIPDB key not configured'}), 500
        
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': abuseipdb_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            ip_data = data.get('data', {})
            
            result = {
                'ip': ip,
                'abuse_confidence_score': ip_data.get('abuseConfidenceScore'),
                'total_reports': ip_data.get('totalReports'),
                'is_whitelisted': ip_data.get('isWhitelisted'),
                'is_blacklisted': ip_data.get('isBlacklisted'),
                'usage_type': ip_data.get('usageType'),
                'isp': ip_data.get('isp'),
                'domain': ip_data.get('domain'),
                'country_code': ip_data.get('countryCode'),
                'reports': ip_data.get('reports', [])[:10],  # Last 10 reports
                'status': 'found',
                'timestamp': datetime.utcnow().isoformat()
            }
            return jsonify(result)
        else:
            return jsonify({'error': f'AbuseIPDB API error: {resp.status_code}'}), 500
    
    except Exception as e:
        logger.error(f"AbuseIPDB lookup error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    debug = os.getenv('DEBUG', 'False') == 'True'
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting OpenSpy RECON Scanner on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
