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
CORS(app, resources={r"/api/*": {"origins": "*"}})

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
