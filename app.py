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
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════

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
