# OpenSpy RECON Scanner Backend

Advanced reconnaissance and vulnerability scanning API for OpenSpy.

## Features

- **IP Geolocation & Reputation** - Get location, ISP, ASN, and reputation data for any IP
- **DNS & WHOIS Lookup** - Query DNS records and domain registration info
- **SSL/TLS Certificate Scanning** - Analyze SSL certificates and detect expiration
- **Subdomain Enumeration** - Discover subdomains through DNS enumeration
- **Technology Detection** - Identify CMS, frameworks, analytics, and CDNs
- **Vulnerability Scanning** - Check for known CVEs and misconfigurations

## Installation

### Requirements
- Python 3.8+
- pip

### Setup

1. **Clone/create the backend directory:**
```bash
cd OpenSpy-Backend
```

2. **Create virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure environment:**
```bash
cp .env.example .env
```

5. **Generate security key:**
```bash
openssl rand -hex 32
```

Update `OPENSPY_KEY` in `.env` with the generated key.

## Running

### Development
```bash
python app.py
```

Server will start on `http://0.0.0.0:8000`

### Production
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## API Endpoints

All endpoints require `X-Scanner-Key` header with your `OPENSPY_KEY`.

### Health Check
```
GET /health
```

### IP Scan
```
POST /api/scan/ip
Content-Type: application/json
X-Scanner-Key: your-key

{
  "ip": "1.2.3.4"
}
```

### Domain Scan
```
POST /api/scan/domain
Content-Type: application/json
X-Scanner-Key: your-key

{
  "domain": "example.com"
}
```

### SSL Scan
```
POST /api/scan/ssl
Content-Type: application/json
X-Scanner-Key: your-key

{
  "host": "example.com",
  "port": 443
}
```

### Subdomain Enumeration
```
POST /api/scan/subdomains
Content-Type: application/json
X-Scanner-Key: your-key

{
  "domain": "example.com"
}
```

### Technology Detection
```
POST /api/scan/tech
Content-Type: application/json
X-Scanner-Key: your-key

{
  "url": "https://example.com"
}
```

### Vulnerability Scan
```
POST /api/scan/vulns
Content-Type: application/json
X-Scanner-Key: your-key

{
  "target": "example.com"
}
```

## Integration with OpenSpy Frontend

Update OpenSpy frontend `.env`:

```env
SCANNER_URL=http://localhost:8000
SCANNER_KEY=your-64-character-hex-key
```

Or if deployed:
```env
SCANNER_URL=https://your-backend-domain.com
SCANNER_KEY=your-64-character-hex-key
```

## Architecture

```
app.py                    # Main Flask application
├── scanners/
│   ├── __init__.py
│   ├── ip_scanner.py     # IP geolocation & reputation
│   ├── domain_scanner.py # DNS & WHOIS
│   ├── ssl_scanner.py    # SSL certificate analysis
│   ├── subdomain_scanner.py # Subdomain enumeration
│   ├── tech_scanner.py   # Technology detection
│   └── vuln_scanner.py   # Vulnerability checking
requirements.txt          # Python dependencies
.env.example             # Configuration template
README.md                # This file
```

## Free APIs Used

- **IP-API** - Geolocation (ip-api.com)
- **Cymru ASN** - ASN lookup (asn.cymru.com)
- **CIRCL CVE** - Vulnerability data (cve.circl.lu)
- **crt.sh** - SSL certificate search
- **Standard Libraries** - DNS, WHOIS

## Optional Paid APIs

For enhanced scanning, add API keys to `.env`:

- **AbuseIPDB** - Better IP reputation
- **Shodan** - Internet scan data
- **VirusTotal** - File and IP analysis

## Rate Limiting

- IP APIs: 45 requests/minute
- DNS queries: Limited by system resolver
- WHOIS: 1 request per domain per hour
- SSL: Limited by socket connections

## Security

- All API requests require authentication
- Constant-time key comparison to prevent timing attacks
- No logs of sensitive data
- CORS configured for frontend only

## Troubleshooting

### DNS Resolution Issues
```bash
# Check if dnspython is installed
pip install dnspython
```

### SSL Certificate Errors
```bash
# Install cryptography
pip install cryptography
```

### WHOIS Lookup Fails
```bash
# Some domains require specific WHOIS servers
pip install whois
```

## Performance Notes

- First request takes ~2-3 seconds (DNS warm-up)
- Subsequent requests are cached by system
- Batch requests recommended for multiple targets
- Consider rate limiting for production

## License

Part of OpenSpy project

## Support

For issues, check OpenSpy GitHub repository
