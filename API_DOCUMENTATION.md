# OpenSpy RECON Scanner - API Documentation

## Base URL
```
http://localhost:8000
```

## Authentication
All endpoints require an API key passed as either:
- Query parameter: `?key=YOUR_API_KEY`
- Header: `X-Scanner-Key: YOUR_API_KEY`

The key is configured in `.env` as `OPENSPY_KEY`

---

## 📍 IP & LOCATION SCANNING

### Quick IP Scan
```
GET /scan/quick?target=IP_ADDRESS&key=KEY
```
Quick IP reputation, geolocation, fraud score, AbuseIPDB data

### Geolocation Lookup
```
GET /scan/geoloc?target=IP_ADDRESS&key=KEY
```
Detailed geolocation, ISP, timezone info

---

## 🌐 DOMAIN & NETWORK SCANNING

### WHOIS Lookup
```
GET /scan/whois?target=DOMAIN&key=KEY
```
Domain registration info, registrar, nameservers

### SSL/TLS Certificates
```
GET /scan/ssl?target=DOMAIN&key=KEY
```
Certificate chain, expiry, threat analysis, security headers

### DNS Lookup
```
GET /api/osint/dns?domain=DOMAIN&key=KEY
```
DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV)

### Subdomain Enumeration
```
GET /scan/subdomains?target=DOMAIN&key=KEY
```
Discover subdomains, check reputation

### Reverse DNS
```
GET /scan/rdns?target=IP_ADDRESS&key=KEY
```
Reverse DNS lookups

---

## 🔧 SERVICE & VULNERABILITY SCANNING

### Technology Detection
```
GET /scan/tech?target=DOMAIN&key=KEY
```
Identify CMS, web frameworks, server software, security headers

### Vulnerability Scanning
```
GET /scan/vuln?target=IP_OR_DOMAIN&key=KEY
```
Check for known CVEs, misconfigurations

### CVE Details
```
GET /api/osint/cve?cve=CVE-YYYY-XXXX&key=KEY
```
Detailed CVE information, CVSS score, severity

---

## ☎️ PHONE RECONNAISSANCE

### Phone Number Lookup
```
GET /scan/phone?target=PHONE_NUMBER&key=KEY
```
Carrier info, geolocation, line type (mobile/landline)

### Phone Ping
```
GET /scan/phone-ping?target=PHONE_NUMBER&key=KEY
```
Check if phone number is active/reachable

---

## 👤 PEOPLE & NAME OSINT

### Comprehensive People Search
```
GET /scan/people?target=NAME_OR_EMAIL&type=auto&key=KEY
```
Full people reconnaissance - breaches, social media, emails, GitHub

**Query Types:**
- `auto` - Auto-detect (default)
- `name` - Full name search
- `email` - Email lookup
- `username` - Username search
- `phone` - Phone number

### Name-Based Lookup
```
GET /api/osint/name?name=FIRST_LAST&key=KEY
```
OSINT reconnaissance on full name

### Email Intelligence
```
GET /api/osint/email?email=EMAIL@DOMAIN&key=KEY
```
Email validation, breach checking, associated accounts, social media

### Data Breach Checking
```
GET /api/osint/breaches?query=EMAIL_OR_USERNAME&key=KEY
```
Check if email/username appears in known data breaches

### Username Lookup
```
GET /api/osint/username?username=USERNAME&key=KEY
```
Find accounts and check platform availability

### Associated Accounts
```
GET /api/osint/associated?email=EMAIL@DOMAIN&key=KEY
```
Find all accounts associated with email address

### Username Availability Check
```
GET /api/osint/availability?username=USERNAME&key=KEY
```
Check if username is available across platforms

---

## 🌍 THREAT INTELLIGENCE & INFRASTRUCTURE

### Shodan IoT Lookup
```
GET /api/osint/shodan?ip=IP_ADDRESS&key=KEY
```
Internet-connected devices, open ports, services

### Threat Intelligence
```
GET /api/osint/threats?query=DOMAIN_OR_IP&key=KEY
```
General threat intelligence on target (uses VirusTotal + AbuseIPDB)

### VirusTotal Threat Intelligence
```
GET /api/osint/virustotal?query=DOMAIN_OR_IP&key=KEY
```
VirusTotal domain/IP reputation, threat names, analysis stats

**Response:**
```json
{
  "query": "example.com",
  "last_analysis_stats": {
    "malicious": 0,
    "suspicious": 0,
    "undetected": 65,
    "harmless": 10
  },
  "reputation": -5,
  "threat_names": [],
  "status": "found"
}
```

### AbuseIPDB IP Reputation
```
GET /api/osint/abuseipdb?ip=IP_ADDRESS&key=KEY
```
AbuseIPDB IP abuse reports, confidence score, blacklist status

**Response:**
```json
{
  "ip": "192.168.1.1",
  "abuse_confidence_score": 45,
  "total_reports": 12,
  "is_whitelisted": false,
  "is_blacklisted": true,
  "usage_type": "Commercial",
  "isp": "ISP Name",
  "reports": [...]
}
```

### BGP Information
```
GET /api/osint/bgp?query=ASN_OR_IP&key=KEY
```
BGP routing info, ASN details, prefix information

### MAC Address Vendor
```
GET /api/osint/mac?mac=MAC_ADDRESS&key=KEY
```
MAC address vendor/manufacturer lookup

### GitHub User Reconnaissance
```
GET /api/osint/github?user=USERNAME&key=KEY
```
GitHub profile info, public repos, followers, email

---

## 🏠 NETWORK SWEEPING

### Network Sweep
```
GET /api/osint/sweep?ip=IP_ADDRESS&cidr=24&key=KEY
```
Prepare network sweep (enumerate IP range using Shodan)

---

## Health Check

### Server Status
```
GET /health
```
No authentication required - check if server is running

---

## Error Handling

All endpoints return standard JSON error responses:

```json
{
  "error": "Error description",
  "status": "error"
}
```

**Common HTTP Status Codes:**
- `200 OK` - Success
- `400 Bad Request` - Missing required parameter
- `401 Unauthorized` - Invalid or missing API key
- `404 Not Found` - Endpoint not found
- `500 Internal Server Error` - Server error

---

## API Keys Configuration (.env)

```env
# Generated internally (don't share)
OPENSPY_KEY=your_secure_key_here

# External APIs - Sign up for free
ABUSEIPDB_KEY=from_https://www.abuseipdb.com
VIRUSTOTAL_KEY=from_https://www.virustotal.com
SHODAN_KEY=from_https://www.shodan.io
IPQUALITYSCORE_KEY=from_https://www.ipqualityscore.com
NUMLOOKUP_KEY=from_https://www.numlookup.com
```

---

## All Available Endpoints (31 total)

| Endpoint | Purpose | Auth Required |
|----------|---------|---|
| `/health` | Health check | No |
| `/scan/quick` | Quick IP scan | Yes |
| `/scan/geoloc` | Geolocation | Yes |
| `/scan/whois` | Domain WHOIS | Yes |
| `/scan/ssl` | SSL/TLS scan | Yes |
| `/scan/headers` | HTTP headers | Yes |
| `/scan/subdomains` | Subdomain enum | Yes |
| `/scan/rdns` | Reverse DNS | Yes |
| `/scan/tech` | Tech detection | Yes |
| `/scan/vuln` | Vulnerability scan | Yes |
| `/scan/phone` | Phone lookup | Yes |
| `/scan/phone-ping` | Phone ping | Yes |
| `/scan/people` | People search | Yes |
| `/api/osint/dns` | DNS lookup | Yes |
| `/api/osint/threats` | Threat intel | Yes |
| `/api/osint/shodan` | Shodan lookup | Yes |
| `/api/osint/virustotal` | VirusTotal | Yes |
| `/api/osint/abuseipdb` | AbuseIPDB | Yes |
| `/api/osint/bgp` | BGP info | Yes |
| `/api/osint/mac` | MAC vendor | Yes |
| `/api/osint/github` | GitHub user | Yes |
| `/api/osint/leaks` | Breach check | Yes |
| `/api/osint/cve` | CVE details | Yes |
| `/api/osint/sweep` | Network sweep | Yes |
| `/api/osint/name` | Name lookup | Yes |
| `/api/osint/email` | Email intel | Yes |
| `/api/osint/breaches` | Breach check | Yes |
| `/api/osint/username` | Username lookup | Yes |
| `/api/osint/associated` | Associated accounts | Yes |
| `/api/osint/availability` | Username availability | Yes |
| `/api/osint/certs` | Certificate lookup | Yes |

---

## Security Notes

1. **Never commit API keys** - Use `.env` file, add to `.gitignore`
2. **Rate limit clients** - Implement on frontend
3. **HTTPS in production** - Use SSL/TLS certificates
4. **CORS configured** - Allowed for Netlify frontend
5. **Input validation** - All inputs sanitized
6. **Timeout protection** - 10-second timeout on all API calls
7. **Constant-time comparison** - Used for API key validation (prevents timing attacks)

---

## Rate Limits by API

| Service | Limit | Tier |
|---------|-------|------|
| NumLookup | 100 req/month | Free |
| IPQualityScore | Varies | Free (limited) |
| Shodan | Unlimited | Free (InternetDB) |
| VirusTotal | 4 req/min | Free |
| AbuseIPDB | 1000 req/day | Free |
| GitHub | 60 req/hour | Unauthenticated |
| HaveIBeenPwned | Rate limited | Free |

---

## Example Usage

### Comprehensive IP Reconnaissance
```bash
# Quick scan
curl "http://localhost:8000/scan/quick?target=1.1.1.1&key=YOUR_KEY"

# VirusTotal check
curl "http://localhost:8000/api/osint/virustotal?query=1.1.1.1&key=YOUR_KEY"

# AbuseIPDB check
curl "http://localhost:8000/api/osint/abuseipdb?ip=1.1.1.1&key=YOUR_KEY"
```

### Domain Intelligence
```bash
# Full domain scan
curl "http://localhost:8000/scan/ssl?target=example.com&key=YOUR_KEY"

# DNS lookup
curl "http://localhost:8000/api/osint/dns?domain=example.com&key=YOUR_KEY"

# VirusTotal domain rep
curl "http://localhost:8000/api/osint/virustotal?query=example.com&key=YOUR_KEY"
```

### People Search
```bash
# Comprehensive people search
curl "http://localhost:8000/scan/people?target=john@example.com&key=YOUR_KEY"

# Breach check
curl "http://localhost:8000/api/osint/breaches?query=john@example.com&key=YOUR_KEY"

# Username lookup
curl "http://localhost:8000/api/osint/username?username=johndoe&key=YOUR_KEY"
```

---

*Last Updated: 2024*
*OpenSpy RECON Scanner Backend v1.0*
*31 Endpoints | 6 External APIs | Full OSINT Capabilities*
