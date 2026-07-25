# OpenSpy RECON Scanner Backend — Deployment Guide

## Quick Start Options

### Option 1: Railway (Easiest - Recommended)
1. Go to https://railway.app
2. Sign in with GitHub
3. Create new project → Deploy from GitHub repo
4. Select `ethanpokemonking0902-cloud/OpenSpy-Backend`
5. Add environment variables:
   - `OPENSPY_KEY`: `9768678debc56cb587003b8bf83722cf4092b59e366ea36799ad97757f0f7a4f`
   - `DEBUG`: `False`
   - `PORT`: `8000`
6. Railway will auto-detect `Dockerfile` and deploy
7. Copy the public URL (e.g., `https://your-app.railway.app`)
8. Update frontend `.env`:
   ```
   SCANNER_URL=https://your-app.railway.app
   SCANNER_KEY=9768678debc56cb587003b8bf83722cf4092b59e366ea36799ad97757f0f7a4f
   ```

### Option 2: Render (Free Tier Available)
1. Go to https://render.com
2. Click "New +" → "Web Service"
3. Connect GitHub → select `OpenSpy-Backend` repo
4. Configure:
   - Name: `openspy-scanner`
   - Environment: `Python 3.11`
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn -w 4 -b 0.0.0.0:8000 app:app`
5. Add environment variables (same as above)
6. Deploy (free tier available)

### Option 3: Heroku (Paid)
1. Go to https://heroku.com
2. Create new app
3. Connect GitHub repo
4. Add environment variables
5. Deploy → wait for build to complete
6. Use the Heroku URL in frontend

### Option 4: DigitalOcean (VPS - Most Control)
1. Create Ubuntu 22.04 droplet ($5-12/month)
2. SSH into droplet
3. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install python3-pip python3-venv nginx
   ```
4. Clone repo:
   ```bash
   git clone https://github.com/ethanpokemonking0902-cloud/OpenSpy-Backend.git
   cd OpenSpy-Backend
   ```
5. Create virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
6. Create `.env` file with OPENSPY_KEY
7. Run with gunicorn:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:8000 app:app
   ```
8. Configure nginx as reverse proxy (point to 8000)
9. Set up SSL with Let's Encrypt
10. Update frontend with your VPS IP/domain

### Option 5: Docker on Any Server
1. SSH into your server
2. Install Docker
3. Pull and run:
   ```bash
   docker run -d \
     -e OPENSPY_KEY=9768678debc56cb587003b8bf83722cf4092b59e366ea36799ad97757f0f7a4f \
     -p 8000:8000 \
     --name openspy-scanner \
     ghcr.io/ethanpokemonking0902-cloud/openspy-backend:latest
   ```

## Recommended: Railway

**Why Railway?**
- ✅ Easiest setup (5 minutes)
- ✅ Free tier available ($5 credit/month)
- ✅ Auto-deploys from GitHub
- ✅ Custom domain support
- ✅ SSL included
- ✅ Environment variables UI
- ✅ Logs & monitoring built-in

**Steps:**
1. Push this repo to GitHub (✅ done)
2. Go to https://railway.app
3. Sign in with GitHub
4. Click "New Project" → "Deploy from GitHub"
5. Select `OpenSpy-Backend`
6. Add env vars (see above)
7. Wait for deploy (~2 min)
8. Get public URL from Railway dashboard
9. Update frontend `.env` with that URL

## After Deployment

Once backend is live:

1. **Update Frontend `.env`:**
   ```
   SCANNER_URL=https://your-backend-url.railway.app
   SCANNER_KEY=9768678debc56cb587003b8bf83722cf4092b59e366ea36799ad97757f0f7a4f
   ```

2. **Test Backend Health:**
   ```bash
   curl https://your-backend-url.railway.app/health
   ```
   Should return:
   ```json
   {
     "status": "ok",
     "version": "1.0.0",
     "service": "OpenSpy RECON Scanner"
   }
   ```

3. **Test Scanner Endpoint:**
   ```bash
   curl "https://your-backend-url.railway.app/scan/quick?target=8.8.8.8&key=9768678debc56cb587003b8bf83722cf4092b59e366ea36799ad97757f0f7a4f"
   ```

4. **Redeploy Frontend:**
   - Push updated `.env` to GitHub
   - Netlify auto-redeploys
   - RECON features now live!

## Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `OPENSPY_KEY` | 64-char hex | Authentication key (must match frontend SCANNER_KEY) |
| `DEBUG` | `False` | Disable debug mode in production |
| `HOST` | `0.0.0.0` | Listen on all interfaces |
| `PORT` | `8000` | Port to run on |

## Endpoints (POST with key param)

| Endpoint | Purpose | Example |
|----------|---------|---------|
| `/health` | Health check | `GET /health` |
| `/scan/quick` | IP geolocation | `GET /scan/quick?target=1.2.3.4&key=...` |
| `/scan/geoloc` | Geolocation data | `GET /scan/geoloc?target=example.com&key=...` |
| `/scan/whois` | Domain WHOIS | `GET /scan/whois?target=example.com&key=...` |
| `/scan/ssl` | SSL certificate | `GET /scan/ssl?target=example.com&key=...` |
| `/scan/headers` | HTTP headers | `GET /scan/headers?target=example.com&key=...` |
| `/scan/subdomains` | Subdomain enum | `GET /scan/subdomains?target=example.com&key=...` |
| `/scan/rdns` | Reverse DNS | `GET /scan/rdns?target=1.2.3.4&key=...` |
| `/scan/tech` | Tech detection | `GET /scan/tech?target=example.com&key=...` |
| `/scan/vuln` | Vulnerability scan | `GET /scan/vuln?target=example.com&key=...` |

## Troubleshooting

**"Scanner not configured" error:**
- Frontend SCANNER_KEY doesn't match backend OPENSPY_KEY
- Check both .env files match

**"Scanner unreachable" error:**
- Backend URL is wrong or down
- Check health endpoint: `curl {SCANNER_URL}/health`
- Verify CORS is enabled (it is by default)

**Rate limiting issues:**
- Backend has no built-in rate limits
- Frontend has 5 scans/minute per IP
- Add Redis rate limiting if needed

## Next Steps

1. **Choose deployment option** (Railway recommended)
2. **Deploy backend** (5-10 minutes)
3. **Update frontend .env** with backend URL
4. **Test RECON features** in OpenSpy UI
5. **Monitor** backend logs for errors

## Support

- Backend repo: https://github.com/ethanpokemonking0902-cloud/OpenSpy-Backend
- Frontend repo: https://github.com/ethanpokemonking0902-cloud/OpenSpy
- Issues: Create GitHub issue in either repo
