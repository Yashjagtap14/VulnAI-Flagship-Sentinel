from flask import Flask, request, render_template, jsonify, send_file
import requests
from urllib.parse import urlparse
import ssl, socket
from datetime import datetime
import re
import json
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# ---- Helpers (defensive, non-invasive) ----
def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^https?://', url):
        url = 'https://' + url
    return url

def fetch_head(url: str):
    try:
        headers = requests.head(url, allow_redirects=True, timeout=app.config['TIMEOUT'],
                                headers={'User-Agent': app.config['SAFE_USER_AGENT']}).headers
        return dict(headers)
    except Exception as e:
        return {'error': str(e)}

def safe_get(url: str):
    try:
        resp = requests.get(url, headers={'User-Agent': app.config['SAFE_USER_AGENT']}, timeout=app.config['TIMEOUT'])
        return resp
    except Exception as e:
        return None

def check_security_headers(headers: dict):
    essentials = {
        'Strict-Transport-Security': 'HSTS (enforce HTTPS)',
        'Content-Security-Policy': 'CSP (mitigate XSS)',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY or SAMEORIGIN',
        'Referrer-Policy': 'controls referrer header',
        'Permissions-Policy': 'controls browser features',
        'X-XSS-Protection': 'legacy XSS protection'
    }
    checks = []
    present_count = 0
    for h, desc in essentials.items():
        found = any(k.lower() == h.lower() for k in headers.keys()) if isinstance(headers, dict) else False
        checks.append({'header': h, 'present': bool(found), 'advice': f'Consider setting {h} ({desc})'})
        if found:
            present_count += 1
    coverage = round((present_count / len(essentials)) * 100)
    return checks, coverage

def check_tls_expiry(hostname: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            notAfter = cert.get('notAfter')
            if notAfter:
                try:
                    expire_dt = datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_dt - datetime.utcnow()).days
                    return {'expiry': notAfter, 'days_left': days_left}
                except Exception:
                    return {'expiry': notAfter}
            return {'error': 'no cert data'}
    except Exception as e:
        return {'error': str(e)}

def fetch_robots_txt(url: str):
    try:
        parsed = urlparse(url)
        robots = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        r = requests.get(robots, headers={'User-Agent': app.config['SAFE_USER_AGENT']}, timeout=app.config['TIMEOUT'])
        if r.status_code == 200:
            return {'found': True, 'content': r.text}
        return {'found': False, 'status_code': r.status_code}
    except Exception as e:
        return {'error': str(e)}

def analyze_cookies(resp):
    cookies = []
    if not resp:
        return cookies
    for c in resp.cookies:
        cookies.append({'name': c.name, 'secure': c.secure, 'httponly': bool(c._rest.get('HttpOnly', False))})
    return cookies

def simple_risk_score(coverage, tls_days):
    # coverage: header coverage % (0-100), tls_days: int or None
    score = 100
    score -= (100 - coverage) * 0.4  # headers matter
    if isinstance(tls_days, int):
        if tls_days < 30:
            score -= 30
        elif tls_days < 90:
            score -= 10
    # clamp
    if score < 10: score = 10
    return int(score)

# ---- Routes ----
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'url is required'}), 400
    url = normalize_url(url)
    headers = fetch_head(url)
    resp = safe_get(url)
    sec_checks, coverage = check_security_headers(headers if isinstance(headers, dict) else {})
    robots = fetch_robots_txt(url)
    parsed = urlparse(url)
    tls = check_tls_expiry(parsed.netloc)
    cookies = analyze_cookies(resp)
    tls_days = tls.get('days_left') if isinstance(tls, dict) and 'days_left' in tls else None
    risk = simple_risk_score(coverage, tls_days)
    report = {
        'target': url,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'headers': headers,
        'security_checks': sec_checks,
        'header_coverage_percent': coverage,
        'robots': robots,
        'tls': tls,
        'cookies': cookies,
        'risk_score': risk
    }
    return jsonify(report)

@app.route('/sample')
def sample():
    return send_file('sample_report.json', as_attachment=False)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
