# VulnLite (Top UI) — Educational Web Security Analyzer

**What it is**
VulnLite is an educational, defensive web security analyzer (non-invasive).
It inspects headers, TLS certificate expiry, robots.txt, cookie flags and generates
a neat PDF report with charts.

**Why use for admissions**
- Full-stack project: Flask backend + polished frontend
- Shows cybersecurity knowledge (OWASP-style checks)
- Dockerized + demo-ready for interviews or SOP

## Quick start (local)
1. Clone or copy files into `vuln-lite-top/`
2. Using Python 3.10+:
   ```bash
   python -m venv venv
   source venv/bin/activate     # Linux/macOS
   venv\Scripts\activate        # Windows PowerShell
   pip install -r requirements.txt
   python app.py
   # open http://localhost:5000
