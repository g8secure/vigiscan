import sqlite3
from flask import Flask, render_template, request, redirect, session, jsonify, flash, send_file, make_response, url_for
from functools import wraps
from datetime import datetime, timedelta
from fpdf import FPDF
import threading, time, uuid
from zapv2 import ZAPv2
import pyotp
import qrcode
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import pandas as pd
import socket
import os
import json
from threading import Lock
import nmap
import re   # ✅ required for sanitization
import requests   # ✅ added for CVE lookup

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
# Use env var in production; fallback only for local dev
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')
app.permanent_session_lifetime = timedelta(minutes=10)

# ================= JINJA2 TEMPLATE GLOBALS =================
@app.template_global('statusBadge')
def status_badge(status):
    """Render a status badge span for a given status string."""
    s = (status or 'Open').lower().replace(' ', '-')
    return f'<span class="status-badge status-{s}">{status or "Open"}</span>'

@app.template_global('riskBadge')
def risk_badge(risk):
    """Render a risk badge span for a given risk level string."""
    r = (risk or 'Info').lower()
    return f'<span class="risk-badge risk-{r}">{risk or "Info"}</span>'

# Register a 'match' test so templates can use selectattr('x', 'match', 'regex')
@app.template_test('match')
def regex_match(value, pattern):
    """Jinja test: check if a string matches a regex pattern."""
    if value is None:
        return False
    return re.match(pattern, str(value)) is not None

# ================= DATABASE PATH =================
# On Render with a persistent disk mounted at /data, store the DB there.
# Locally, falls back to the project directory.
DB_PATH = os.path.join('/data', 'users.db') if os.path.isdir('/data') else os.path.join(os.path.dirname(__file__), 'users.db')

# ================= EMAIL CONFIGURATION =================
# To enable email alerts, replace placeholders with your real SMTP credentials.
_MAIL_USER = os.environ.get('VIGISCAN_MAIL_USER', 'your-email@gmail.com')
_MAIL_PASS = os.environ.get('VIGISCAN_MAIL_PASS', 'your-app-password')
_MAIL_CONFIGURED = (_MAIL_USER != 'your-email@gmail.com' and _MAIL_PASS != 'your-app-password')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = _MAIL_USER
app.config['MAIL_PASSWORD'] = _MAIL_PASS
app.config['MAIL_DEFAULT_SENDER'] = _MAIL_USER

mail = Mail(app)

SCAN_LOCK = Lock()
SCAN_JOBS = {}

# ================= KNOWLEDGE BASE =================
KNOWLEDGE_BASE = {
    "web-vulns": {
        "name": "Web Vulnerabilities",
        "topics": {
            "xss": {
                "name": "Cross-Site Scripting (XSS)",
                "description": "Occurs when a web application allows user input to run as script in the browser",
                "how_it_happens": "Input fields are not properly filtered or encoded",
                "impact": "Attackers can steal session cookies or redirect users",
                "severity": "High",
                "fix": "Validate input, encode output, use security headers"
            },
            "sql-injection": {
                "name": "SQL Injection",
                "description": "Attackers inject malicious SQL queries into input fields",
                "how_it_happens": "Application directly uses user input in database queries",
                "impact": "Full database compromise",
                "severity": "Critical",
                "fix": "Use parameterized queries and ORM frameworks"
            },
            "misconfiguration": {
                "name": "Security Misconfiguration",
                "description": "System is not securely set up",
                "how_it_happens": "Default settings not changed, insecure server configs",
                "impact": "Data exposure or unauthorized access",
                "severity": "Medium",
                "fix": "Disable default settings, secure server configs"
            }
        }
    },
    "network-ports": {
        "name": "Network & Port Risks",
        "topics": {
            "ftp": {
                "name": "Port 21 (FTP)",
                "description": "File transfer protocol",
                "risk": "Sends data in plain text",
                "risk_level": "High",
                "recommendation": "Use SFTP instead"
            },
            "http": {
                "name": "Port 80 (HTTP)",
                "description": "Web traffic without encryption",
                "risk": "Data can be intercepted",
                "risk_level": "Medium",
                "recommendation": "Use HTTPS"
            },
            "ssh": {
                "name": "Port 22 (SSH)",
                "description": "Secure remote login",
                "risk": "Brute-force attacks",
                "risk_level": "Medium",
                "recommendation": "Use key authentication"
            }
        }
    },
    "severity-guide": {
        "name": "Severity Guide",
        "topics": {
            "critical": {
                "name": "Critical",
                "meaning": "Immediate action required",
                "action": "Fix immediately, high priority"
            },
            "high": {
                "name": "High",
                "meaning": "Fix urgently",
                "action": "Address within days"
            },
            "medium": {
                "name": "Medium",
                "meaning": "Fix soon",
                "action": "Plan remediation"
            },
            "low": {
                "name": "Low",
                "meaning": "Monitor",
                "action": "Low priority, monitor for changes"
            }
        }
    },
    "fix-guide": {
        "name": "Fix & Remediation Guide",
        "topics": {
            "sql-fix": {
                "name": "SQL Injection Fix",
                "recommended_fix": "Use prepared statements",
                "tools": "Parameterized queries, ORM frameworks",
                "steps": "Validate inputs, avoid dynamic queries"
            },
            "xss-fix": {
                "name": "XSS Fix",
                "recommended_fix": "Encode output, validate input",
                "tools": "Security libraries, CSP headers",
                "steps": "Sanitize user input, use safe encoding"
            }
        }
    },
    "about": {
        "name": "About VigiScan",
        "topics": {
            "what": {
                "name": "What is VigiScan?",
                "description": "An enterprise-grade Vulnerability Management, Detection and Response (VMDR) platform."
            },
            "how": {
                "name": "How it works",
                "description": "Uses Nmap for network scanning and OWASP ZAP for web vulnerabilities."
            },
            "why": {
                "name": "Why it matters",
                "description": "Helps users identify and fix security issues easily."
            }
        }
    }
}

# ================= OPEN PORTS & SERVICES INTERPRETATION =================
# Risk is assigned to an open port ONLY when supported by the detected
# service/version, configuration, or vulnerability intelligence. An open
# port is attack surface, not a vulnerability. If the service cannot be
# confidently identified, "Unknown / Requires Assessment" is displayed.
PORT_KNOWLEDGE_BASE = {
    21:    {"service": "FTP", "risk": "High", "recommendation": "Disable FTP or replace with SFTP/FTPS; restrict to trusted networks"},
    22:    {"service": "SSH", "risk": "Medium", "recommendation": "Restrict to trusted networks; enforce key-based authentication"},
    23:    {"service": "Telnet", "risk": "High", "recommendation": "Disable Telnet; use encrypted SSH instead"},
    25:    {"service": "SMTP", "risk": "Medium", "recommendation": "Restrict to authorised mail relays; enable TLS and authentication"},
    53:    {"service": "DNS", "risk": "Medium", "recommendation": "Restrict recursive queries; keep DNS software patched"},
    80:    {"service": "HTTP", "risk": "Medium", "recommendation": "Redirect to HTTPS; restrict exposure to trusted networks"},
    110:   {"service": "POP3", "risk": "Medium", "recommendation": "Replace with POP3S/IMAPS; restrict to trusted networks"},
    111:   {"service": "RPC Bind", "risk": "Medium", "recommendation": "Restrict access; disable if not required"},
    135:   {"service": "Microsoft Windows RPC", "risk": "Medium", "recommendation": "Restrict exposure to trusted networks"},
    139:   {"service": "Microsoft Windows NetBIOS", "risk": "Medium", "recommendation": "Disable if not required"},
    143:   {"service": "IMAP", "risk": "Medium", "recommendation": "Replace with IMAPS; restrict to trusted networks"},
    389:   {"service": "LDAP", "risk": "Medium", "recommendation": "Use LDAPS; restrict to trusted networks"},
    443:   {"service": "HTTPS", "risk": "Low", "recommendation": "Verify TLS configuration and certificate validity"},
    445:   {"service": "Microsoft SMB", "risk": "High", "recommendation": "Verify SMB configuration and patch level",
           "note": "SMB has a history of widely exploited vulnerabilities (e.g., MS17-010 / EternalBlue). Confirm the host is fully patched."},
    512:   {"service": "rexec", "risk": "High", "recommendation": "Disable rexec; use SSH instead"},
    513:   {"service": "rlogin", "risk": "High", "recommendation": "Disable rlogin; use SSH instead"},
    514:   {"service": "rsh", "risk": "High", "recommendation": "Disable rsh; use SSH instead"},
    873:   {"service": "rsync", "risk": "Low", "recommendation": "Restrict to trusted networks; enable authentication"},
    902:   {"service": "VMware Authentication Daemon", "risk": "Medium", "recommendation": "Restrict access to management networks"},
    912:   {"service": "VMware Authentication Daemon", "risk": "Medium", "recommendation": "Verify VMware service requirement"},
    993:   {"service": "IMAPS", "risk": "Low", "recommendation": "Verify TLS configuration"},
    995:   {"service": "POP3S", "risk": "Low", "recommendation": "Verify TLS configuration"},
    1433:  {"service": "MSSQL", "risk": "High", "recommendation": "Restrict access; enforce strong authentication"},
    1521:  {"service": "Oracle Database", "risk": "High", "recommendation": "Restrict access; apply latest security patches"},
    2049:  {"service": "NFS", "risk": "Medium", "recommendation": "Restrict exports to trusted hosts"},
    2375:  {"service": "Docker API", "risk": "High", "recommendation": "Do not expose the Docker socket publicly; require TLS"},
    2376:  {"service": "Docker API (TLS)", "risk": "Low", "recommendation": "Restrict to trusted management hosts"},
    3306:  {"service": "MySQL", "risk": "High", "recommendation": "Restrict access; enforce strong authentication"},
    3389:  {"service": "Remote Desktop Protocol (RDP)", "risk": "High", "recommendation": "Restrict RDP; require VPN and MFA"},
    5432:  {"service": "PostgreSQL", "risk": "High", "recommendation": "Restrict access; enforce strong authentication"},
    5601:  {"service": "Kibana", "risk": "Medium", "recommendation": "Restrict access; enable authentication"},
    5900:  {"service": "VNC", "risk": "High", "recommendation": "Disable VNC or tunnel over VPN; enforce strong passwords"},
    5984:  {"service": "CouchDB", "risk": "Medium", "recommendation": "Restrict access; enforce authentication"},
    6379:  {"service": "Redis", "risk": "High", "recommendation": "Restrict access; enable authentication"},
    8080:  {"service": "HTTP Alt", "risk": "Medium", "recommendation": "Verify software and patch level; restrict exposure"},
    8443:  {"service": "HTTPS Alt", "risk": "Low", "recommendation": "Verify TLS configuration and service identity"},
    9200:  {"service": "Elasticsearch", "risk": "High", "recommendation": "Restrict access; enable authentication"},
    11211: {"service": "Memcached", "risk": "High", "recommendation": "Restrict access; disable UDP; enable authentication"},
    27017: {"service": "MongoDB", "risk": "High", "recommendation": "Restrict access; enable authentication"},
    5000:  {"service": "Werkzeug HTTP Server", "risk": "Medium", "recommendation": "Avoid exposing development servers publicly"},
    16992: {"service": "Intel AMT", "risk": "Medium", "recommendation": "Restrict management interface"},
}

# Product/service text profiles used when the detected product is confidently
# identified from the Nmap alert text (takes precedence over the port map).
SERVICE_RISK_PROFILES = [
    {"keywords": ["werkzeug"], "service": "Werkzeug HTTP Server", "risk": "Medium", "recommendation": "Avoid exposing development servers publicly"},
    {"keywords": ["vmware"], "service": "VMware Authentication Daemon", "risk": "Medium", "recommendation": "Restrict access to management networks"},
    {"keywords": ["intel", "amt", "active management"], "service": "Intel AMT", "risk": "Medium", "recommendation": "Restrict management interface"},
    {"keywords": ["microsoft-rpc", "msrpc", "microsoft windows rpc"], "service": "Microsoft Windows RPC", "risk": "Medium", "recommendation": "Restrict exposure to trusted networks"},
    {"keywords": ["netbios", "netbios-ssn"], "service": "Microsoft Windows NetBIOS", "risk": "Medium", "recommendation": "Disable if not required"},
    {"keywords": ["microsoft-ds", "smb", "samba"], "service": "Microsoft SMB", "risk": "High", "recommendation": "Verify SMB configuration and patch level",
     "note": "SMB has a history of widely exploited vulnerabilities (e.g., MS17-010 / EternalBlue). Confirm the host is fully patched."},
    {"keywords": ["rdp", "remote desktop"], "service": "Remote Desktop Protocol (RDP)", "risk": "High", "recommendation": "Restrict RDP; require VPN and MFA"},
    {"keywords": ["ssh", "openssh"], "service": "SSH", "risk": "Medium", "recommendation": "Restrict to trusted networks; enforce key-based authentication"},
    {"keywords": ["ftp"], "service": "FTP", "risk": "High", "recommendation": "Disable FTP or replace with SFTP/FTPS; restrict to trusted networks"},
    {"keywords": ["telnet"], "service": "Telnet", "risk": "High", "recommendation": "Disable Telnet; use encrypted SSH instead"},
]

def lookup_port_profile(alert_text, port_num):
    """Return the risk profile for a port, preferring the detected product text.

    When the detected product text matches a known service profile AND the port
    number has its own knowledge-base entry with the same service label, the
    port-specific entry takes precedence so per-port recommendations (e.g. the
    VMware daemon on 902 vs 912) are preserved.
    """
    text = (alert_text or "").lower()
    port_profile = PORT_KNOWLEDGE_BASE.get(port_num)
    for entry in SERVICE_RISK_PROFILES:
        if any(kw in text for kw in entry["keywords"]):
            # If the port has a specific, matching profile, honour its
            # recommendation/note while keeping the confidently-identified
            # service label from the matched text profile.
            if port_profile and port_profile.get("service", "").lower() == entry["service"].lower():
                merged = dict(entry)
                merged["service"] = port_profile["service"]
                merged["recommendation"] = port_profile["recommendation"]
                if port_profile.get("note"):
                    merged["note"] = port_profile["note"]
                return merged
            return entry
    return port_profile

def parse_port_entries(alerts):
    """Parse existing Nmap port alerts into a structured port table.

    Only data already produced by the scanner is used. No versions or
    vulnerabilities are invented. Unknown services are reported as
    'Unknown / Requires Assessment'.
    """
    ports = []
    for a in alerts or []:
        path = a.get("path") or ""
        m = re.match(r'^Port\s+(\d+)/(tcp|udp)$', path, re.IGNORECASE)
        if not m:
            continue

        port_num = int(m.group(1))
        protocol = m.group(2).upper()
        alert_text = a.get("alert") or ""
        cves = a.get("cves") or []

        # Existing alert format: "{product} {version} on port X"
        #                     or: "Service on port X"
        suffix = f" on port {port_num}"
        product_text = alert_text[:-len(suffix)].strip() if alert_text.endswith(suffix) else alert_text.strip()
        if not product_text or product_text.lower() in ("service", "unknown"):
            product_text = None

        # Service label: prefer confidently detected product profile, then the
        # well-known port profile, then the raw product text, otherwise Unknown.
        profile = lookup_port_profile(alert_text, port_num)
        base_profile = PORT_KNOWLEDGE_BASE.get(port_num)

        if profile:
            service_label = profile["service"]
        elif base_profile:
            service_label = base_profile["service"]
        elif product_text:
            service_label = product_text
        else:
            service_label = "Unknown"

        if profile:
            risk = profile["risk"]
            recommendation = profile["recommendation"]
            note = profile.get("note")
        elif cves:
            # Vulnerability intelligence supports a risk assignment.
            risk = "Medium"
            recommendation = a.get("solution") or "Verify software version and apply required patches"
            note = f"{len(cves)} known CVE reference(s) found for this service."
        else:
            risk = "Unknown / Requires Assessment"
            recommendation = a.get("solution") or "Perform a manual assessment of this service before exposure decisions."
            note = None

        entry = {
            "port": port_num,
            "protocol": protocol,
            "service": service_label,
            "risk": risk,
            "recommendation": recommendation,
            "raw": {
                "path": path,
                "alert": alert_text,
                "description": a.get("description", ""),
                "solution": a.get("solution", ""),
                "cves": cves
            }
        }
        if note:
            entry["note"] = note
        ports.append(entry)
    return ports

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        otp_secret TEXT,
        email TEXT,
        settings TEXT DEFAULT '{}',
        is_admin INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        user TEXT,
        target TEXT,
        date TEXT,
        alerts TEXT,
        profile TEXT DEFAULT 'deep',
        status TEXT DEFAULT 'Completed',
        current_phase TEXT DEFAULT 'Done',
        fixed TEXT DEFAULT '[]'
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        action TEXT,
        details TEXT,
        date TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        scan_id TEXT,
        message TEXT,
        traceback TEXT,
        date TEXT
    )''')

    # ✅ Asset Inventory Table
    c.execute('''CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        ip TEXT,
        domain TEXT,
        owner TEXT,
        environment TEXT,
        criticality TEXT DEFAULT 'Medium',
        is_internet_facing INTEGER DEFAULT 0,
        asset_group TEXT
    )''')

    # ✅ Vulnerability Lifecycle Table
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        asset_id INTEGER,
        name TEXT,
        severity TEXT,
        risk_score INTEGER,
        status TEXT DEFAULT 'Open',
        cvss_score REAL,
        exposure TEXT,
        compliance_tags TEXT DEFAULT '[]',
        date_found TEXT,
        last_seen TEXT,
        FOREIGN KEY(asset_id) REFERENCES assets(id)
    )''')
    
    try:
        c.execute("ALTER TABLE vulnerabilities ADD COLUMN compliance_tags TEXT DEFAULT '[]'")
    except: pass

    # ✅ Notifications Table
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        type TEXT,
        message TEXT,
        is_read INTEGER DEFAULT 0,
        date TEXT
    )''')

    # ✅ Knowledge Base Table
    c.execute('''CREATE TABLE IF NOT EXISTS knowledge_base (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        category TEXT,
        content TEXT,
        tags TEXT DEFAULT '[]',
        author TEXT,
        created_date TEXT,
        updated_date TEXT,
        is_public INTEGER DEFAULT 1,
        views INTEGER DEFAULT 0
    )''')

    # Migrations for existing columns
    try:
        c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except: pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN settings TEXT DEFAULT '{}'")
    except: pass

    conn.commit()
    conn.close()

def log_error(user, scan_id, message, traceback=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO error_logs (user, scan_id, message, traceback, date) VALUES (?,?,?,?,?)",
                  (user, scan_id, str(message), str(traceback), datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
    except:
        pass

def log_activity(user, action, details=""):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (user, action, details, date) VALUES (?,?,?,?)",
                  (user, action, str(details), datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        conn.close()
    except:
        pass

init_db()

# ================= CVE LOOKUP =================
def lookup_cves(product, version):
    try:
        if not product or not version:
            return []
        query = f"{product} {version}"
        url = f"https://vulners.com/api/v3/search/lucene/?query={query}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        cves = []
        for item in data.get("data", {}).get("search", []):
            cves.append({
                "id": item.get("id"),
                "title": item.get("title"),
                "cvss": item.get("cvss", "N/A"),
                "href": item.get("href")
            })
        return cves
    except Exception:
        return []

# ================= DECORATORS =================
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            return redirect('/login')
        if not session.get("is_admin", False):
            return "Access denied: Admins only", 403
        return f(*args, **kwargs)
    return wrap

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            return redirect('/login')
        last_active = session.get("last_active")
        if last_active:
            try:
                last_active = datetime.fromisoformat(last_active)
                if (datetime.utcnow() - last_active).total_seconds() > 600:
                    session.clear()
                    return redirect('/login')
            except:
                pass
        session["last_active"] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return wrap

# ================= AUTH =================
@app.route('/', methods=['GET','POST'])
@app.route('/login', methods=['GET','POST'])
def login():
    if 'user' in session:
        return redirect('/dashboard')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, username, password, otp_secret, email, is_admin FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['temp_user'] = username
            session['2fa_secret'] = user[3]
            session['email'] = user[4]
            session['is_admin'] = bool(user[5])
            return redirect('/login_2fa')
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form.get('email', '').strip()
        password = generate_password_hash(request.form['password'])
        otp_secret = pyotp.random_base32()

        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash("Invalid username format", "danger")
            return redirect('/register')

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        try:
            c.execute("SELECT COUNT(*) FROM users")
            is_first_user = c.fetchone()[0] == 0

            c.execute(
                "INSERT INTO users (username,email,password,otp_secret,is_admin) VALUES (?,?,?,?,?)",
                (username, email, password, otp_secret, 1 if is_first_user else 0)
            )
            conn.commit()
            return redirect('/login')

        except:
            flash("Username exists", "danger")

        finally:
            conn.close()

    return render_template("register.html")

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    try:
        if request.method == 'POST':
            email = request.form.get('email', '').strip()
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE email=? AND email != ''", (email,))
            user = c.fetchone()
            conn.close()

            if user:
                # Generate secure token
                serializer = URLSafeTimedSerializer(app.secret_key)
                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)
                
                # Send Email
                if _MAIL_CONFIGURED:
                    try:
                        msg = Message("Password Reset Request - VigiScan", 
                                      sender=_MAIL_USER, 
                                      recipients=[email])
                        msg.body = f"Hello {user[0]},\n\nTo reset your password, click the following link:\n{reset_url}\n\nIf you did not make this request, please ignore this email.\nThis link will expire in 1 hour."
                        mail.send(msg)
                        flash("A password reset link has been sent to your email address.", "success")
                    except Exception as e:
                        flash(f"Failed to send email. Please check server configuration. Error: {str(e)}", "danger")
                else:
                    # Fallback for when email is not configured on the server
                    flash(f"Email is not configured on this server. Here is your manual reset link: {reset_url}", "success")
            else:
                # Security standard: Don't reveal if email exists or not
                flash("If that email is registered, a password reset link has been sent.", "success")

        return render_template("forgot_password.html")
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        return f"Forgot Password Error: {str(e)}<br><pre>{error_trace}</pre>", 500

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            hashed_pw = generate_password_hash(password)
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE email=?", (hashed_pw, email))
            conn.commit()
            conn.close()
            flash("Your password has been securely updated! You may now log in.", "success")
            return redirect(url_for('login'))

    return render_template("reset_password.html")


@app.route('/login_2fa', methods=['GET','POST'])
def login_2fa():
    if 'temp_user' not in session:
        return redirect('/login')

    qr_uri = pyotp.TOTP(session['2fa_secret']).provisioning_uri(
        name=session['temp_user'],
        issuer_name="VigiScan"
    )

    qr_img = qrcode.make(qr_uri)
    buf = BytesIO()
    qr_img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    if request.method == 'POST':
        token = request.form['token']
        totp = pyotp.TOTP(session['2fa_secret'])

        if totp.verify(token):
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=30)
            session['user'] = session['temp_user']
            session.pop('temp_user', None)
            session.pop('2fa_secret', None)
            log_activity(session['user'], "LOGIN", "User logged in via 2FA")
            return redirect('/dashboard')
        else:
            flash("Invalid authentication code. Please try again.", "danger")

    return render_template("login_2fa.html", qr_b64=qr_b64)


@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT settings FROM users WHERE username=?", (session.get("user"),))
    row = c.fetchone()
    conn.close()

    user_lang = "en"
    if row and row[0]:
        try:
            settings_data = json.loads(row[0])
            user_lang = settings_data.get("language", "en")
        except:
            pass

    return render_template("dashboard.html", user=session.get("user", "Guest"), user_lang=user_lang, active_page="dashboard")

@app.route('/api/save_language', methods=['POST'])
@login_required
def save_language():
    data = request.get_json(silent=True) or {}
    lang = data.get("language", "en")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT settings FROM users WHERE username=?", (session.get("user"),))
    row = c.fetchone()
    
    settings_data = {}
    if row and row[0]:
        try:
            settings_data = json.loads(row[0])
        except:
            pass
            
    settings_data["language"] = lang
    
    c.execute("UPDATE users SET settings=? WHERE username=?", (json.dumps(settings_data), session.get("user")))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/profile')
@login_required
def profile():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, is_admin FROM users WHERE username=?", (session.get("user"),))
    user = c.fetchone()
    conn.close()

    if not user:
        return "User not found", 404

    return render_template("profile.html", username=user[0], role="Admin" if user[1] else "User", user_lang=get_user_lang(), active_page="settings")

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect('/login')


@app.route('/users')
@login_required
def users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # ✅ Return ID and Is_Admin status as well
    c.execute("SELECT id, username, is_admin FROM users")
    rows = c.fetchall()
    conn.close()

    return jsonify([
        {
            "id": r[0],
            "username": r[1],
            "is_admin": bool(r[2]),
            "can_delete": session.get("is_admin", False) and r[1] != session.get("user")
        }
        for r in rows
    ])

@app.route('/active_scans')
@login_required
def active_scans():
    # Only return scans that are not completed/terminated
    return jsonify({
        sid: {
            "target": job["target"],
            "status": job["status"],
            "progress": job["progress"]
        }
        for sid, job in SCAN_JOBS.items()
        if job.get("status") not in ["Completed", "Terminated", "Not Found"]
    })


@app.route('/admin/audit_logs')
@admin_required
def get_audit_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user, action, details, date FROM audit_logs ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {"user": r[0], "action": r[1], "details": r[2], "date": r[3]}
        for r in rows
    ])


# ================= ADMIN PANEL =================
@app.route('/admin')
@admin_required
def admin_panel():
    return render_template("admin.html", user=session.get("user"), user_lang=get_user_lang(), active_page="admin")


@app.route('/admin/users')
@admin_required
def admin_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin FROM users")
    rows = c.fetchall()
    conn.close()

    return jsonify([
        {"id": r[0], "username": r[1], "role": "Admin" if r[2] else "User"}
        for r in rows
    ])


@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    # Fetch username before deleting for log
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    target_user = c.fetchone()
    
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    
    if target_user:
        log_activity(session.get("user"), "DELETE_USER", f"Permanently removed user: {target_user[0]}")
    return jsonify({"message": "deleted"})


@app.route('/admin/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password")
    is_admin = 1 if request.form.get("is_admin") == "on" else 0

    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    hashed_pw = generate_password_hash(password)
    otp_secret = pyotp.random_base32()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, otp_secret, is_admin) VALUES (?,?,?,?)",
                  (username, hashed_pw, otp_secret, is_admin))
        conn.commit()
        log_activity(session.get("user"), "CREATE_USER", f"Created new account for {username} (Admin: {bool(is_admin)})")
        return jsonify({"message": "User created successfully"})
    except:
        return jsonify({"error": "User already exists"}), 400
    finally:
        conn.close()


@app.route('/admin/make_admin/<int:user_id>')
@admin_required
def make_admin(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    target_user = c.fetchone()
    c.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    if target_user:
        log_activity(session.get("user"), "PROMOTE_ADMIN", f"Promoted user {target_user[0]} to Administrator")
    return jsonify({"message": "promoted"})


@app.route('/admin/error_logs')
@admin_required
def get_error_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user, scan_id, message, date FROM error_logs ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {"user": r[0], "scan_id": r[1], "message": r[2], "date": r[3]}
        for r in rows
    ])

@app.route('/admin/remove_admin/<int:user_id>')
@admin_required
def remove_admin(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "demoted"})


@app.route('/api/assets')
@login_required
def get_assets():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, ip, domain, environment, criticality, is_internet_facing FROM assets")
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {
            "id": r[0], "name": r[1], "target": r[2] or r[3],
            "environment": r[4], "criticality": r[5], "internet_facing": bool(r[6])
        }
        for r in rows
    ])

@app.route('/api/admin/add_asset', methods=['POST'])
@login_required
def add_asset():
    data = request.json
    name = data.get("name")
    target = data.get("target")
    env = data.get("env")
    criticality = data.get("criticality")
    internet = 1 if data.get("internet") else 0

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Basic logic to distinguish IP vs Domain
    ip = target if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target) else None
    domain = target if not ip else None

    c.execute("INSERT INTO assets (name, ip, domain, owner, environment, criticality, is_internet_facing) VALUES (?,?,?,?,?,?,?)",
              (name, ip, domain, session.get("user"), env, criticality, internet))
    conn.commit()
    conn.close()
    log_activity(session.get("user"), "ADD_ASSET", f"Added asset: {name} ({target})")
    return jsonify({"message": "Asset added"})

@app.route('/api/vulnerabilities')
@login_required
def get_all_vulnerabilities():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT v.id, v.name, v.severity, v.risk_score, v.status, v.date_found, a.name, v.scan_id
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        ORDER BY v.risk_score DESC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {
            "id": r[0], "alert": r[1], "risk": r[2], "risk_score": r[3],
            "status": r[4], "date_found": r[5], "asset_name": r[6], "scan_id": r[7],
            "description": "Lifecycle tracked vulnerability.", "solution": "See scan reports for details."
        }
        for r in rows
    ])

@app.route('/api/admin/delete_asset/<int:asset_id>', methods=['DELETE'])
@login_required
def delete_asset(asset_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Asset deleted"})

# ================= REMEDIATION =================
REMEDIATION_SCRIPTS = {
    "X-Frame-Options Header Not Set": {
        "text": "Add 'X-Frame-Options: SAMEORIGIN' to your web server configuration.",
        "script": "# Apache\nHeader always set X-Frame-Options \"SAMEORIGIN\"\n\n# Nginx\nadd_header X-Frame-Options \"SAMEORIGIN\";"
    },
    "X-Content-Type-Options Header Missing": {
        "text": "Set 'X-Content-Type-Options: nosniff' header.",
        "script": "add_header X-Content-Type-Options \"nosniff\";"
    },
    "Insecure Port Open": {
        "text": "Close unnecessary ports using your firewall (ufw/iptables).",
        "script": "sudo ufw deny 21/tcp # Example for FTP"
    },
    "Technology Fingerprint": {
        "text": "Restrict information disclosure by disabling server signatures and version banners.",
        "script": "# Apache\nServerTokens Prod\nServerSignature Off\n\n# Nginx\nserver_tokens off;"
    }
}

def get_remediation(alert_name):
    # Partial match for common ZAP/Nmap alerts
    for key in REMEDIATION_SCRIPTS:
        if key.lower() in alert_name.lower():
            return REMEDIATION_SCRIPTS[key]
    return {"text": "Refer to official security guidelines for this product.", "script": ""}

# ================= I18N SUPPORT =================
LANGUAGES = {
    "en": {"dashboard": "Dashboard", "start_scan": "Start Scan", "history": "History", "alerts": "Alerts", "assets": "Asset Inventory"},
    "uk_en": {"dashboard": "Dashboard", "start_scan": "Commence Scan", "history": "Past Assessments", "alerts": "Vulnerabilities", "assets": "Asset Register"},
    "es": {"dashboard": "Panel de Control", "start_scan": "Iniciar Escaneo", "history": "Historial", "alerts": "Alertas"},
    "fr": {"dashboard": "Tableau de Bord", "start_scan": "Lancer le Scan", "history": "Historique", "alerts": "Alertes"},
    "zh-CN": {"dashboard": "仪表板", "start_scan": "开始扫描", "history": "历史记录", "alerts": "警报"}
}

@app.route('/api/notifications')
@login_required
def get_notifications():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, type, message, is_read, date FROM notifications WHERE user=? ORDER BY id DESC LIMIT 20", (session.get("user"),))
    rows = c.fetchall()
    conn.close()
    return jsonify([{"id": r[0], "type": r[1], "message": r[2], "is_read": bool(r[3]), "date": r[4]} for r in rows])

@app.route('/api/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notif_read(notif_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user=?", (notif_id, session.get("user")))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/api/notifications/clear', methods=['POST'])
@login_required
def clear_notifs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE notifications SET is_read=1 WHERE user=?", (session.get("user"),))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/api/vulnerability/status', methods=['POST'])
@login_required
def update_vuln_status():
    data = request.json
    vuln_id = data.get("id")
    new_status = data.get("status")
    
    # Check permissions
    if new_status == "Accepted Risk" and not session.get("is_admin"):
         return jsonify({"error": "Admin approval required for risk acceptance"}), 403

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE vulnerabilities SET status=? WHERE id=?", (new_status, vuln_id))
    conn.commit()
    conn.close()
    
    log_activity(session.get("user"), "VULN_UPDATE", f"Updated vuln {vuln_id} to {new_status}")
    return jsonify({"message": "Status updated"})

# ================= KNOWLEDGE BASE =================
@app.route('/api/knowledge_base')
@login_required
def get_knowledge_base():
    return jsonify(KNOWLEDGE_BASE)

@app.route('/api/knowledge_base/<int:article_id>')
@login_required
def get_knowledge_article(article_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM knowledge_base WHERE id=? AND (is_public=1 OR author=?)", (article_id, session.get("user")))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Article not found"}), 404
    
    # Increment view count
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE knowledge_base SET views=views+1 WHERE id=?", (article_id,))
    conn.commit()
    conn.close()
    
    return jsonify({
        "id": row[0],
        "title": row[1],
        "category": row[2],
        "content": row[3],
        "tags": json.loads(row[4]) if row[4] else [],
        "author": row[5],
        "created_date": row[6],
        "updated_date": row[7],
        "is_public": bool(row[8]),
        "views": row[9] + 1
    })

@app.route('/api/knowledge_base', methods=['POST'])
@login_required
def create_knowledge_article():
    data = request.json
    title = data.get("title")
    category = data.get("category")
    content = data.get("content")
    tags = json.dumps(data.get("tags", []))
    is_public = data.get("is_public", True)
    
    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400
    
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO knowledge_base (title, category, content, tags, author, created_date, updated_date, is_public) VALUES (?,?,?,?,?,?,?,?)",
              (title, category, content, tags, session.get("user"), now, now, 1 if is_public else 0))
    article_id = c.lastrowid
    conn.commit()
    conn.close()
    
    log_activity(session.get("user"), "KB_CREATE", f"Created knowledge base article: {title}")
    return jsonify({"message": "Article created", "id": article_id})

@app.route('/api/knowledge_base/<int:article_id>', methods=['PUT'])
@login_required
def update_knowledge_article(article_id):
    data = request.json
    title = data.get("title")
    category = data.get("category")
    content = data.get("content")
    tags = json.dumps(data.get("tags", []))
    is_public = data.get("is_public", True)
    
    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400
    
    # Check ownership
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT author FROM knowledge_base WHERE id=?", (article_id,))
    row = c.fetchone()
    if not row or (row[0] != session.get("user") and not session.get("is_admin")):
        conn.close()
        return jsonify({"error": "Permission denied"}), 403
    
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("UPDATE knowledge_base SET title=?, category=?, content=?, tags=?, updated_date=?, is_public=? WHERE id=?",
              (title, category, content, tags, now, 1 if is_public else 0, article_id))
    conn.commit()
    conn.close()
    
    log_activity(session.get("user"), "KB_UPDATE", f"Updated knowledge base article: {title}")
    return jsonify({"message": "Article updated"})

@app.route('/api/knowledge_base/<int:article_id>', methods=['DELETE'])
@login_required
def delete_knowledge_article(article_id):
    # Check ownership
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT author FROM knowledge_base WHERE id=?", (article_id,))
    row = c.fetchone()
    if not row or (row[0] != session.get("user") and not session.get("is_admin")):
        conn.close()
        return jsonify({"error": "Permission denied"}), 403
    
    c.execute("DELETE FROM knowledge_base WHERE id=?", (article_id,))
    conn.commit()
    conn.close()
    
    log_activity(session.get("user"), "KB_DELETE", f"Deleted knowledge base article ID: {article_id}")
    return jsonify({"message": "Article deleted"})

@app.route('/api/knowledge_base/search')
@login_required
def search_knowledge_base():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    sql = "SELECT id, title, category, tags, author, created_date, updated_date, views FROM knowledge_base WHERE (is_public=1 OR author=?)"
    params = [session.get("user")]
    
    if query:
        sql += " AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)"
        params.extend([f'%{query}%', f'%{query}%', f'%{query}%'])
    
    if category:
        sql += " AND category = ?"
        params.append(category)
    
    sql += " ORDER BY updated_date DESC"
    
    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    
    articles = []
    for row in rows:
        articles.append({
            "id": row[0],
            "title": row[1],
            "category": row[2],
            "tags": json.loads(row[3]) if row[3] else [],
            "author": row[4],
            "created_date": row[5],
            "updated_date": row[6],
            "views": row[7]
        })
    return jsonify(articles)

# ================= THREAT INTEL =================
THREAT_INTEL = {
    "seen_in_wild": ["Apache", "Nginx", "Wordpress"],
    "active_exploits": ["CVE-2021-44228", "CVE-2024-3400"]
}

def map_to_compliance(alert_name):
    mapping = {
        "PCI-DSS": ["Injection", "SSL", "Encryption", "Cleartext", "Credit Card"],
        "GDPR": ["Personal Data", "Directory", "Sensitive", "Privacy"],
        "SOC2": ["Access Control", "Audit", "Monitoring", "Logging"],
        "HIPAA": ["Health", "Protected", "Insecure Design"]
    }
    tags = []
    for standard, keywords in mapping.items():
        if any(k.lower() in alert_name.lower() for k in keywords):
            tags.append(standard)
    return tags if tags else ["Internal Standard"]

# ================= REMEDIATION TRACKING =================
def track_remediation(target, current_alerts):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT alerts FROM scans WHERE target=? AND status='Completed' ORDER BY id DESC LIMIT 1 OFFSET 1", (target,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return []

    try:
        old_alerts = json.loads(row[0])
    except Exception:
        return []
    fixed = []
    current_names = [a["alert"] for a in current_alerts]
    
    for old in old_alerts:
        if old["alert"] not in current_names:
            fixed.append(old["alert"])
    return fixed

# ================= RISK & ML =================
def calculate_risk_score(alert, asset_criticality="Medium", is_internet_facing=False):
    """
    Scoring Layer:
    - Base: Risk Level (High=50, Medium=25, Low=10)
    - Exposure: Internet Facing (+20)
    - Criticality: Asset Importance (Critical=+30, High=+20, Medium=+10)
    - CVE: Presence of CVE (+10)
    """
    score = 0
    # Base Severity
    if alert.get("risk") == "High": score += 50
    elif alert.get("risk") == "Medium": score += 25
    elif alert.get("risk") == "Low": score += 10
    
    # Asset Criticality
    if asset_criticality == "Critical": score += 30
    elif asset_criticality == "High": score += 20
    elif asset_criticality == "Medium": score += 10
    
    # Exposure
    if is_internet_facing: score += 20
    
    # Threat Intel / CVE
    if alert.get("cves") and len(alert["cves"]) > 0: score += 10
    if any("wild" in str(f).lower() for f in alert.get("intel", [])): score += 15
    
    return min(100, score)

def zero_day_heuristics(alert_name, path):
    if "unknown" in str(alert_name).lower(): return True
    return False

def map_to_owasp(alert):
    alert_lower = alert.lower()
    if "sql" in alert_lower or "injection" in alert_lower: return "A03:2021-Injection"
    if "cross" in alert_lower and "site" in alert_lower: return "A03:2021-Injection" # XSS
    if "auth" in alert_lower or "login" in alert_lower: return "A07:2021-Identification and Authentication Failures"
    if "config" in alert_lower: return "A05:2021-Security Misconfiguration"
    if "component" in alert_lower or "version" in alert_lower: return "A06:2021-Vulnerable and Outdated Components"
    if "expose" in alert_lower or "data" in alert_lower: return "A02:2021-Cryptographic Failures"
    return "OWASP-Uncategorized"

def enrich_with_intel(alert_name):
    intel = []
    if "sql" in alert_name.lower(): intel.append("High exploitability (CISA KEV)")
    if "xss" in alert_name.lower() or "cross site" in alert_name.lower(): intel.append("Commonly exploited remotely")
    if "rce" in alert_name.lower() or "remote code" in alert_name.lower(): intel.append("Critical: Immediate action required")
    for software in THREAT_INTEL["seen_in_wild"]:
        if software.lower() in alert_name.lower():
            intel.append("🔥 Seen in the wild")
    return intel

# ================= NOTIFICATIONS =================
def add_notification(user, ntype, message):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO notifications (user, type, message, date) VALUES (?,?,?,?)",
                  (user, ntype, message, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except: pass

def send_realtime_alert(user, target, risk, alert_name):
    # Stub for push/email notification
    log_activity(user, "SECURITY_ALERT", f"High-risk vulnerability detected: {alert_name} on {target}")
    add_notification(user, "SECURITY_ALERT", f"CRITICAL: {alert_name} detected on {target}")
    # In a real app, you'd trigger a SMTP mail here
    pass

# ================= SCAN SYSTEM =================
# ZAP daemon connection settings (overridable via environment variables).
# Defaults match the container setup in start.sh (ZAP on 127.0.0.1:8080).
ZAP_HOST = os.environ.get("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={
        'http': f'http://{ZAP_HOST}:{ZAP_PORT}',
        'https': f'http://{ZAP_HOST}:{ZAP_PORT}'
    }
)

def run_scans(target, scan_id, start_phase="Nmap", user_email=None):
    job = SCAN_JOBS.get(scan_id, {})
    if not job:
        print(f"❌ Job {scan_id} not found in memory")
        return

    try:
        print(f"🚀 Initiating scan task for {target} (ID: {scan_id})")
        profile = job.get("profile", "deep")
        use_nmap = (job.get("use_nmap", True) and profile != "targeted_web") and start_phase in ["Nmap"]
        use_zap_spider = (job.get("use_zap", True) and profile != "targeted_ports") and start_phase in ["Nmap", "Spider"]
        use_zap_ascan = (job.get("use_zap", True) and profile == "deep") and start_phase in ["Nmap", "Spider", "Active Scan"]
        
        job["status"] = "Running..."
        
        if use_nmap:
            try:
                nm = nmap.PortScanner()
                scan_args = '-sV -T4' if profile == 'deep' else '-F -T4'
            except Exception as ne:
                print(f"⚠️ Nmap initialiation failed: {ne}")
                log_error(job["user"], scan_id, f"Nmap not found or permission denied: {str(ne)}")
                use_nmap = False # Skip Nmap but continue with other modules
                job["status"] = "Running (Nmap skipped)..."

        if use_nmap:
            # --- TECHNOLOGY FINGERPRINTING & SUBDOMAIN ---
            try:
                # Basic subdomain lookup
                base = target.split("//")[-1].split("/")[0]
                common_subs = ['dev', 'staging', 'test', 'api', 'vpn']
                for sub in common_subs:
                    try:
                        full = f"{sub}.{base}"
                        ip = socket.gethostbyname(full)
                        job["alerts"].append({"alert": f"Subdomain Found: {full}", "risk": "Info", "path": ip, "description": f"Internal or hidden subdomain discovered: {full} ({ip})"})
                    except: pass
            except: pass

            try:
                # Tech fingerprinting via headers
                head_resp = requests.head(target, timeout=5)
                server = head_resp.headers.get("Server", "Unknown")
                powered = head_resp.headers.get("X-Powered-By", "Unknown")
                job["alerts"].append({"alert": "Technology Fingerprint", "risk": "Info", "path": target, "description": f"Server: {server}, Powered-By: {powered}"})
            except: pass

            # --- SSL/TLS MISCONFIGURATION CHECKS ---
            if target.startswith("https"):
                try:
                    ssl_resp = requests.get(target, verify=True, timeout=5)
                except requests.exceptions.SSLError:
                    job["alerts"].append({"alert": "Insecure SSL/TLS configuration", "risk": "Medium", "path": target, "description": "The server is using an expired or self-signed certificate."})
                except: pass
            
            # --- DIRECTORY BRUTE FORCE ---
            if profile == "deep":
                paths = ["/admin", "/config", "/.git", "/backup", "/wp-admin", "/panel"]
                for p in paths:
                    try:
                        r = requests.get(target + p, timeout=2, verify=False)
                        if r.status_code in [200, 403]:
                            job["alerts"].append({
                                "alert": f"Sensitive Directory/File Detected: {p}",
                                "risk": "Medium",
                                "path": target + p,
                                "solution": "Restrict access to sensitive directories.",
                                "description": f"Encountered {r.status_code} when accessing {p}."
                            })
                    except: pass
            
            for i in range(1, 40):
                if job.get("terminated"): return
                job["nmap"] = i
                time.sleep(0.02)

            try:
                nm.scan(hosts=target, arguments=scan_args)
                job["nmap"] = 100
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            service = nm[host][proto][port]
                            product = service.get("product", "")
                            version = service.get("version", "")
                            cves = lookup_cves(product, version)
                            alert_name = f"{product} {version} on port {port}" if product else f"Service on port {port}"
                            remediation = get_remediation(alert_name)
                            intel = enrich_with_intel(alert_name)
                            risk_score = 0
                            
                            job["alerts"].append({
                                "alert": alert_name,
                                "risk": "Info",
                                "risk_score": risk_score,
                                "is_zero_day": zero_day_heuristics(alert_name, f"Port {port}"),
                                "path": f"Port {port}/{proto}",
                                "solution": remediation["text"],
                                "script": remediation["script"],
                                "cves": cves,
                                "intel": intel,
                                "description": f"Service detection found {product} {version} running on port {port}."
                            })

                            # INTELLIGENT FLOW: Trigger ZAP if HTTP/HTTPS found on raw IP
                            if port in [80, 443] and not target.startswith("http"):
                                protocol = "https" if port == 443 else "http"
                                web_target = f"{protocol}://{target}"
                                job["alerts"].append({"alert": "Web Service Detected", "risk": "Info", "path": target, "description": f"Nmap found port {port}. Automatically triggering web scan on {web_target}."})
                                
                                # Overwrite target for ZAP
                                target = web_target
                                use_zap_spider = True
                                if profile == 'deep':
                                    use_zap_ascan = True

            except Exception as e:
                log_error(job["user"], scan_id, f"Nmap Error: {str(e)}")

        if use_zap_spider:
            api_url = job.get("api_url")
            auth_user = job.get("auth_user")
            auth_pass = job.get("auth_pass")

            if auth_user and auth_pass:
                import base64
                auth_str = base64.b64encode(f"{auth_user}:{auth_pass}".encode()).decode()
                try:
                    zap.replacer.add_rule(description="AuthHeader", enabled="true", matchtype="REQ_HEADER", matchregex="false", matchstring="Authorization", replacement=f"Basic {auth_str}", initiators="")
                    job["alerts"].append({"alert": "Authenticated Scan Enabled", "risk": "Info", "path": target, "description": f"HTTP Basic Auth enabled for user: {auth_user}"})
                except Exception as e:
                    pass

            if api_url:
                job["current_phase"] = "API Import"
                try:
                    zap.openapi.import_url(api_url, target)
                    job["alerts"].append({"alert": "API Schema Imported", "risk": "Info", "path": api_url, "description": f"Successfully imported OpenAPI definition from {api_url}"})
                except Exception as e:
                    job["alerts"].append({"alert": "API Schema Import Failed", "risk": "Info", "path": api_url, "description": f"Failed to import from {api_url}: {e}"})

            job["current_phase"] = "Spider"
            try:
                zap.urlopen(target)
                spider_id = zap.spider.scan(target)
                while int(zap.spider.status(spider_id)) < 100:
                    if job.get("terminated"):
                        job["status"] = "Terminated"
                        return
                    job["spider"] = int(zap.spider.status(spider_id))
                    job["progress"] = 30 + int(job["spider"] * 0.3)
                    time.sleep(0.5)
                job["spider"] = 100
            except Exception as ze:
                print(f"⚠️ ZAP Connection failed: {ze}")
                log_error(job["user"], scan_id, f"ZAP Proxy not reachable: {str(ze)}")
                job["alerts"].append({
                    "alert": "Scanner Core Unavailable",
                    "risk": "Info",
                    "path": "System",
                    "description": "The ZAP vulnerability engine is not running on this server (Render). Deep web scanning skipped.",
                    "solution": "Deploy via Docker with ZAP installed or run locally."
                })
                use_zap_spider = False
                use_zap_ascan = False
                job["spider"] = 100


        if use_zap_ascan:
            job["current_phase"] = "Active Scan"
            try:
                ascan_id = zap.ascan.scan(target)
                while int(zap.ascan.status(ascan_id)) < 100:
                    if job.get("terminated"):
                        job["status"] = "Terminated"
                        return
                    job["active"] = int(zap.ascan.status(ascan_id))
                    job["progress"] = 60 + int(job["active"] * 0.4)
                    time.sleep(1)
                job["active"] = 100
            except Exception as ae:
                print(f"⚠️ ZAP Active Scan failed: {ae}")
                job["active"] = 100

        # Cleanup Auth Rule
        try:
            zap.replacer.remove_rule("AuthHeader")
        except:
            pass

        # Collect results if ZAP was used at all
        if profile != "targeted_ports" and (use_zap_spider or use_zap_ascan):
            try:
                zap_alerts = zap.core.alerts(baseurl=target)
            except Exception:
                zap_alerts = []
                
            for a in zap_alerts:
                risk = a.get("risk", "Info")
                alert_name = a.get("alert", "N/A")
                remediation = get_remediation(alert_name)
                if risk in ["High", "Medium"]:
                    send_realtime_alert(job["user"], target, risk, alert_name)
                
                intel = enrich_with_intel(alert_name)
                risk_score = 0
                # Zero Day Detection
                is_zero_day = zero_day_heuristics(alert_name, a.get("url", ""))

                if risk in ["High", "Medium"]:
                    send_realtime_alert(job["user"], target, risk, alert_name)
                
                job["alerts"].append({
                    "alert": alert_name,
                    "risk": risk,
                    "risk_score": risk_score,
                    "is_zero_day": is_zero_day,
                    "path": a.get("url", ""),
                    "solution": a.get("solution", "") or remediation["text"],
                    "script": remediation["script"],
                    "description": a.get("description", ""),
                    "cves": []
                })

        # Remediation Tracking
        fixed_vulnerabilities = track_remediation(target, job["alerts"])
        job["fixed"] = fixed_vulnerabilities

        # ✅ VULNERABILITY LIFECYCLE TRACKING
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Try to find associated asset
        c.execute("SELECT id, criticality, is_internet_facing FROM assets WHERE ip=? OR domain=?", (target, target))
        asset_row = c.fetchone()
        asset_id = asset_row[0] if asset_row else None
        criticality = asset_row[1] if asset_row else "Medium"
        internet = asset_row[2] if asset_row else 0

        for alert in job["alerts"]:
            # Update risk score based on asset context
            alert["risk_score"] = calculate_risk_score(alert, criticality, bool(internet))
            compliance = map_to_compliance(alert["alert"])
            
            # Record in vulnerabilities table
            c.execute("""
                INSERT INTO vulnerabilities (scan_id, asset_id, name, severity, risk_score, status, cvss_score, exposure, compliance_tags, date_found, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job["id"], asset_id, alert["alert"], alert["risk"], alert["risk_score"],
                "Open", alert.get("cvss", 0), "Internet-Facing" if internet else "Internal",
                json.dumps(compliance), datetime.utcnow().isoformat(), datetime.utcnow().isoformat()
            ))

        c.execute(
            "INSERT INTO scans (scan_id, user, target, date, alerts, profile, status, current_phase, fixed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job["id"], job["user"], target, datetime.utcnow().isoformat(), json.dumps(job["alerts"]), profile, "Completed", "Done", json.dumps(job.get("fixed", [])))
        )
        conn.commit()
        conn.close()
        
        # ✅ FIX: Update the JOB status in memory so Polling sees it!
        job["status"] = "Completed"
        job["progress"] = 100
        job["nmap"] = 100
        job["spider"] = 100
        job["active"] = 100
        
        # Notification
        add_notification(job["user"], "SCAN_COMPLETE", f"Scan for {target} finished successfully.")
        
        # ✅ EMAIL NOTIFICATION (only fires if SMTP is configured)
        if _MAIL_CONFIGURED and user_email:
            with app.app_context():
                try:
                    print(f"📧 Preparing to send scan completion email to: {user_email}")
                    msg = Message(f"VigiScan Completion: {target}", recipients=[user_email])
                    high = len([a for a in job["alerts"] if a.get("risk") == "High"])
                    med = len([a for a in job["alerts"] if a.get("risk") == "Medium"])
                    msg.body = f"The scan for {target} ({profile}) has completed.\n\nSummary:\n- High Risk: {high}\n- Medium Risk: {med}\n- Total Issues: {len(job['alerts'])}\n\nYou can view the full report at: http://localhost:5000/dashboard"
                    mail.send(msg)
                    print(f"✅ Email successfully sent to {user_email}")
                except Exception as e:
                    print(f"⚠️ Email send failed: {str(e)}")

        if any(a["risk"] == "High" for a in job["alerts"]):
            add_notification(job["user"], "URGENT", f"Critical vulnerabilities detected on {target}!")

        log_activity(job["user"], "SCAN_COMPLETED", f"Target: {target}, Scan ID: {job['id']}")

    except Exception as e:
        err_msg = f"Critical Failure: {str(e)}"
        print(f"❌ {err_msg}")
        log_error(job["user"], scan_id, err_msg)
        job["status"] = f"Failed: {str(e)}"
        job["progress"] = 0


@app.route('/settings')
@login_required
def settings():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT otp_secret FROM users WHERE username=?", (session.get("user"),))
    row = c.fetchone()
    conn.close()

    twofa_enabled = bool(row and row[0])
    return render_template("settings.html", user=session.get("user"), twofa_enabled=twofa_enabled, user_lang=get_user_lang(), active_page="settings")
@app.route('/settings', methods=['POST'])
@login_required
def update_settings():
    new_password = request.form.get("password")
    enable_2fa = request.form.get("2fa") == "on"

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ✅ Update password if provided
    if new_password and new_password.strip():
        hashed_pw = generate_password_hash(new_password.strip())
        c.execute("UPDATE users SET password=? WHERE username=?", (hashed_pw, session.get("user")))

    # ✅ Update 2FA setting
    if enable_2fa:
        # generate new secret if enabling
        otp_secret = pyotp.random_base32()
        c.execute("UPDATE users SET otp_secret=? WHERE username=?", (otp_secret, session.get("user")))
    else:
        # disable 2FA by clearing secret
        c.execute("UPDATE users SET otp_secret=NULL WHERE username=?", (session.get("user"),))

    conn.commit()
    conn.close()

    flash("Settings updated successfully!", "success")
    return redirect("/settings")


RATE_LIMITS = {}

@app.route('/api/trigger', methods=['POST'])
@login_required
def scan():
    try:
        user = session.get("user", "Guest")
        now = time.time()
        if user in RATE_LIMITS and now - RATE_LIMITS[user] < 5:
            return jsonify({"error": "Rate limit exceeded. Please wait before starting another scan."}), 429
        RATE_LIMITS[user] = now

        # Handle both JSON and Form-data
        if request.is_json:
            data = request.json
        else:
            data = request.form
            
        target = data.get('target', '').strip()
        profile = data.get('profile', 'deep')
        
        if not target:
            return jsonify({"error": "Target is required"}), 400
            
        import urllib.parse
        import re

        is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target)
        
        if not is_ip:
            parsed = urllib.parse.urlparse(target)
            if not parsed.scheme or not parsed.netloc:
                return jsonify({"error": "Invalid target. Must be a valid IP address or include http:// or https://"}), 400
            
        scan_id = str(uuid.uuid4())[:6]
        
        # Determine module usage based on form or profile
        use_nmap = profile in ["deep", "quick", "targeted_ports"]
        if "use_nmap" in request.form:
            use_nmap = request.form.get("use_nmap").lower() == "true"
            
        use_zap = profile in ["deep", "quick", "targeted_web"]
        if "use_zap" in request.form:
            use_zap = request.form.get("use_zap").lower() == "true"
            
        api_url = data.get("api_url", "").strip()
        auth_user = data.get("auth_user", "").strip()
        auth_pass = data.get("auth_pass", "").strip()

        SCAN_JOBS[scan_id] = {
            "id": scan_id,
            "user": user,
            "target": target,
            "api_url": api_url,
            "auth_user": auth_user,
            "auth_pass": auth_pass,
            "spider": 0,
            "active": 0,
            "nmap": 0,
            "progress": 0,
            "status": "Starting...",
            "alerts": [],
            "terminated": False,
            "created": datetime.utcnow().isoformat(),
            "profile": profile,
            "use_nmap": use_nmap,
            "use_zap": use_zap
        }

        threading.Thread(target=run_scans, args=(target, scan_id, "Nmap", session.get("email")), daemon=True).start()
        return jsonify({"scan_id": scan_id})
    except Exception as e:
        print(f"DEBUG: Scan initiation failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/resume/<scan_id>', methods=['POST'])
@login_required
def resume_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT target, profile, current_phase FROM scans WHERE scan_id=? AND user=?", (scan_id, session.get("user")))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Scan not found"}), 404

    target, profile, phase = row[0], row[1], row[2]
    new_scan_id = str(uuid.uuid4())[:6]
    
    SCAN_JOBS[new_scan_id] = {
        "id": new_scan_id,
        "user": session.get("user"),
        "target": target,
        "spider": 0, "active": 0, "nmap": 0, "progress": 0,
        "status": "Resuming...",
        "alerts": [], "terminated": False,
        "created": datetime.utcnow().isoformat(),
        "profile": profile,
        "use_nmap": profile in ["deep", "quick", "targeted_ports"],
        "use_zap": profile in ["deep", "quick", "targeted_web"]
    }

    threading.Thread(target=run_scans, args=(target, new_scan_id, phase, session.get("email")), daemon=True).start()
    return jsonify({"scan_id": new_scan_id, "message": f"Resuming from {phase}"})

@app.route('/relaunch/<scan_id>', methods=['POST'])
@login_required
def relaunch_scan(scan_id):
    """Relaunch a completed scan against the same target with the same profile."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT target, profile FROM scans WHERE scan_id=? AND user=?", (scan_id, session.get("user")))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Scan not found"}), 404

    target, profile = row[0], row[1]
    new_scan_id = str(uuid.uuid4())[:6]

    SCAN_JOBS[new_scan_id] = {
        "id": new_scan_id,
        "user": session.get("user"),
        "target": target,
        "spider": 0, "active": 0, "nmap": 0, "progress": 0,
        "status": "Starting...",
        "alerts": [], "terminated": False,
        "created": datetime.utcnow().isoformat(),
        "profile": profile,
        "use_nmap": profile in ["deep", "quick", "targeted_ports"],
        "use_zap": profile in ["deep", "quick", "targeted_web"]
    }

    threading.Thread(target=run_scans, args=(target, new_scan_id, "Nmap", session.get("email")), daemon=True).start()
    log_activity(session.get("user"), "RELAUNCH_SCAN", f"Relaunched scan for {target} (profile: {profile})")
    return jsonify({"scan_id": new_scan_id, "message": f"Scan relaunched for {target}"})


# ================= SCHEDULED SCANS =================
from apscheduler.schedulers.background import BackgroundScheduler

# Create and start the scheduler
scheduler = BackgroundScheduler()
scheduler.start()

def scheduled_scan(target, user="Abrahamdagr8"):
    scan_id = str(uuid.uuid4())[:6]
    SCAN_JOBS[scan_id] = {
        "id": scan_id,
        "user": user,
        "target": target,
        "spider": 0,
        "active": 0,
        "nmap": 0,
        "progress": 0,
        "status": "Scheduled",
        "alerts": [],
        "terminated": False,
        "created": datetime.utcnow().isoformat(),
        "use_nmap": True,
        "use_zap": True
    }
    threading.Thread(target=run_scans, args=(target, scan_id), daemon=True).start()
    print(f"✅ Scheduled scan started for {target} with ID {scan_id}")

# Example: run every day at 2 AM automatically
# Example job removed to prevent confusion with cancelled tasks

# Route to allow users to schedule scans via dashboard
@app.route('/schedule_scan', methods=['POST'])
@login_required
def schedule_scan():
    target = request.form.get("target")
    frequency = request.form.get("frequency")  # e.g. daily, weekly
    hour = int(request.form.get("hour", 2))    # default 2 AM

    if frequency == "daily":
        scheduler.add_job(scheduled_scan, 'cron', hour=hour, minute=0, kwargs={"target": target, "user": session.get("user")})
    elif frequency == "weekly":
        scheduler.add_job(scheduled_scan, 'cron', day_of_week='sun', hour=hour, minute=0, kwargs={"target": target, "user": session.get("user")})

    return jsonify({"message": f"Successfully scheduled {frequency} scan for {target} at {hour}:00"})

@app.route('/schedule', methods=['POST'])
@login_required
def schedule_scan_json():
    """JSON-based scheduling endpoint used by the dashboard modal."""
    data = request.get_json(force=True) or {}
    target = data.get("target", "").strip()
    profile = data.get("profile", "deep")
    frequency = data.get("frequency", "daily")
    start_time_str = data.get("start_time", "")

    if not target:
        return jsonify({"error": "Target is required"}), 400

    run_date = None
    if start_time_str:
        try:
            run_date = datetime.fromisoformat(start_time_str)
        except Exception:
            return jsonify({"error": "Invalid start_time format"}), 400

    user = session.get("user")

    if frequency == "daily":
        scheduler.add_job(
            scheduled_scan, 'cron',
            hour=run_date.hour if run_date else 2,
            minute=run_date.minute if run_date else 0,
            kwargs={"target": target, "user": user}
        )
    elif frequency == "weekly":
        scheduler.add_job(
            scheduled_scan, 'cron', day_of_week='sun',
            hour=run_date.hour if run_date else 2,
            minute=run_date.minute if run_date else 0,
            kwargs={"target": target, "user": user}
        )
    elif frequency == "monthly":
        scheduler.add_job(
            scheduled_scan, 'cron', day=1,
            hour=run_date.hour if run_date else 2,
            minute=run_date.minute if run_date else 0,
            kwargs={"target": target, "user": user}
        )
    else:
        # One-time run at the given datetime
        scheduler.add_job(
            scheduled_scan, 'date',
            run_date=run_date,
            kwargs={"target": target, "user": user}
        )

    log_activity(user, "SCHEDULE_SCAN", f"Scheduled {frequency} scan for {target}")
    return jsonify({"message": f"✅ {frequency.capitalize()} scan scheduled for {target}"})

@app.route('/cancel_schedule/<job_id>', methods=['POST'])
@login_required
def cancel_schedule(job_id):
    try:
        scheduler.remove_job(job_id)
        log_activity(session.get("user"), "CANCEL_SCHEDULE", f"Job ID: {job_id}")
        return jsonify({"message": "Schedule cancelled successfully"})
    except:
        return jsonify({"error": "Job not found"}), 404

@app.route('/api/schedules')
@login_required
def get_schedules():
    jobs = []
    for job in scheduler.get_jobs():
        # APScheduler jobs can be inspected
        if job.kwargs.get("user") == session.get("user") or session.get("is_admin"):
            jobs.append({
                "id": job.id,
                "target": job.kwargs.get("target"),
                "next_run": job.next_run_time.isoformat() if job.next_run_time else "Paused"
            })
    return jsonify(jobs)


@app.route('/api/trends')
@login_required
def get_trends():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT date, alerts FROM scans WHERE user=? ORDER BY date ASC", (session.get("user"),))
    rows = c.fetchall()
    conn.close()

    trends = []
    for r in rows:
        try:
            alerts = json.loads(r[1]) if r[1] else []
            high = len([a for a in alerts if a.get("risk") == "High"])
            medium = len([a for a in alerts if a.get("risk") == "Medium"])
            low = len([a for a in alerts if a.get("risk") == "Low"])
            trends.append({
                "date": r[0][:10], # YYYY-MM-DD
                "high": high,
                "medium": medium,
                "low": low
            })
        except:
            continue
    
    return jsonify(trends)


@app.route('/delete_scan/<scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    if not session.get("is_admin"):
        return jsonify({"error": "Only admins can delete scans"}), 403
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
    conn.commit()
    conn.close()
    
    if scan_id in SCAN_JOBS:
        del SCAN_JOBS[scan_id]
        
    log_activity(session.get("user"), "DELETE_SCAN", f"Deleted scan: {scan_id}")
    return jsonify({"message": "Scan deleted"})

@app.route('/status/<scan_id>')
@login_required
def status(scan_id):
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return jsonify({"status": "Not Found", "spider": 0, "active": 0, "nmap": 0, "progress": 0})

    return jsonify({
        "status": job.get("status", "Unknown"),
        "spider": job.get("spider", 0),
        "active": job.get("active", 0),
        "nmap": job.get("nmap", 0),
        "progress": job.get("progress", 0)
    })


@app.route('/scan_result/<scan_id>')
@login_required
def scan_result(scan_id):
    job = SCAN_JOBS.get(scan_id)

    if not job:
        # Fallback to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT target, status, alerts, fixed FROM scans WHERE scan_id=?", (scan_id,))
        row = c.fetchone()
        conn.close()
        
        if row:
            alerts = json.loads(row[2]) if row[2] else []
            return jsonify({
                "target": row[0],
                "status": row[1],
                "alerts": alerts,
                "fixed": json.loads(row[3]) if row[3] else [],
                "summary": {
                    "total_alerts": len(alerts),
                    "high": len([a for a in alerts if a.get("risk") == "High"]),
                    "medium": len([a for a in alerts if a.get("risk") == "Medium"]),
                    "low": len([a for a in alerts if a.get("risk") == "Low"])
                }
            }), 200
        return jsonify({"error": "Invalid scan ID"}), 404

    # If terminated, return terminated status with alerts collected so far
    if job.get("terminated"):
        return jsonify({
            "target": job.get("target"),
            "status": "Terminated",
            "alerts": job.get("alerts", []),
            "summary": {
                "total_alerts": len(job.get("alerts", [])),
                "high": len([a for a in job.get("alerts", []) if a.get("risk") == "High"]),
                "medium": len([a for a in job.get("alerts", []) if a.get("risk") == "Medium"]),
                "low": len([a for a in job.get("alerts", []) if a.get("risk") == "Low"])
            }
        }), 200

    # If still running
    if job.get("status") not in ["Completed", "Terminated"]:
        return jsonify({
            "message": "Scan not completed",
            "status": job.get("status"),
            "progress": job.get("progress", 0)
        }), 202

    # Completed scan (freshly done and still in memory)
    return jsonify({
        "target": job.get("target"),
        "status": "Completed",
        "alerts": job.get("alerts", []),
        "fixed": job.get("fixed", []),
        "summary": {
            "total_alerts": len(job.get("alerts", [])),
            "high": len([a for a in job.get("alerts", []) if a.get("risk") == "High"]),
            "medium": len([a for a in job.get("alerts", []) if a.get("risk") == "Medium"]),
            "low": len([a for a in job.get("alerts", []) if a.get("risk") == "Low"])
        }
    }), 200


@app.route('/terminate/<scan_id>', methods=['POST'])
@login_required
def terminate_scan(scan_id):   # ✅ renamed function
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return jsonify({"error": "Invalid scan ID"}), 404

    # Mark job as terminated
    job["terminated"] = True
    job["status"] = "Terminated"

    return jsonify({
        "message": f"Scan {scan_id} terminated",
        "status": "Terminated"
    }), 200


@app.route('/history')
@login_required
def history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # ✅ Updated column selection
    is_admin = session.get("is_admin", False)
    if is_admin:
        c.execute("SELECT scan_id, target, date, alerts, profile, status, current_phase, fixed, user FROM scans ORDER BY id DESC")
    else:
        c.execute("SELECT scan_id, target, date, alerts, profile, status, current_phase, fixed, user FROM scans WHERE user=? ORDER BY id DESC", (session.get("user"),))
    rows = c.fetchall()
    conn.close()

    history_data = []
    
    # 1. Past Scans
    for r in rows:
        try:
            alerts = json.loads(r[3]) if r[3] else []
            history_data.append({
                "scan_id": r[0],
                "target": r[1],
                "date": r[2],
                "alerts_count": len(alerts),
                "high": len([a for a in alerts if a.get("risk") == "High"]),
                "medium": len([a for a in alerts if a.get("risk") == "Medium"]),
                "low": len([a for a in alerts if a.get("risk") == "Low"]),
                "fixed": json.loads(r[7]) if len(r) > 7 and r[7] else [],
                "profile": r[4],
                "status": r[5],
                "current_phase": r[6] if len(r) > 6 else "Done",
                "is_scheduled": False,
                "can_delete": is_admin,
                "user": r[8],
                "report_pdf": f"/report?scan_id={r[0]}&type=pdf",
                "report_html": f"/report?scan_id={r[0]}&type=html",
                "report_excel": f"/report?scan_id={r[0]}&type=excel"
            })
        except:
            continue

    # 2. Scheduled Jobs
    for job in scheduler.get_jobs():
        job_kwargs = job.kwargs if hasattr(job, "kwargs") else {}
        target = job_kwargs.get("target", "Unknown")
        user = job_kwargs.get("user")

        if user == session.get("user") or session.get("is_admin"):
            history_data.append({
                "scan_id": job.id,
                "target": target,
                "date": "Scheduled",
                "is_scheduled": True,
                "next_run_time": job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job.next_run_time else "Paused",
                "alerts_count": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "profile": "Recurring",
                "status": "Scheduled",
                "report_pdf": None,
                "report_html": None,
                "report_excel": None
            })

    return jsonify(history_data)


# ================= REPORT FIXED SYSTEM =================

# ================= REPORT CHART HELPERS =================

def _load_report_font(size):
    """Load a TTF font for chart rendering with fallback to default."""
    from PIL import ImageFont
    candidates = [
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    ]
    for fp in candidates:
        try:
            return ImageFont.truetype(fp, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()

def _severity_distribution(alerts, severity_resolver):
    """Count alerts by severity using the provided resolver."""
    labels = ["Critical", "High", "Medium", "Low", "Informational"]
    counts = {label: 0 for label in labels}
    for a in alerts or []:
        sev = severity_resolver(a)
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Informational"] += 1
    return counts

def _port_summary(alerts):
    """Summarize open ports/services from scan alerts."""
    ports = parse_port_entries(alerts or [])
    summary = {}
    for p in ports:
        key = f"{p.get('port')}/{p.get('protocol')} ({p.get('service') or 'Unknown'})"
        summary[key] = summary.get(key, 0) + 1
    return summary

def _severity_chart_png(alerts, severity_resolver):
    """Generate a severity distribution bar chart as PNG bytes using Pillow."""
    from PIL import Image, ImageDraw

    counts = _severity_distribution(alerts, severity_resolver)
    labels = ["Critical", "High", "Medium", "Low", "Informational"]
    colors = [(220, 38, 38), (231, 76, 60), (243, 156, 18), (39, 174, 96), (56, 189, 248)]

    width, height = 620, 260
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)

    margin_left, margin_right = 50, 20
    margin_top, margin_bottom = 40, 50
    chart_w = width - margin_left - margin_right
    chart_h = height - margin_top - margin_bottom

    max_count = max(counts.values()) if counts else 0
    max_count = max(max_count, 1)

    slot_w = chart_w / len(labels)
    bar_w = slot_w * 0.55
    font = _load_report_font(14)
    small_font = _load_report_font(12)

    for i, label in enumerate(labels):
        count = counts[label]
        x0 = margin_left + i * slot_w + (slot_w - bar_w) / 2
        bar_h = int((count / max_count) * chart_h) if count > 0 else 2
        y0 = margin_top + chart_h - bar_h
        x1 = x0 + bar_w
        y1 = margin_top + chart_h

        draw.rectangle([x0, y0, x1, y1], fill=colors[i])

        # Count label above bar
        count_text = str(count)
        bbox = draw.textbbox((0, 0), count_text, font=font)
        tw = bbox[2] - bbox[0]
        draw.text((x0 + bar_w / 2 - tw / 2, y0 - 20), count_text, fill="black", font=font)

        # Severity label below
        bbox = draw.textbbox((0, 0), label, font=small_font)
        tw = bbox[2] - bbox[0]
        draw.text((x0 + bar_w / 2 - tw / 2, margin_top + chart_h + 8), label, fill="black", font=small_font)

    # Axes
    draw.line([margin_left, margin_top + chart_h, width - margin_right, margin_top + chart_h], fill="black")
    draw.line([margin_left, margin_top, margin_left, margin_top + chart_h], fill="black")

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

def _ports_chart_png(alerts):
    """Generate an open ports/services horizontal bar chart as PNG bytes using Pillow."""
    from PIL import Image, ImageDraw

    summary = _port_summary(alerts)
    if not summary:
        return None

    # Sort by count descending, take top 8
    items = sorted(summary.items(), key=lambda x: x[1], reverse=True)[:8]

    width, height = 620, 30 + len(items) * 26 + 20
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)

    margin_left, margin_right = 200, 50
    margin_top, margin_bottom = 15, 15
    chart_w = width - margin_left - margin_right
    chart_h = height - margin_top - margin_bottom

    max_count = max(v for _, v in items) if items else 1
    max_count = max(max_count, 1)

    row_h = chart_h / len(items)
    bar_h = row_h * 0.6
    font = _load_report_font(12)

    for i, (label, count) in enumerate(items):
        y0 = margin_top + i * row_h + (row_h - bar_h) / 2
        bar_w = int((count / max_count) * chart_w) if count > 0 else 2

        # Label (truncate to fit)
        short_label = label if len(label) <= 28 else label[:27] + "..."
        draw.text((margin_left - 195, y0), short_label, fill="black", font=font)

        # Bar
        draw.rectangle([margin_left, y0, margin_left + bar_w, y0 + bar_h], fill=(52, 152, 219))

        # Count
        draw.text((margin_left + bar_w + 6, y0), str(count), fill="black", font=font)

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_router():
    scan_id = request.values.get("scan_id")
    report_type = request.values.get("type", "pdf").lower()

    if not scan_id:
        return "scan_id missing", 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    try:
        c.execute("SELECT alerts FROM scans LIMIT 1")
    except sqlite3.OperationalError:
        try:
            c.execute("ALTER TABLE scans ADD COLUMN alerts TEXT")
            conn.commit()
        except:
            pass

    # ✅ Fetch both target and alerts
    c.execute("SELECT target, alerts FROM scans WHERE scan_id=?", (scan_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "Report not found", 404

    target = row[0]
    try:
        alerts = json.loads(row[1]) if row[1] else []
    except:
        alerts = []

    if not isinstance(alerts, list):
        alerts = []

    def get_short_description(a):
        alert_name = a.get("alert", "")
        desc = a.get("description", "")
        solution = a.get("solution", "")
        cves = a.get("cves") or []
        
        # 1. If CVEs exist, construct description from the CVE details
        if isinstance(cves, list) and len(cves) > 0:
            cve = cves[0]
            if isinstance(cve, dict):
                cve_id = cve.get("id") or "CVE"
                cve_title = cve.get("title") or ""
            else:
                cve_id = str(cve)
                cve_title = ""
            cve_title = " ".join(cve_title.split())
            cve_info = f" ({cve_title})" if cve_title else ""
            return f"This service is affected by a known vulnerability {cve_id}{cve_info}. Exploitation of this vulnerability could lead to unauthorized system access or denial of service. It is highly recommended to update the service to the latest secure version."

        # 2. Map standard/common alerts to high-quality, concise descriptions
        alert_lower = alert_name.lower()
        
        if "content security policy" in alert_lower or "csp" in alert_lower:
            return "The Content Security Policy (CSP) header is not configured on the web server. Without CSP, the site is vulnerable to Cross-Site Scripting (XSS) and data injection attacks. Implement a robust CSP header to restrict the sources of executable scripts and resources."
            
        if "http only site" in alert_lower or "insecure ssl/tls" in alert_lower:
            return "The website is accessible over unencrypted HTTP, transmitting all communication in cleartext. This allows attackers to perform man-in-the-middle attacks and intercept sensitive data like login credentials. Configure SSL/TLS encryption and redirect all HTTP traffic to HTTPS."
            
        if "clickjacking" in alert_lower or "x-frame-options" in alert_lower:
            return "The X-Frame-Options or CSP frame-ancestors header is missing from HTTP responses. This allows attackers to embed this site in an iframe on an external page and perform clickjacking attacks to trick users. Configure the X-Frame-Options header to 'SAMEORIGIN' or 'DENY'."
            
        if "x-content-type-options" in alert_lower:
            return "The X-Content-Type-Options header is missing, allowing web browsers to MIME-sniff the response content type. This could lead to security issues where user-uploaded files are executed as scripts. Configure the web server to send this header set to 'nosniff'."
            
        if "subdomain found" in alert_lower:
            return "An active subdomain was discovered during security reconnaissance. Exposing unmonitored subdomains increases the overall attack surface and may expose outdated services. Verify that this subdomain is authorized, monitored, and properly secured."
            
        if "technology fingerprint" in alert_lower or "server header" in alert_lower:
            return "The web server reveals software and version details in response headers (such as 'Server' or 'X-Powered-By'). Attackers use this fingerprinting information to identify potential exploits targeting your specific software versions. Configure your web server to hide or sanitize these headers."

        if "scanner core unavailable" in alert_lower:
            return "The ZAP vulnerability scanner core engine is not running on this server. This limits the depth of web application vulnerability scanning. Ensure that the ZAP daemon is correctly installed and active in the scanner's environment."

        if "retrieved from cache" in alert_lower:
            return "Sensitive web page responses might be stored in public or browser caches. This could allow unauthorized users to retrieve cached pages containing sensitive user-specific data. Configure cache control headers such as 'no-store' or 'private' to prevent caching."

        if "sample vulnerability" in alert_lower:
            return "A sample placeholder vulnerability was detected. This finding is used to demonstrate the report layout and severity distribution. Ensure all system components are correctly configured and real scans are conducted."

        # 3. Check if it's a port-related alert
        port_match = re.search(r'port\s+(\d+)', alert_lower)
        if port_match:
            port_num = int(port_match.group(1))
            # Look up in PORT_KNOWLEDGE_BASE
            base_profile = PORT_KNOWLEDGE_BASE.get(port_num)
            if base_profile:
                service = base_profile.get("service", "unknown service")
                rec = base_profile.get("recommendation", "restrict access")
                return f"An open network port was detected running the {service} service. Exposing services directly to the network increases the system's attack surface and can invite unauthorized access attempts. It is recommended to: {rec.lower()}."
            else:
                return f"An open network port ({port_num}) was detected on the target. Exposed network ports present potential entry points for attackers to probe and exploit services. Restrict access to this port using a firewall and disable the service if it is not required."

        # 4. If there's an existing description from ZAP or other scans, reuse/format it
        if desc and desc.strip():
            # Clean the description up to 1-2 sentences
            sentences = [s.strip() for s in re.split(r'\. |\? |\! ', desc) if s.strip()]
            short_desc = ". ".join(sentences[:2])
            if not short_desc.endswith('.'):
                short_desc += '.'
            # Add why it matters and what to do if not already present
            if solution:
                sol_text = solution.strip()
                sol_sentences = [s.strip() for s in re.split(r'\. |\? |\! ', sol_text) if s.strip()]
                sol_brief = sol_sentences[0] if sol_sentences else sol_text
                if not sol_brief.endswith('.'):
                    sol_brief += '.'
                return f"{short_desc} This can lead to unauthorized access or system compromise. To address this, you should: {sol_brief}"
            else:
                return f"{short_desc} This vulnerability can expose sensitive data or operations. Ensure proper input sanitization and secure configuration to remediate it."

        # 5. Default fallback
        fallback = f"A security finding was detected: {alert_name}."
        if solution:
            fallback += f" To address this issue, you should: {solution}."
        return fallback

    # ✅ Add First/Last Detection logic
    for a in alerts:
        a["last_detected"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        # Simple heuristic: find earlier scans for same target and same alert
        conn_hist = sqlite3.connect(DB_PATH)
        c_hist = conn_hist.cursor()
        c_hist.execute("SELECT date FROM scans WHERE target=? AND alerts LIKE ? ORDER BY id ASC LIMIT 1", 
                       (target, f'%"{a.get("alert")}"%'))
        first = c_hist.fetchone()
        conn_hist.close()
        a["first_flagged"] = first[0] if first else a["last_detected"]
        a["description"] = get_short_description(a)

    # Build a lookup of interpreted port severity values so the report Severity
    # column matches the View Scan page's Open Ports & Services table.
    # Port alerts are stored as "Info" in the raw scan data but the port
    # knowledge base resolves them to their real severity (Critical/High/
    # Medium/Low/Informational). Non-port findings keep their original value.
    port_severity_lookup = {}
    for pe in parse_port_entries(alerts):
        port_severity_lookup[pe["raw"]["path"]] = pe["risk"]

    def report_severity(a):
        """Resolve the displayed severity for a finding in report output.

        Uses the interpreted port severity for port alerts, falls back to the
        raw alert risk value, and normalizes 'Info' to 'Informational'.
        """
        raw = port_severity_lookup.get(a.get("path", ""), a.get("risk", ""))
        raw = (raw or "").strip()
        if raw.lower() in ("critical", "high", "medium", "low"):
            return raw
        if raw.lower() in ("info", "informational"):
            return "Informational"
        return raw or "Unknown"

    def sanitize_for_pdf(text):
        if not text: return ""
        # Replace common non-latin-1 characters
        replacements = {
            "\u2013": "-", # en dash
            "\u2014": "--", # em dash
            "\u2018": "'", # left single quote
            "\u2019": "'", # right single quote
            "\u201c": '"', # left double quote
            "\u201d": '"', # right double quote
            "\u2022": "*", # bullet
            "\u2026": "...", # ellipsis
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        return text.encode('latin-1', 'replace').decode('latin-1')

    # ================= PDF (ENTERPRISE UPGRADE) =================
    if report_type == "pdf":
        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            # Headers & Branding
            pdf.set_fill_color(15, 23, 42)
            pdf.rect(0, 0, 210, 40, 'F')
            pdf.set_font("Arial", "B", 24)
            pdf.set_text_color(56, 189, 248) # accent-primary
            pdf.text(10, 25, "VigiScan Vulnerability report")
            
            pdf.set_font("Arial", "", 10)
            pdf.set_text_color(255, 255, 255)
            pdf.text(10, 32, sanitize_for_pdf(f"Target: {target} | Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"))
            
            pdf.ln(45)

            # 1. Executive Summary
            pdf.set_font("Arial", "B", 16)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 10, "1. Executive Summary", ln=True)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
            
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 7, sanitize_for_pdf(f"This professional security assessment was performed against {target}. The analysis identifies vulnerabilities across multiple categories, including OWASP Top 10 mapping and severity-based prioritization."))
            
            pdf.ln(5)
            # Summary Stats
            total = len(alerts)
            high = len([a for a in alerts if a.get("risk") == "High"])
            med = len([a for a in alerts if a.get("risk") == "Medium"])
            
            # Severity Distribution Chart
            try:
                sev_chart = _severity_chart_png(alerts, report_severity)
                if sev_chart:
                    pdf.image(sev_chart, x=10, w=180)
                    pdf.ln(5)
            except Exception:
                pass
            
            # Open Ports & Services Chart
            try:
                ports_chart = _ports_chart_png(alerts)
                if ports_chart:
                    pdf.ln(3)
                    pdf.set_font("Arial", "B", 12)
                    pdf.set_text_color(15, 23, 42)
                    pdf.cell(0, 8, "Open Ports & Services Summary", ln=True)
                    pdf.ln(3)
                    pdf.image(ports_chart, x=10, w=180)
                    pdf.ln(5)
            except Exception:
                pass

            # 2. Technical Findings
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "2. Technical Findings & OWASP Mapping", ln=True)
            pdf.ln(5)

            for i, a in enumerate(alerts, start=1):
                if pdf.get_y() > 250: pdf.add_page()
                
                severity = sanitize_for_pdf(report_severity(a))
                alert_name = sanitize_for_pdf(a.get("alert", ""))
                owasp_cat = sanitize_for_pdf(map_to_owasp(a.get("alert", "")))
                
                pdf.set_x(10)
                pdf.set_font("Arial", "B", 11)
                pdf.set_fill_color(241, 245, 249)
                pdf.cell(190, 8, f" {i}. {alert_name} [{severity}]", fill=True)
                pdf.ln(8)
                
                pdf.set_x(10)
                pdf.set_font("Arial", "I", 9)
                pdf.set_text_color(100, 100, 100)
                pdf.cell(190, 6, f"   OWASP Category: {owasp_cat}")
                pdf.ln(6)
                
                pdf.set_font("Arial", "", 9)
                pdf.set_text_color(0, 0, 0)
                pdf.set_x(10)
                try:
                    pdf.multi_cell(190, 5, sanitize_for_pdf(f"   Description: {a.get('description', 'N/A')}"))
                except:
                    pass
                
                pdf.set_font("Arial", "B", 9)
                pdf.set_x(10)
                try:
                    pdf.multi_cell(190, 5, sanitize_for_pdf(f"   Remediation: {a.get('solution', 'N/A')}"))
                except:
                    pass
                pdf.ln(5)

            pdf_bytes = pdf.output(dest='S')
            # fpdf2 may return str or bytes depending on version; normalize to bytes
            if isinstance(pdf_bytes, str):
                pdf_bytes = pdf_bytes.encode('latin-1')
            response = make_response(pdf_bytes)
            response.headers["Content-Type"] = "application/pdf"
            response.headers["Content-Disposition"] = f"attachment; filename=VigiScan_{target}_Report.pdf"
            return response
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            return f"PDF Generation Error: {str(e)}<br><pre>{error_trace}</pre>", 500

    # ================= EXCEL EXPORT (ADDED) =================
    elif report_type == "excel":
        rows = []
        for a in alerts:
            rows.append({
                "Vulnerability Title": a.get("alert", ""),
                "Severity": report_severity(a),
                "Vulnerability Path": a.get("path", ""),
                "Solution": a.get("solution", "")
            })

        df = pd.DataFrame(rows)
        file_path = f"VigiScan_Report_{scan_id}.xlsx"
        df.to_excel(file_path, index=False)

        return send_file(file_path, as_attachment=True, download_name="VigiScan_Report.xlsx")

    # ================= CSV EXPORT (ADDED) =================
    elif report_type == "csv":
        rows = []
        for a in alerts:
            rows.append({
                "Vulnerability Title": a.get("alert", ""),
                "Severity": report_severity(a),
                "Vulnerability Path": a.get("path", ""),
                "Solution": a.get("solution", "")
            })

        df = pd.DataFrame(rows)
        file_path = f"VigiScan_Report_{scan_id}.csv"
        df.to_csv(file_path, index=False)

        return send_file(file_path, as_attachment=True, download_name="VigiScan_Report.csv")

    # ================= HTML EXPORT (ADDED & COLORFUL WITH LINES) =================
    elif report_type == "html":
        rows_html = ""
        for a in alerts:
            severity = report_severity(a)
            severity_class = "severity-low"
            if severity == "Critical": severity_class = "severity-critical"
            elif severity == "High": severity_class = "severity-high"
            elif severity == "Medium": severity_class = "severity-medium"
            elif severity == "Informational": severity_class = "severity-info"
            
            desc_text = a.get('description', '')
            desc_html = f'<div style="font-size: 9px; color: #555; margin-top: 4px; line-height: 1.3;"><strong>Description:</strong> {desc_text}</div>' if desc_text else ''
            
            rows_html += f"""
                <tr>
                    <td>
                        <strong>{a.get('alert', '')}</strong>
                        {desc_html}
                    </td>
                    <td class='{severity_class}'>{severity}</td>
                    <td>{a.get('first_flagged', '')}</td>
                    <td>{a.get('last_detected', '')}</td>
                    <td>{a.get('solution', '')}</td>
                </tr>"""

        # --- Severity Distribution Chart (CSS bars) ---
        sev_counts = _severity_distribution(alerts, report_severity)
        sev_max = max(sev_counts.values()) if sev_counts else 1
        sev_max = max(sev_max, 1)
        sev_colors = {
            "Critical": "#dc2626",
            "High": "#e74c3c",
            "Medium": "#f39c12",
            "Low": "#27ae60",
            "Informational": "#38bdf8",
        }
        sev_chart_html = ""
        for label in ["Critical", "High", "Medium", "Low", "Informational"]:
            count = sev_counts[label]
            pct = int((count / sev_max) * 100) if count > 0 else 0
            sev_chart_html += f"""
                <div class="chart-row">
                    <span class="chart-label">{label}</span>
                    <div class="chart-track">
                        <div class="chart-bar" style="width:{pct}%;background:{sev_colors[label]};">{count}</div>
                    </div>
                </div>"""

        # --- Open Ports & Services Chart (CSS bars) ---
        port_summary = _port_summary(alerts)
        ports_chart_html = ""
        if port_summary:
            port_items = sorted(port_summary.items(), key=lambda x: x[1], reverse=True)[:10]
            port_max = max(v for _, v in port_items) if port_items else 1
            port_max = max(port_max, 1)
            for label, count in port_items:
                pct = int((count / port_max) * 100) if count > 0 else 0
                ports_chart_html += f"""
                <div class="chart-row">
                    <span class="chart-label">{label}</span>
                    <div class="chart-track">
                        <div class="chart-bar chart-port" style="width:{pct}%;">{count}</div>
                    </div>
                </div>"""
        else:
            ports_chart_html = "<p><em>No open ports/services detected in this scan.</em></p>"

        html_content = f"""
        <html>
        <head>
            <title>VigiScan Report</title>
            <style>
                body {{ font-family: Verdana, sans-serif; background: #f4f4f9; color: #333; padding: 20px; }}
                h2 {{ text-align: center; color: #2c3e50; margin-bottom: 20px; font-size: 20px; }} /* ✅ Reduced from 24px? to 20px */
                table {{ width: 100%; border-collapse: collapse; background: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
                th {{ background: #3498db; color: white; padding: 10px; font-size: 14px; }}
                td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 10px; }} /* ✅ Reduced from 12? to 10 */
                .severity-critical {{ color: #dc2626; font-weight: bold; }}
                .severity-high {{ color: #e74c3c; font-weight: bold; }}
                .severity-medium {{ color: #f39c12; font-weight: bold; }}
                .severity-low {{ color: #27ae60; font-weight: bold; }}
                .severity-info {{ color: #38bdf8; font-weight: bold; }}
                .chart-container {{ background: #ffffff; padding: 15px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                .chart-container h3 {{ margin-top: 0; color: #2c3e50; font-size: 16px; }}
                .chart-row {{ display: flex; align-items: center; margin-bottom: 8px; }}
                .chart-label {{ width: 140px; font-size: 12px; color: #555; text-align: right; padding-right: 10px; }}
                .chart-track {{ flex: 1; background: #f0f0f0; border-radius: 4px; height: 24px; position: relative; }}
                .chart-bar {{ height: 24px; border-radius: 4px; color: white; font-size: 12px; line-height: 24px; text-align: center; min-width: 24px; }}
                .chart-port {{ background: #3498db; }}
            </style>
        </head>
        <body>
            <h2>🛡️ VigiScan Security Report</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="chart-container">
                <h3>Vulnerability Severity Distribution</h3>
                {sev_chart_html}
            </div>
            <div class="chart-container">
                <h3>Open Ports & Services</h3>
                {ports_chart_html}
            </div>
            <table>
                <tr><th>Vulnerability Title</th><th>Severity</th><th>First Seen</th><th>Last Seen</th><th>Solution</th></tr>
                {rows_html}
            </table>
        </body>
        </html>
        """

        response = make_response(html_content)
        response.headers["Content-Type"] = "text/html"
        response.headers["Content-Disposition"] = "attachment; filename=VigiScan_Report.html"

        return response

    return "Invalid report type", 400


# ================= MULTI-PAGE ROUTES =================
def get_user_lang():
    """Helper to get the current user's language preference."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT settings FROM users WHERE username=?", (session.get("user"),))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            settings_data = json.loads(row[0])
            return settings_data.get("language", "en")
    except:
        pass
    return "en"

@app.route('/history-page')
@login_required
def history_page():
    return render_template("history.html", user=session.get("user"), user_lang=get_user_lang(), active_page="history")

@app.route('/assets')
@login_required
def assets_page():
    return render_template("assets.html", user=session.get("user"), user_lang=get_user_lang(), active_page="assets")

@app.route('/assets/<int:asset_id>')
@login_required
def asset_detail_page(asset_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, ip, domain, owner, environment, criticality, is_internet_facing, asset_group FROM assets WHERE id=?", (asset_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("Asset not found.", "danger")
        return redirect('/assets')
    asset = {
        "id": row[0], "name": row[1], "ip": row[2], "domain": row[3],
        "owner": row[4], "environment": row[5], "criticality": row[6],
        "is_internet_facing": bool(row[7]), "asset_group": row[8]
    }
    return render_template("asset_detail.html", user=session.get("user"), user_lang=get_user_lang(), active_page="assets", asset=asset)

@app.route('/scans')
@login_required
def scans_page():
    scan_type = request.args.get('type', '')
    return render_template("scans.html", user=session.get("user"), user_lang=get_user_lang(), active_page="scans", scan_type=scan_type)

@app.route('/scans/<scan_id>')
@login_required
def scan_detail_page(scan_id):
    # Try in-memory first, then DB
    job = SCAN_JOBS.get(scan_id)
    scan_data = None
    if job:
        scan_data = {
            "scan_id": scan_id,
            "target": job.get("target", ""),
            "status": job.get("status", ""),
            "profile": job.get("profile", "deep"),
            "alerts": job.get("alerts", []),
            "fixed": job.get("fixed", []),
            "date": job.get("created", ""),
            "current_phase": job.get("current_phase", ""),
            "is_live": job.get("status") not in ["Completed", "Terminated", "Not Found"]
        }
    else:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT scan_id, target, date, alerts, profile, status, current_phase, fixed, user FROM scans WHERE scan_id=?", (scan_id,))
        row = c.fetchone()
        conn.close()
        if row:
            try:
                alerts = json.loads(row[3]) if row[3] else []
            except:
                alerts = []
            try:
                fixed = json.loads(row[7]) if row[7] else []
            except:
                fixed = []
            scan_data = {
                "scan_id": row[0],
                "target": row[1],
                "date": row[2],
                "alerts": alerts,
                "profile": row[4],
                "status": row[5],
                "current_phase": row[6],
                "fixed": fixed,
                "user": row[8],
                "is_live": False
            }
    if not scan_data:
        flash("Scan not found.", "danger")
        return redirect('/scans')

    # Parse the existing Nmap port alerts into a structured table.
    # Raw scan data remains untouched in scan.alerts for technical details.
    port_entries = parse_port_entries(scan_data.get("alerts", []))
    port_entries.sort(key=lambda p: p["port"])

    return render_template("scan_detail.html", user=session.get("user"), user_lang=get_user_lang(), active_page="scans", scan=scan_data, port_entries=port_entries)

@app.route('/vulnerabilities')
@login_required
def vulnerabilities_page():
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    return render_template("vulnerabilities.html", user=session.get("user"), user_lang=get_user_lang(), active_page="vulnerabilities", filter_severity=severity, filter_status=status)

@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
def vulnerability_detail_page(vuln_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT v.id, v.scan_id, v.asset_id, v.name, v.severity, v.risk_score, v.status, v.cvss_score, v.exposure, v.compliance_tags, v.date_found, v.last_seen, a.name, a.ip, a.domain, a.criticality
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        WHERE v.id=?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("Vulnerability not found.", "danger")
        return redirect('/vulnerabilities')
    
    try:
        compliance_tags = json.loads(row[9]) if row[9] else []
    except:
        compliance_tags = []
    
    vuln = {
        "id": row[0], "scan_id": row[1], "asset_id": row[2], "name": row[3],
        "severity": row[4], "risk_score": row[5], "status": row[6],
        "cvss_score": row[7], "exposure": row[8], "compliance_tags": compliance_tags,
        "date_found": row[9], "last_seen": row[10],
        "asset_name": row[11], "asset_ip": row[12], "asset_domain": row[13],
        "asset_criticality": row[14]
    }
    
    # Get scan alerts for this vulnerability to find evidence
    evidence = None
    if vuln["scan_id"]:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT alerts FROM scans WHERE scan_id=?", (vuln["scan_id"],))
        scan_row = c.fetchone()
        conn.close()
        if scan_row and scan_row[0]:
            try:
                alerts = json.loads(scan_row[0])
                for a in alerts:
                    if a.get("alert") == vuln["name"]:
                        evidence = a
                        break
            except:
                pass
    
    # Get CVE info from evidence
    cves = []
    if evidence and evidence.get("cves"):
        cves = evidence["cves"]
    
    # Get remediation
    remediation = get_remediation(vuln["name"])
    
    # Get OWASP mapping
    owasp = map_to_owasp(vuln["name"])
    
    # Get MITRE ATT&CK mapping (heuristic)
    mitre = []
    name_lower = vuln["name"].lower()
    if "sql" in name_lower or "injection" in name_lower:
        mitre = [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]
    elif "xss" in name_lower or "cross" in name_lower:
        mitre = [{"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"}]
    elif "auth" in name_lower or "login" in name_lower:
        mitre = [{"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"}]
    elif "config" in name_lower or "misconfig" in name_lower:
        mitre = [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}]
    elif "port" in name_lower or "service" in name_lower:
        mitre = [{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}]
    elif "ssl" in name_lower or "tls" in name_lower or "certificate" in name_lower:
        mitre = [{"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"}]
    else:
        mitre = [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}]
    
    return render_template("vulnerability_detail.html", user=session.get("user"), user_lang=get_user_lang(), active_page="vulnerabilities", vuln=vuln, evidence=evidence, cves=cves, remediation=remediation, owasp=owasp, mitre=mitre)

@app.route('/reports')
@login_required
def reports_page():
    report_type = request.args.get('type', '')
    return render_template("reports.html", user=session.get("user"), user_lang=get_user_lang(), active_page="reports", report_type=report_type)

@app.route('/schedules')
@login_required
def schedules_page():
    return render_template("schedules.html", user=session.get("user"), user_lang=get_user_lang(), active_page="schedules")

@app.route('/risk')
@login_required
def risk_page():
    return render_template("risk.html", user=session.get("user"), user_lang=get_user_lang(), active_page="risk")

@app.route('/knowledge-base')
@login_required
def knowledge_base_page():
    return render_template("knowledge_base.html", user=session.get("user"), user_lang=get_user_lang(), active_page="knowledge")

@app.route('/api/asset/<int:asset_id>')
@login_required
def get_asset_detail(asset_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, ip, domain, owner, environment, criticality, is_internet_facing, asset_group FROM assets WHERE id=?", (asset_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Asset not found"}), 404
    return jsonify({
        "id": row[0], "name": row[1], "ip": row[2], "domain": row[3],
        "owner": row[4], "environment": row[5], "criticality": row[6],
        "is_internet_facing": bool(row[7]), "asset_group": row[8]
    })

@app.route('/api/asset/<int:asset_id>', methods=['PUT'])
@login_required
def update_asset(asset_id):
    data = request.json
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM assets WHERE id=?", (asset_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "Asset not found"}), 404
    
    name = data.get("name", "")
    target = data.get("target", "")
    env = data.get("env", "")
    criticality = data.get("criticality", "Medium")
    internet = 1 if data.get("internet") else 0
    
    ip = target if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target) else None
    domain = target if not ip else None
    
    c.execute("UPDATE assets SET name=?, ip=?, domain=?, environment=?, criticality=?, is_internet_facing=? WHERE id=?",
              (name, ip, domain, env, criticality, internet, asset_id))
    conn.commit()
    conn.close()
    log_activity(session.get("user"), "UPDATE_ASSET", f"Updated asset: {name}")
    return jsonify({"message": "Asset updated"})

@app.route('/api/vulnerability/<int:vuln_id>')
@login_required
def get_vulnerability_detail(vuln_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT v.id, v.scan_id, v.asset_id, v.name, v.severity, v.risk_score, v.status, v.cvss_score, v.exposure, v.compliance_tags, v.date_found, v.last_seen, a.name
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        WHERE v.id=?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Vulnerability not found"}), 404
    try:
        compliance_tags = json.loads(row[9]) if row[9] else []
    except:
        compliance_tags = []
    return jsonify({
        "id": row[0], "scan_id": row[1], "asset_id": row[2], "name": row[3],
        "severity": row[4], "risk_score": row[5], "status": row[6],
        "cvss_score": row[7], "exposure": row[8], "compliance_tags": compliance_tags,
        "date_found": row[9], "last_seen": row[10], "asset_name": row[11]
    })

@app.route('/api/cve/search')
@login_required
def cve_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    # Use the existing lookup_cves function
    cves = lookup_cves(query, "")
    return jsonify(cves)

@app.route('/api/risk/overview')
@login_required
def risk_overview():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Total vulnerabilities by severity
    c.execute("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")
    by_severity = {r[0]: r[1] for r in c.fetchall()}
    
    # By status
    c.execute("SELECT status, COUNT(*) FROM vulnerabilities GROUP BY status")
    by_status = {r[0]: r[1] for r in c.fetchall()}
    
    # By asset
    c.execute("""
        SELECT a.id, a.name, COUNT(v.id) as cnt, SUM(v.risk_score) as total_risk
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        GROUP BY a.id
        ORDER BY total_risk DESC NULLS LAST
        LIMIT 10
    """)
    by_asset = [{"id": r[0], "name": r[1] or "Unknown", "count": r[2], "risk": r[3] or 0} for r in c.fetchall()]
    
    # Highest risk vulnerabilities
    c.execute("""
        SELECT v.id, v.name, v.risk_score, v.severity, a.name
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        ORDER BY v.risk_score DESC
        LIMIT 10
    """)
    highest_risk = [{"id": r[0], "name": r[1], "risk_score": r[2], "severity": r[3], "asset": r[4]} for r in c.fetchall()]
    
    # Total assets
    c.execute("SELECT COUNT(*) FROM assets")
    total_assets = c.fetchone()[0]
    
    # Total scans
    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "by_severity": by_severity,
        "by_status": by_status,
        "by_asset": by_asset,
        "highest_risk": highest_risk,
        "total_assets": total_assets,
        "total_scans": total_scans,
        "total_vulnerabilities": sum(by_severity.values())
    })

# ================= RUN =================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
