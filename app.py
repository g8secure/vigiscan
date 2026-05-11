import sqlite3
from flask import Flask, render_template, request, redirect, session, jsonify, flash, send_file, make_response
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

app = Flask(__name__)
# Use env var in production; fallback only for local dev
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')
app.permanent_session_lifetime = timedelta(minutes=10)

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
                "INSERT INTO users (username,password,otp_secret,is_admin) VALUES (?,?,?,?)",
                (username, password, otp_secret, 1 if is_first_user else 0)
            )
            conn.commit()
            return redirect('/login')

        except:
            flash("Username exists", "danger")

        finally:
            conn.close()

    return render_template("register.html")


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

    return render_template("dashboard.html", user=session.get("user", "Guest"), user_lang=user_lang)

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

    return render_template("profile.html", username=user[0], role="Admin" if user[1] else "User")

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
    return render_template("admin.html", user=session.get("user"))


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
zap = ZAPv2(
    apikey='',
    proxies={'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
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

        if use_zap_ascan:
            job["current_phase"] = "Active Scan"
            ascan_id = zap.ascan.scan(target)
            while int(zap.ascan.status(ascan_id)) < 100:
                if job.get("terminated"):
                    job["status"] = "Terminated"
                    return
                job["active"] = int(zap.ascan.status(ascan_id))
                job["progress"] = 60 + int(job["active"] * 0.4)
                time.sleep(1)
            job["active"] = 100

        # Cleanup Auth Rule
        try:
            zap.replacer.remove_rule("AuthHeader")
        except:
            pass

        # Collect results if ZAP was used at all
        if profile != "targeted_ports" and (use_zap_spider or use_zap_ascan):
            zap_alerts = zap.core.alerts(baseurl=target)
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
    return render_template("settings.html", user=session.get("user"), twofa_enabled=twofa_enabled)
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
        pdf.multi_cell(0, 7, sanitize_for_pdf(f"This professional security assessment was performed against {target}. The analysis identifies vulnerabilities across multiple categories, including OWASP Top 10 mapping and risk-based prioritization."))
        
        pdf.ln(5)
        # Summary Stats
        total = len(alerts)
        high = len([a for a in alerts if a.get("risk") == "High"])
        med = len([a for a in alerts if a.get("risk") == "Medium"])
        
        # DRAW SIMPLE BAR CHART
        pdf.set_font("Arial", "B", 10)
        pdf.cell(40, 10, f"Critical/High Alerts: {high}")
        pdf.set_fill_color(231, 76, 60)
        pdf.rect(50, pdf.get_y() + 2, max(2, high * 5), 6, 'F')
        pdf.ln(8)
        
        pdf.cell(40, 10, f"Medium Alerts: {med}")
        pdf.set_fill_color(243, 156, 18)
        pdf.rect(50, pdf.get_y() + 2, max(2, med * 5), 6, 'F')
        pdf.ln(10)

        # 2. Technical Findings
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "2. Technical Findings & OWASP Mapping", ln=True)
        pdf.ln(5)

        for i, a in enumerate(alerts, start=1):
            if pdf.get_y() > 250: pdf.add_page()
            
            risk = a.get("risk", "Info")
            alert_name = sanitize_for_pdf(a.get("alert", ""))
            owasp_cat = sanitize_for_pdf(map_to_owasp(a.get("alert", "")))
            
            pdf.set_font("Arial", "B", 11)
            pdf.set_fill_color(241, 245, 249)
            pdf.cell(0, 8, f" {i}. {alert_name} [{risk}]", ln=True, fill=True)
            
            pdf.set_font("Arial", "I", 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 6, f"   OWASP Category: {owasp_cat}", ln=True)
            
            pdf.set_font("Arial", "", 9)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 5, sanitize_for_pdf(f"   Description: {a.get('description', 'N/A')}"))
            pdf.set_font("Arial", "B", 9)
            pdf.multi_cell(0, 5, sanitize_for_pdf(f"   Remediation: {a.get('solution', 'N/A')}"))
            pdf.ln(5)

        response = make_response(pdf.output(dest='S').encode('latin-1', 'replace'))
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"attachment; filename=VigiScan_{target}_Report.pdf"
        return response

    # ================= EXCEL EXPORT (ADDED) =================
    elif report_type == "excel":
        rows = []
        for a in alerts:
            rows.append({
                "Alert": a.get("alert", ""),
                "Risk": a.get("risk", ""),
                "URL": a.get("path", ""),
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
                "Alert": a.get("alert", ""),
                "Risk": a.get("risk", ""),
                "URL": a.get("path", ""),
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
            risk_class = "risk-low"
            if a.get("risk") == "High": risk_class = "risk-high"
            elif a.get("risk") == "Medium": risk_class = "risk-medium"
            rows_html += f"""
                <tr>
                    <td>{a.get('alert', '')}</td>
                    <td class='{risk_class}'>{a.get('risk', '')}</td>
                    <td>{a.get('first_flagged', '')}</td>
                    <td>{a.get('last_detected', '')}</td>
                    <td>{a.get('solution', '')}</td>
                </tr>"""

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
                .risk-high {{ color: #e74c3c; font-weight: bold; }}
                .risk-medium {{ color: #f39c12; font-weight: bold; }}
                .risk-low {{ color: #27ae60; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h2>🛡️ VigiScan Security Report</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <table>
                <tr><th>Alert</th><th>Risk</th><th>First Seen</th><th>Last Seen</th><th>Solution</th></tr>
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


# ================= RUN =================
if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV', 'production') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0')