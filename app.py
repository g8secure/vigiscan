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

@app.context_processor
def inject_user_language():
    user_lang = "en"
    if session.get("user"):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT settings FROM users WHERE username=?", (session.get("user"),))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            try:
                settings_data = json.loads(row[0])
                user_lang = settings_data.get("language", "en")
            except:
                user_lang = "en"

    lang_strings = LANGUAGES.get(user_lang, LANGUAGES.get("en", {}))
    return {"user_lang": user_lang, "lang_strings": lang_strings}

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

    return render_template("dashboard.html", user=session.get("user", "Guest"), user_lang=user_lang)

@app.route('/assets')
@login_required
def assets():
    return render_template("assets.html", user=session.get("user"))

@app.route('/assets/<int:asset_id>')
@login_required
def asset_detail(asset_id):
    return render_template("asset_detail.html", user=session.get("user"), asset_id=asset_id)

@app.route('/scans')
@login_required
def scans():
    return render_template("scans.html", user=session.get("user"))

@app.route('/scans/new')
@login_required
def scan_new():
    return render_template("scan_new.html", user=session.get("user"))

@app.route('/scans/authenticated')
@login_required
def scan_authenticated():
    return render_template("scan_authenticated.html", user=session.get("user"))

@app.route('/scans/<scan_id>')
@login_required
def scan_detail(scan_id):
    return render_template("scan_detail.html", user=session.get("user"), scan_id=scan_id)

@app.route('/vulnerabilities')
@login_required
def vulnerabilities():
    return render_template("vulnerabilities.html", user=session.get("user"))

@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
def vulnerability_detail(vuln_id):
    return render_template("vulnerability_detail.html", user=session.get("user"), vuln_id=vuln_id)

@app.route('/reports')
@login_required
def reports():
    return render_template("reports.html", user=session.get("user"))

@app.route('/schedules')
@login_required
def schedules():
    return render_template("schedules.html", user=session.get("user"))

@app.route('/risk')
@login_required
def risk():
    return render_template("risk.html", user=session.get("user"))

@app.route('/knowledge-base')
@login_required
def knowledge_base():
    return render_template("knowledge_base.html", user=session.get("user"))

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
    c.execute("SELECT id, name, ip, domain, owner, environment, criticality, is_internet_facing FROM assets")
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {
            "id": r[0], "name": r[1], "target": r[2] or r[3],
            "owner": r[4], "environment": r[5], "criticality": r[6], "internet_facing": bool(r[7])
        }
        for r in rows
    ])

@app.route('/api/assets/<int:asset_id>')
@login_required
def get_asset(asset_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, ip, domain, owner, environment, criticality, is_internet_facing FROM assets WHERE id=?", (asset_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Asset not found"}), 404
    return jsonify({
        "id": row[0],
        "name": row[1],
        "target": row[2] or row[3],
        "owner": row[4], "environment": row[5],
        "criticality": row[6], "internet_facing": bool(row[7])
    })

@app.route('/api/assets/<int:asset_id>', methods=['PUT'])
@login_required
def update_asset(asset_id):
    data = request.json or {}
    name = data.get('name')
    target = data.get('target')
    env = data.get('environment')
    criticality = data.get('criticality')
    internet = 1 if data.get('internet') else 0

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT owner FROM assets WHERE id=?", (asset_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Asset not found"}), 404

    owner = row[0]
    if owner != session.get('user') and not session.get('is_admin'):
        conn.close()
        return jsonify({"error": "Permission denied"}), 403

    ip = target if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target) else None
    domain = target if not ip else None
    c.execute("UPDATE assets SET name=?, ip=?, domain=?, environment=?, criticality=?, is_internet_facing=? WHERE id=?",
              (name, ip, domain, env, criticality, internet, asset_id))
    conn.commit()
    conn.close()

    log_activity(session.get('user'), 'UPDATE_ASSET', f'Updated asset {asset_id} ({name})')
    return jsonify({"message": "Asset updated"})

@app.route('/api/assets/<int:asset_id>', methods=['DELETE'])
@login_required
def delete_asset_by_id(asset_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT owner FROM assets WHERE id=?", (asset_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Asset not found"}), 404

    owner = row[0]
    if owner != session.get('user') and not session.get('is_admin'):
        conn.close()
        return jsonify({"error": "Permission denied"}), 403

    c.execute("DELETE FROM assets WHERE id=?", (asset_id,))
    conn.commit()
    conn.close()
    log_activity(session.get('user'), 'DELETE_ASSET', f'Deleted asset {asset_id}')
    return jsonify({"message": "Asset deleted"})

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
        SELECT v.id, v.name, v.severity, v.risk_score, v.status, v.date_found, a.name, v.scan_id, v.asset_id
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        ORDER BY v.risk_score DESC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {
            "id": r[0], "alert": r[1], "risk": r[2], "risk_score": r[3],
            "status": r[4], "date_found": r[5], "asset_name": r[6], "scan_id": r[7], "asset_id": r[8],
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
    "en": {
        "dashboard": "Dashboard",
        "start_scan": "Start Scan",
        "history": "History",
        "alerts": "Alerts",
        "assets": "Asset Inventory",
        "reports": "Reports",
        "schedules": "Schedules",
        "risk": "Risk",
        "knowledge": "Knowledge Base",
        "administration": "Administration",
        "settings": "Settings",
        "logout": "Logout",
        "profile": "Profile",
        "new_scan": "+ NEW SCAN",
        "help": "?",
        "security_overview_title": "Security Operations Overview",
        "security_overview_description": "Monitor scan activity, asset status, and vulnerability trends in one place.",
        "launch_scan": "Launch Scan",
        "recent_scan_history": "Recent Scan History",
        "notifications": "Notifications",
        "trend_summary": "Trend Summary",
        "loading_latest_scans": "Loading latest scans...",
        "no_recent_scans": "No recent scans available.",
        "no_notifications": "No notifications yet.",
        "unable_load_history": "Unable to load scan history.",
            "loading_scan_history": "Loading scan history...",
        "unable_load_notifications": "Unable to load notifications.",
        "unable_load_trends": "Unable to load trends.",
        "history_page_heading": "Scan History",
        "history_page_description": "Review completed and scheduled scan activity across your account.",
        "back_to_dashboard": "Back to Dashboard",
        "scan_id": "Scan ID",
        "target": "Target",
        "date": "Date",
        "status": "Status",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "loading_history": "Loading scan history...",
        "no_scan_history": "No scan history available.",
        "profile_label": "Profile",
        "logged_in_as": "Logged in as:",
        "twofa_status": "Two-Factor Status:",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "new_password": "New Password",
        "preferred_language": "Preferred Language",
        "enable_mfa": "Enable Multi-Factor Authentication (MFA)",
        "apply_configuration": "Apply Configuration",
        "settings_updated": "Settings updated successfully!",
        "id_label": "ID",
        "name_label": "Name",
        "asset_id_label": "Asset ID",
        "vulnerability_id_label": "Vulnerability ID",
            "scan_id_label": "Scan ID",
        "risk_score_label": "Risk Score",
        "alert_label": "Alert",
            "severity_label": "Severity",
        "count_label": "Count",
        "related_vulnerabilities": "Related Vulnerabilities",
        "loading_related_vulnerabilities": "Loading related vulnerabilities...",
        "no_related_vulnerabilities": "No related vulnerabilities found.",
        "unable_load_asset_details": "Unable to load asset details.",
        "back_to_assets": "Back to Assets",
        "save_asset": "Save Asset",
        "save_changes": "Save Changes",
        "edit_asset": "Edit Asset",
        "delete_asset": "Delete Asset",
        "delete_asset_confirm": "Delete this asset? This cannot be undone.",
        "unable_delete_asset": "Unable to delete asset.",
            "unable_update_asset": "Unable to update asset.",
        "could_not_save_asset": "Unable to save asset.",
        "asset_name": "Asset Name",
            "asset": "Asset",
        "target_address": "Target Address",
        "environment": "Environment",
        "criticality": "Criticality",
        "internet_facing": "Internet Facing",
            "add_asset_title": "Add New Asset",
            "add_asset_description": "Create a new asset record to include it in scan inventories.",
            "asset_details_description": "Review the asset profile, risk context, and associated scan findings.",
            "asset_name_placeholder": "Database server",
            "target_address_placeholder": "192.168.1.10 or app.example.com",
            "environment_placeholder": "Production, Staging, DMZ",
            "low_label": "Low",
            "high_label": "High",
            "critical_label": "Critical",
            "yes_label": "Yes",
            "no_label": "No",
        "loading_remediation_details": "Loading remediation details...",
        "remediation_guidance": "Remediation Guidance",
        "vulnerability_detail_description": "Review vulnerability context, asset association, and remediation guidance.",
            "vulnerability_detail_title": "Vulnerability Details",
        "back_to_vulnerabilities": "Back to Vulnerabilities",
        "vulnerability_not_found": "Vulnerability not found.",
        "unable_load_vulnerability_details": "Unable to load vulnerability details.",
        "refer_scan_report": "Refer to the scan report for remediation details.",
        "review_vendor_guidance": "Review vendor guidance and apply secure configuration changes.",
        "scan_details_title": "Scan Details",
        "scan_details_description": "Detailed view of scan results, alerts, and remediation status.",
        "back_to_scans": "Back to Scans",
        "alert_breakdown": "Alert Breakdown",
        "loading_alert_breakdown": "Loading alert breakdown...",
        "scan_record_not_found": "Scan record not found.",
        "unable_load_scan_details": "Unable to load scan details.",
        "scheduled_scans_title": "Scheduled Scans",
        "scheduled_scans_description": "Manage recurring and one-time scan jobs for your environment.",
        "create_schedule": "Create Schedule",
        "schedule_id": "Schedule ID",
        "next_run": "Next Run",
        "no_schedules_configured": "No schedules configured.",
        "unable_load_schedules": "Unable to load schedules.",
            "loading_schedules": "Loading schedules...",
        "active_status": "Active",
        "paused_status": "Paused",
        "scan_management_title": "Scan Management",
            "scans_title": "Scans",
            "alerts_label": "Alerts",
            "medium_label": "Medium",
            "unable_load_scan_history": "Unable to load scan history.",
        "review_active_jobs": "Review active jobs and historical scan results.",
        "no_scan_records_found": "No scan records found.",
        "delete_user_confirm": "Are you sure you want to delete this user?",
        "delete_button": "Delete",
        "make_admin_button": "Make Admin",
        "remove_admin_button": "Remove Admin",
        "user_role": "Role",
            "username_label": "Username",
        "actions_label": "Actions",
        "admin_panel_title": "Admin Panel",
        "admin_panel_description": "Manage users, roles, and privileged administration tasks from a centralized view.",
        "open_vulns": "Open Vulnerabilities",
        "active_jobs": "Active Jobs",
        "loading_notifications": "Loading notifications...",
        "no_next_run": "No next run",
        "settings_description": "Update your password and manage account security settings including 2FA.",
        "total_assets": "Total Assets",
        "total_scans": "Total Scans",
        "unknown": "Unknown"
    },
    "uk_en": {
        "dashboard": "Dashboard",
        "start_scan": "Commence Scan",
        "history": "Past Assessments",
        "alerts": "Vulnerabilities",
        "assets": "Asset Register",
        "reports": "Reports",
        "schedules": "Schedules",
        "risk": "Risk",
        "knowledge": "Knowledge Base",
        "administration": "Administration",
        "settings": "Settings",
        "logout": "Logout",
        "profile": "Profile",
        "new_scan": "+ NEW SCAN",
        "help": "?",
        "topbar_subtitle": "Vulnerability management platform",
        "asset_inventory_title": "Asset Register",
        "asset_inventory_description": "Track assets, hosting, and criticality across your environment.",
        "add_new_asset": "Add New Asset",
        "loading_assets": "Loading assets...",
        "no_assets_found": "No assets found.",
        "unable_load_assets": "Unable to load assets.",
        "report_center_title": "Report Center",
        "report_center_description": "Generate exportable PDF, HTML, Excel, and CSV reports from recent scan results.",
        "open_scan_history": "Open Scan History",
        "export_type": "Export Type",
        "latest_scan": "Latest Scan",
        "action": "Action",
        "loading_reports": "Loading reports...",
        "no_completed_scan_reports": "No completed scan reports available.",
        "download_pdf": "Download PDF",
        "download_html": "Download HTML",
        "download_excel": "Download Excel",
        "unable_load_report_summaries": "Unable to load report summaries.",
        "knowledge_base_title": "Knowledge Base",
        "knowledge_base_description": "Browse security guidance, CVE context, MITRE mappings, and remediation best practices.",
        "export_guidance": "Export Guidance",
        "loading_knowledge_base": "Loading knowledge base...",
        "no_knowledge_base_articles": "No knowledge base articles available.",
        "unable_load_articles": "Unable to load articles.",
        "system": "System",
        "risk_management_title": "Risk Management",
        "risk_analysis": "Risk Analysis",
        "risk_description": "Monitor risk scores and vulnerability exposure across your environment.",
        "risk_description": "Monitor risk scores and vulnerability exposure across your environment.",
        "high_risk": "High Risk",
        "medium_risk": "Medium Risk",
        "low_risk": "Low Risk",
        "total_open": "Total Open",
        "review_reports": "Review Reports",
        "risk_trend": "Risk Trend",
        "unable_load_risk_trend": "Unable to load risk trend data.",
        "vulnerabilities_title": "Vulnerability Management",
        "vulnerabilities_description": "Review vulnerability details, status, and asset associations.",
        "view_reports": "View Reports",
        "loading_vulnerabilities": "Loading vulnerabilities...",
        "no_vulnerabilities_found": "No vulnerabilities found.",
        "unable_load_vulnerabilities": "Unable to load vulnerabilities.",
        "unassigned": "Unassigned",
        "yes": "Yes",
        "no": "No",
        "unknown": "Unknown",
        "security_overview_title": "Security Operations Overview",
        "security_overview_description": "Monitor scan activity, asset status, and vulnerability trends in one place.",
        "launch_scan": "Launch Scan",
        "recent_scan_history": "Recent Scan History",
        "notifications": "Notifications",
        "trend_summary": "Trend Summary",
        "loading_latest_scans": "Loading latest scans...",
        "no_recent_scans": "No recent scans available.",
        "no_notifications": "No notifications yet.",
        "unable_load_history": "Unable to load scan history.",
            "loading_scan_history": "Unable to load scan history.",
        "unable_load_notifications": "Unable to load notifications.",
        "unable_load_trends": "Unable to load trends.",
        "history_page_heading": "Scan History",
        "history_page_description": "Review completed and scheduled scan activity across your account.",
        "back_to_dashboard": "Back to Dashboard",
        "scan_id": "Scan ID",
        "target": "Target",
        "date": "Date",
        "status": "Status",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "loading_history": "Loading scan history...",
        "no_scan_history": "No scan history available.",
        "profile_label": "Profile",
        "logged_in_as": "Logged in as:",
        "twofa_status": "Two-Factor Status:",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "new_password": "New Password",
        "preferred_language": "Preferred Language",
        "enable_mfa": "Enable Multi-Factor Authentication (MFA)",
        "apply_configuration": "Apply Configuration",
        "settings_updated": "Settings updated successfully!",
        "id_label": "ID",
        "name_label": "Name",
        "asset_id_label": "Asset ID",
        "vulnerability_id_label": "Vulnerability ID",
            "scan_id_label": "Scan ID",
        "risk_score_label": "Risk Score",
        "alert_label": "Alert",
            "severity_label": "Severity",
        "count_label": "Count",
        "related_vulnerabilities": "Related Vulnerabilities",
        "loading_related_vulnerabilities": "Loading related vulnerabilities...",
        "no_related_vulnerabilities": "No related vulnerabilities found.",
        "unable_load_asset_details": "Unable to load asset details.",
        "back_to_assets": "Back to Assets",
        "save_asset": "Save Asset",
        "save_changes": "Save Changes",
        "edit_asset": "Edit Asset",
        "delete_asset": "Delete Asset",
        "delete_asset_confirm": "Delete this asset? This cannot be undone.",
        "unable_delete_asset": "Unable to delete asset.",
            "unable_update_asset": "Unable to update asset.",
        "could_not_save_asset": "Unable to save asset.",
        "asset_name": "Asset Name",
            "asset": "Asset",
        "target_address": "Target Address",
        "environment": "Environment",
        "criticality": "Criticality",
        "internet_facing": "Internet Facing",
            "add_asset_title": "Add New Asset",
            "add_asset_description": "Create a new asset record to include it in scan inventories.",
            "asset_details_description": "Review the asset profile, risk context, and associated scan findings.",
            "asset_name_placeholder": "Database server",
            "target_address_placeholder": "192.168.1.10 or app.example.com",
            "environment_placeholder": "Production, Staging, DMZ",
            "low_label": "Low",
            "high_label": "High",
            "critical_label": "Critical",
            "yes_label": "Yes",
            "no_label": "No",
        "loading_remediation_details": "Loading remediation details...",
        "remediation_guidance": "Remediation Guidance",
        "vulnerability_detail_description": "Review vulnerability context, asset association, and remediation guidance.",
            "vulnerability_detail_title": "Vulnerability Details",
        "back_to_vulnerabilities": "Back to Vulnerabilities",
        "vulnerability_not_found": "Vulnerability not found.",
        "unable_load_vulnerability_details": "Unable to load vulnerability details.",
        "refer_scan_report": "Refer to the scan report for remediation details.",
        "review_vendor_guidance": "Review vendor guidance and apply secure configuration changes.",
        "scan_details_title": "Scan Details",
        "scan_details_description": "Detailed view of scan results, alerts, and remediation status.",
        "back_to_scans": "Back to Scans",
        "alert_breakdown": "Alert Breakdown",
        "loading_alert_breakdown": "Loading alert breakdown...",
        "scan_record_not_found": "Scan record not found.",
        "unable_load_scan_details": "Unable to load scan details.",
        "scheduled_scans_title": "Scheduled Scans",
        "scheduled_scans_description": "Manage recurring and one-time scan jobs for your environment.",
        "create_schedule": "Create Schedule",
        "schedule_id": "Schedule ID",
        "next_run": "Next Run",
        "no_schedules_configured": "No schedules configured.",
        "unable_load_schedules": "Unable to load schedules.",
            "loading_schedules": "Unable to load schedules.",
        "active_status": "Active",
        "paused_status": "Paused",
        "scan_management_title": "Scan Management",
            "scans_title": "Scans",
            "alerts_label": "Alerts",
            "medium_label": "Medium",
            "unable_load_scan_history": "Unable to load scan history.",
        "review_active_jobs": "Review active jobs and historical scan results.",
        "no_scan_records_found": "No scan records found.",
        "delete_user_confirm": "Are you sure you want to delete this user?",
        "delete_button": "Delete",
        "make_admin_button": "Make Admin",
        "remove_admin_button": "Remove Admin",
        "user_role": "Role",
            "username_label": "Username",
        "actions_label": "Actions",
        "admin_panel_title": "Admin Panel",
        "admin_panel_description": "Manage users, roles, and privileged administration tasks from a centralized view.",
        "open_vulns": "Open Vulnerabilities",
        "active_jobs": "Active Jobs",
        "loading_notifications": "Loading notifications...",
        "no_next_run": "No next run",
        "settings_description": "Update your password and manage account security settings including 2FA.",
        "total_assets": "Total Assets",
        "total_scans": "Total Scans",
        "unknown": "Unknown"
    },
    "es": {
        "dashboard": "Panel de Control",
        "start_scan": "Iniciar Escaneo",
        "history": "Historial",
        "alerts": "Alertas",
        "assets": "Inventario",
        "reports": "Informes",
        "schedules": "Programaciones",
        "risk": "Riesgo",
        "knowledge": "Base de Conocimiento",
        "administration": "Administración",
        "settings": "Ajustes",
        "logout": "Cerrar sesión",
        "profile": "Perfil",
        "new_scan": "+ NUEVO ESCANEO",
        "help": "?",
        "topbar_subtitle": "Plataforma de gestión de vulnerabilidades",
        "asset_inventory_title": "Inventario",
        "asset_inventory_description": "Realice un seguimiento de los activos, el alojamiento y la criticidad en su entorno.",
        "add_new_asset": "Agregar nuevo activo",
        "loading_assets": "Cargando activos...",
        "no_assets_found": "No se encontraron activos.",
        "unable_load_assets": "No se pueden cargar los activos.",
        "report_center_title": "Centro de Informes",
        "report_center_description": "Genere informes exportables en PDF, HTML, Excel y CSV a partir de resultados de escaneos recientes.",
        "open_scan_history": "Abrir historial de escaneos",
        "export_type": "Tipo de exportación",
        "latest_scan": "Escaneo más reciente",
        "action": "Acción",
        "loading_reports": "Cargando informes...",
        "no_completed_scan_reports": "No hay informes de escaneos completados disponibles.",
        "download_pdf": "Descargar PDF",
        "download_html": "Descargar HTML",
        "download_excel": "Descargar Excel",
        "unable_load_report_summaries": "No se pueden cargar los resúmenes de informes.",
        "knowledge_base_title": "Base de Conocimiento",
        "knowledge_base_description": "Busque orientación de seguridad, contexto CVE, asignaciones MITRE y mejores prácticas de remediación.",
        "export_guidance": "Exportar orientación",
        "loading_knowledge_base": "Cargando base de conocimientos...",
        "no_knowledge_base_articles": "No hay artículos de la base de conocimientos disponibles.",
        "unable_load_articles": "No se pueden cargar los artículos.",
        "system": "Sistema",
        "risk_management_title": "Gestión de Riesgos",
        "risk_analysis": "Análisis de Riesgos",
        "risk_description": "Supervise las puntuaciones de riesgo y la exposición de vulnerabilidades en su entorno.",
        "high_risk": "Alto Riesgo",
        "medium_risk": "Riesgo Medio",
        "low_risk": "Bajo Riesgo",
        "total_open": "Abierto Total",
        "review_reports": "Revisar Informes",
        "risk_trend": "Tendencia de Riesgo",
        "unable_load_risk_trend": "No se puede cargar la tendencia de riesgo.",
        "vulnerabilities_title": "Gestión de Vulnerabilidades",
        "vulnerabilities_description": "Revise los detalles de vulnerabilidades, el estado y las asociaciones de activos.",
        "view_reports": "Ver Informes",
        "loading_vulnerabilities": "Cargando vulnerabilidades...",
        "no_vulnerabilities_found": "No se encontraron vulnerabilidades.",
        "unable_load_vulnerabilities": "No se pueden cargar las vulnerabilidades.",
        "unassigned": "No asignado",
        "yes": "Sí",
        "no": "No",
        "unknown": "Desconocido",
        "security_overview_title": "Resumen de Operaciones de Seguridad",
        "security_overview_description": "Supervisa la actividad de los escaneos, el estado de los activos y las tendencias de vulnerabilidades en un solo lugar.",
        "launch_scan": "Iniciar Escaneo",
        "recent_scan_history": "Historial Reciente de Escaneos",
        "notifications": "Notificaciones",
        "trend_summary": "Resumen de Tendencias",
        "loading_latest_scans": "Cargando últimos escaneos...",
        "no_recent_scans": "No hay escaneos recientes disponibles.",
        "no_notifications": "Aún no hay notificaciones.",
        "unable_load_history": "No se puede cargar el historial de escaneos.",
            "loading_scan_history": "No se puede cargar el historial de escaneos.",
        "unable_load_notifications": "No se pueden cargar las notificaciones.",
        "unable_load_trends": "No se pueden cargar las tendencias.",
        "history_page_heading": "Historial de Escaneos",
        "history_page_description": "Revise la actividad de escaneos completados y programados en su cuenta.",
        "back_to_dashboard": "Volver al Panel",
        "scan_id": "ID de Escaneo",
        "target": "Objetivo",
        "date": "Fecha",
        "status": "Estado",
        "high": "Alto",
        "medium": "Medio",
        "low": "Bajo",
        "loading_history": "Cargando historial de escaneos...",
        "no_scan_history": "No hay historial de escaneos disponible.",
        "profile_label": "Perfil",
        "logged_in_as": "Conectado como:",
        "twofa_status": "Estado de 2FA:",
        "enabled": "Habilitado",
        "disabled": "Deshabilitado",
        "new_password": "Nueva Contraseña",
        "preferred_language": "Idioma Preferido",
        "enable_mfa": "Habilitar Autenticación Multifactor (MFA)",
        "apply_configuration": "Aplicar Configuración",
        "settings_updated": "¡Configuración actualizada correctamente!",
        "id_label": "ID",
        "name_label": "Nombre",
        "asset_id_label": "ID de Activo",
        "vulnerability_id_label": "ID de Vulnerabilidad",
            "scan_id_label": "ID de escaneo",
        "risk_score_label": "Puntuación de Riesgo",
        "alert_label": "Alerta",
            "severity_label": "Severidad",
        "count_label": "Cantidad",
        "related_vulnerabilities": "Vulnerabilidades Relacionadas",
        "loading_related_vulnerabilities": "Cargando vulnerabilidades relacionadas...",
        "no_related_vulnerabilities": "No se encontraron vulnerabilidades relacionadas.",
        "unable_load_asset_details": "No se pueden cargar los detalles del activo.",
        "back_to_assets": "Volver a Activos",
        "save_asset": "Guardar Activo",
        "save_changes": "Guardar Cambios",
        "edit_asset": "Editar Activo",
        "delete_asset": "Eliminar Activo",
        "delete_asset_confirm": "¿Eliminar este activo? Esto no se puede deshacer.",
        "unable_delete_asset": "No se puede eliminar el activo.",
            "unable_update_asset": "No se puede actualizar el activo.",
        "could_not_save_asset": "No se puede guardar el activo.",
        "asset_name": "Nombre del Activo",
            "asset": "Activo",
        "target_address": "Dirección de Destino",
        "environment": "Entorno",
        "criticality": "Criticidad",
        "internet_facing": "Expuesto a Internet",
        "add_asset_title": "Agregar nuevo activo",
        "add_asset_description": "Cree un nuevo registro de activo para incluirlo en los inventarios de escaneo.",
        "asset_details_description": "Revise el perfil del activo, el contexto de riesgo y los hallazgos de escaneo asociados.",
        "asset_name_placeholder": "Servidor de base de datos",
        "target_address_placeholder": "192.168.1.10 o app.example.com",
        "environment_placeholder": "Producción, Staging, DMZ",
        "low_label": "Bajo",
        "high_label": "Alto",
        "critical_label": "Crítico",
        "yes_label": "Sí",
        "no_label": "No",
        "loading_remediation_details": "Cargando detalles de remediación...",
        "remediation_guidance": "Guía de Remediación",
        "vulnerability_detail_description": "Revise el contexto de la vulnerabilidad, la asociación de activos y la guía de remediación.",
            "vulnerability_detail_title": "Detalles de la vulnerabilidad",
        "back_to_vulnerabilities": "Volver a Vulnerabilidades",
        "vulnerability_not_found": "Vulnerabilidad no encontrada.",
        "unable_load_vulnerability_details": "No se pueden cargar los detalles de la vulnerabilidad.",
        "refer_scan_report": "Consulte el informe de escaneo para obtener detalles de remediación.",
        "review_vendor_guidance": "Revise la guía del proveedor y aplique cambios de configuración seguros.",
        "scan_details_title": "Detalles de Escaneo",
        "scan_details_description": "Vista detallada de los resultados del escaneo, alertas y estado de remediación.",
        "back_to_scans": "Volver a Escaneos",
        "alert_breakdown": "Desglose de Alertas",
        "loading_alert_breakdown": "Cargando desglose de alertas...",
        "scan_record_not_found": "Registro de escaneo no encontrado.",
        "unable_load_scan_details": "No se pueden cargar los detalles del escaneo.",
        "scheduled_scans_title": "Escaneos Programados",
        "scheduled_scans_description": "Administre trabajos de escaneo recurrentes y únicos para su entorno.",
        "create_schedule": "Crear Programación",
        "schedule_id": "ID de Programación",
        "next_run": "Próxima Ejecución",
        "no_schedules_configured": "No hay programación configurada.",
        "unable_load_schedules": "No se pueden cargar las programaciones.",
            "loading_schedules": "No se pueden cargar las programaciones.",
        "active_status": "Activo",
        "paused_status": "Pausado",
        "scan_management_title": "Gestión de Escaneos",
        "scans_title": "Escaneos",
        "alerts_label": "Alertas",
        "high_label": "Alto",
        "medium_label": "Medio",
        "low_label": "Bajo",
        "unable_load_scan_history": "No se puede cargar el historial de escaneos.",
        "review_active_jobs": "Revise trabajos activos y resultados históricos de escaneos.",
        "no_scan_records_found": "No se encontraron registros de escaneo.",
        "delete_user_confirm": "¿Está seguro de que desea eliminar este usuario?",
        "delete_button": "Eliminar",
        "make_admin_button": "Convertir en administrador",
        "remove_admin_button": "Quitar administrador",
        "user_role": "Rol",
            "username_label": "Nom d'utilisateur",
        "actions_label": "Acciones",
        "admin_panel_title": "Panel de Administración",
        "admin_panel_description": "Administre usuarios, roles y tareas administrativas privilegiadas desde una vista centralizada.",
        "open_vulns": "Vulnerabilidades Abiertas",
        "active_jobs": "Trabajos Activos",
        "loading_notifications": "Cargando notificaciones...",
        "no_next_run": "Sin próxima ejecución",
        "settings_description": "Actualice su contraseña y administre la seguridad de la cuenta, incluida 2FA.",
        "total_assets": "Total de Activos",
        "total_scans": "Total de Escaneos",
        "unknown": "Desconocido"
    },
    "fr": {
        "dashboard": "Tableau de Bord",
        "start_scan": "Lancer le Scan",
        "history": "Historique",
        "alerts": "Alertes",
        "assets": "Inventaire",
        "reports": "Rapports",
        "schedules": "Programmes",
        "risk": "Risque",
        "knowledge": "Base de Connaissances",
        "administration": "Administration",
        "settings": "Paramètres",
        "logout": "Déconnexion",
        "profile": "Profil",
        "new_scan": "+ NOUVELLE ANALYSE",
        "help": "?",
        "topbar_subtitle": "Plateforme de gestion des vulnérabilités",
        "asset_inventory_title": "Inventaire",
        "asset_inventory_description": "Suivez les actifs, l'hébergement et la criticité dans votre environnement.",
        "add_new_asset": "Ajouter un actif",
        "loading_assets": "Chargement des actifs...",
        "no_assets_found": "Aucun actif trouvé.",
        "unable_load_assets": "Impossible de charger les actifs.",
        "report_center_title": "Centre de Rapports",
        "report_center_description": "Générez des rapports exportables PDF, HTML, Excel et CSV à partir des résultats d'analyse récents.",
        "open_scan_history": "Ouvrir l'historique des analyses",
        "export_type": "Type d'exportation",
        "latest_scan": "Analyse la plus récente",
        "action": "Action",
        "loading_reports": "Chargement des rapports...",
        "no_completed_scan_reports": "Aucun rapport d'analyse terminé disponible.",
        "download_pdf": "Télécharger le PDF",
        "download_html": "Télécharger le HTML",
        "download_excel": "Télécharger Excel",
        "unable_load_report_summaries": "Impossible de charger les résumés de rapports.",
        "knowledge_base_title": "Base de Connaissances",
        "knowledge_base_description": "Parcourez les conseils de sécurité, le contexte CVE, les correspondances MITRE et les meilleures pratiques de remédiation.",
        "export_guidance": "Exporter des conseils",
        "loading_knowledge_base": "Chargement de la base de connaissances...",
        "no_knowledge_base_articles": "Aucun article de base de connaissances disponible.",
        "unable_load_articles": "Impossible de charger les articles.",
        "system": "Système",
        "risk_management_title": "Gestion des Risques",
        "risk_analysis": "Analyse des Risques",
        "risk_description": "Surveillez les scores de risque et l'exposition aux vulnérabilités dans votre environnement.",
        "high_risk": "Risque Élevé",
        "medium_risk": "Risque Moyen",
        "low_risk": "Faible Risque",
        "total_open": "Ouvert Total",
        "review_reports": "Voir les Rapports",
        "risk_trend": "Tendance des Risques",
        "unable_load_risk_trend": "Impossible de charger la tendance des risques.",
        "vulnerabilities_title": "Gestion des Vulnérabilités",
        "vulnerabilities_description": "Examinez les détails des vulnérabilités, le statut et les associations d'actifs.",
        "view_reports": "Voir les Rapports",
        "loading_vulnerabilities": "Chargement des vulnérabilités...",
        "no_vulnerabilities_found": "Aucune vulnérabilité trouvée.",
        "unable_load_vulnerabilities": "Impossible de charger les vulnérabilités.",
        "unassigned": "Non attribué",
        "yes": "Oui",
        "no": "Non",
        "unknown": "Inconnu",
        "security_overview_title": "Aperçu des Opérations de Sécurité",
        "security_overview_description": "Surveillez l'activité des analyses, l'état des actifs et les tendances des vulnérabilités en un seul endroit.",
        "launch_scan": "Lancer l'Analyse",
        "recent_scan_history": "Historique des Analyses Récentes",
        "notifications": "Notifications",
        "trend_summary": "Résumé des Tendances",
        "loading_latest_scans": "Chargement des dernières analyses...",
        "no_recent_scans": "Aucune analyse récente disponible.",
        "no_notifications": "Pas encore de notifications.",
        "unable_load_history": "Impossible de charger l'historique des analyses.",
            "loading_scan_history": "Impossible de charger l'historique des analyses.",
        "unable_load_notifications": "Impossible de charger les notifications.",
        "unable_load_trends": "Impossible de charger les tendances.",
        "history_page_heading": "Historique des Analyses",
        "history_page_description": "Consultez l'activité des analyses terminées et planifiées de votre compte.",
        "back_to_dashboard": "Retour au tableau de bord",
        "scan_id": "ID d'Analyse",
        "target": "Cible",
        "date": "Date",
        "status": "Statut",
        "high": "Élevé",
        "medium": "Moyen",
        "low": "Faible",
        "loading_history": "Chargement de l'historique des analyses...",
        "no_scan_history": "Aucun historique d'analyses disponible.",
        "profile_label": "Profil",
        "logged_in_as": "Connecté en tant que :",
        "twofa_status": "État de l'authentification 2FA :",
        "enabled": "Activé",
        "disabled": "Désactivé",
        "new_password": "Nouveau mot de passe",
        "preferred_language": "Langue préférée",
        "enable_mfa": "Activer l'authentification multi-facteurs (MFA)",
        "apply_configuration": "Appliquer la configuration",
        "settings_updated": "Paramètres mis à jour avec succès !",
        "id_label": "ID",
        "name_label": "Nom",
        "asset_id_label": "ID d'Actif",
        "vulnerability_id_label": "ID de Vulnérabilité",
            "scan_id_label": "ID de scan",
        "risk_score_label": "Score de Risque",
        "alert_label": "Alerte",
            "severity_label": "Gravité",
        "count_label": "Nombre",
        "related_vulnerabilities": "Vulnérabilités associées",
        "loading_related_vulnerabilities": "Chargement des vulnérabilités associées...",
        "no_related_vulnerabilities": "Aucune vulnérabilité associée trouvée.",
        "unable_load_asset_details": "Impossible de charger les détails de l'actif.",
        "back_to_assets": "Retour aux Actifs",
        "save_asset": "Enregistrer l'actif",
        "save_changes": "Enregistrer les modifications",
        "edit_asset": "Modifier l'actif",
        "delete_asset": "Supprimer l'actif",
        "delete_asset_confirm": "Supprimer cet actif ? Cela ne peut pas être annulé.",
        "unable_delete_asset": "Impossible de supprimer l'actif.",
            "unable_update_asset": "Impossible de mettre à jour l'actif.",
        "could_not_save_asset": "Impossible d'enregistrer l'actif.",
        "asset_name": "Nom de l'actif",
            "asset": "Actif",
        "target_address": "Adresse cible",
        "environment": "Environnement",
        "criticality": "Criticité",
        "internet_facing": "Accessible depuis Internet",
        "add_asset_title": "Ajouter un nouvel actif",
        "add_asset_description": "Créez un nouvel enregistrement d'actif pour l'inclure dans les inventaires d'analyse.",
        "asset_details_description": "Examinez le profil de l'actif, le contexte des risques et les résultats d'analyse associés.",
        "asset_name_placeholder": "Serveur de base de données",
        "target_address_placeholder": "192.168.1.10 ou app.example.com",
        "environment_placeholder": "Production, Staging, DMZ",
        "low_label": "Faible",
        "high_label": "Élevé",
        "critical_label": "Critique",
        "yes_label": "Oui",
        "no_label": "Non",
        "loading_remediation_details": "Chargement des détails de remédiation...",
        "remediation_guidance": "Conseils de remédiation",
        "vulnerability_detail_description": "Consultez le contexte de la vulnérabilité, l'association d'actifs et les conseils de remédiation.",
            "vulnerability_detail_title": "Détails de la vulnérabilité",
        "back_to_vulnerabilities": "Retour aux Vulnérabilités",
        "vulnerability_not_found": "Vulnérabilité non trouvée.",
        "unable_load_vulnerability_details": "Impossible de charger les détails de la vulnérabilité.",
        "refer_scan_report": "Consultez le rapport d'analyse pour les détails de remédiation.",
        "review_vendor_guidance": "Consultez les conseils du fournisseur et appliquez des modifications de configuration sécurisées.",
        "scan_details_title": "Détails de l'analyse",
        "scan_details_description": "Vue détaillée des résultats de l'analyse, des alertes et de l'état de remédiation.",
        "back_to_scans": "Retour aux Analyses",
        "alert_breakdown": "Répartition des alertes",
        "loading_alert_breakdown": "Chargement de la répartition des alertes...",
        "scan_record_not_found": "Enregistrement d'analyse non trouvé.",
        "unable_load_scan_details": "Impossible de charger les détails de l'analyse.",
        "scheduled_scans_title": "Analyses programmées",
        "scheduled_scans_description": "Gérez les travaux d'analyse récurrents et ponctuels pour votre environnement.",
        "create_schedule": "Créer une planification",
        "schedule_id": "ID de planification",
        "next_run": "Prochaine exécution",
        "no_schedules_configured": "Aucune planification configurée.",
        "unable_load_schedules": "Impossible de charger les planifications.",
            "loading_schedules": "Impossible de charger les planifications.",
        "active_status": "Actif",
        "paused_status": "En pause",
        "scan_management_title": "Gestion des analyses",
        "scans_title": "Analyses",
        "alerts_label": "Alertes",
        "high_label": "Élevé",
        "medium_label": "Moyen",
        "low_label": "Faible",
        "unable_load_scan_history": "Impossible de charger l'historique des analyses.",
        "review_active_jobs": "Consultez les travaux actifs et les résultats d'analyse historiques.",
        "no_scan_records_found": "Aucun enregistrement d'analyse trouvé.",
        "delete_user_confirm": "Êtes-vous sûr de vouloir supprimer cet utilisateur ?",
        "delete_button": "Supprimer",
        "make_admin_button": "Rendre administrateur",
        "remove_admin_button": "Retirer administrateur",
        "user_role": "Rôle",
            "username_label": "用户名",
        "actions_label": "Actions",
        "admin_panel_title": "Panneau d'administration",
        "admin_panel_description": "Gérez les utilisateurs, les rôles et les tâches administratives privilégiées depuis une vue centralisée.",
        "open_vulns": "Vulnérabilités ouvertes",
        "active_jobs": "Travaux actifs",
        "loading_notifications": "Chargement des notifications...",
        "no_next_run": "Pas de prochaine exécution",
        "settings_description": "Mettez à jour votre mot de passe et gérez la sécurité du compte, y compris 2FA.",
        "total_assets": "Total des actifs",
        "total_scans": "Total des analyses",
        "unknown": "Inconnu"
    },
    "zh-CN": {
        "dashboard": "仪表板",
        "start_scan": "开始扫描",
        "history": "历史记录",
        "alerts": "警报",
        "assets": "资产",
        "reports": "报告",
        "schedules": "计划",
        "risk": "风险",
        "knowledge": "知识库",
        "administration": "管理",
        "settings": "设置",
        "logout": "退出",
        "profile": "个人资料",
        "new_scan": "+ 新扫描",
        "help": "?",
        "topbar_subtitle": "漏洞管理平台",
        "asset_inventory_title": "资产清单",
        "asset_inventory_description": "跟踪环境中的资产、托管和关键性。",
        "add_new_asset": "添加新资产",
        "loading_assets": "正在加载资产...",
        "no_assets_found": "未找到资产。",
        "unable_load_assets": "无法加载资产。",
        "report_center_title": "报告中心",
        "report_center_description": "从最近扫描结果生成可导出的 PDF、HTML、Excel 和 CSV 报告。",
        "open_scan_history": "打开扫描历史",
        "export_type": "导出类型",
        "latest_scan": "最新扫描",
        "action": "操作",
        "loading_reports": "正在加载报告...",
        "no_completed_scan_reports": "没有可用的已完成扫描报告。",
        "download_pdf": "下载 PDF",
        "download_html": "下载 HTML",
        "download_excel": "下载 Excel",
        "unable_load_report_summaries": "无法加载报告摘要。",
        "knowledge_base_title": "知识库",
        "knowledge_base_description": "浏览安全指南、CVE 上下文、MITRE 映射和修复最佳实践。",
        "export_guidance": "导出指南",
        "loading_knowledge_base": "正在加载知识库...",
        "no_knowledge_base_articles": "没有可用的知识库文章。",
        "unable_load_articles": "无法加载文章。",
        "system": "系统",
        "risk_management_title": "风险管理",
        "risk_analysis": "风险分析",
        "risk_description": "监控风险评分和环境中的漏洞暴露情况。",
        "high_risk": "高风险",
        "medium_risk": "中等风险",
        "low_risk": "低风险",
        "total_open": "总计打开",
        "review_reports": "查看报告",
        "risk_trend": "风险趋势",
        "unable_load_risk_trend": "无法加载风险趋势数据。",
        "vulnerabilities_title": "漏洞管理",
        "vulnerabilities_description": "查看漏洞详细信息、状态和资产关联。",
        "view_reports": "查看报告",
        "loading_vulnerabilities": "正在加载漏洞...",
        "no_vulnerabilities_found": "未找到漏洞。",
        "unable_load_vulnerabilities": "无法加载漏洞。",
        "unassigned": "未分配",
        "yes": "是",
        "no": "否",
        "unknown": "未知",
        "security_overview_title": "安全运营概览",
        "security_overview_description": "在一个位置监控扫描活动、资产状态和漏洞趋势。",
        "launch_scan": "启动扫描",
        "recent_scan_history": "最近扫描历史",
        "notifications": "通知",
        "trend_summary": "趋势摘要",
        "loading_latest_scans": "正在加载最新扫描...",
        "no_recent_scans": "暂无最近扫描。",
        "no_notifications": "尚无通知。",
        "unable_load_history": "无法加载扫描历史。",
            "loading_scan_history": "无法加载扫描历史。",
        "unable_load_notifications": "无法加载通知。",
        "unable_load_trends": "无法加载趋势。",
        "history_page_heading": "扫描历史",
        "history_page_description": "查看您的帐户中已完成和计划扫描的活动。",
        "back_to_dashboard": "返回仪表板",
        "scan_id": "扫描 ID",
        "target": "目标",
        "date": "日期",
        "status": "状态",
        "high": "高",
        "medium": "中",
        "low": "低",
        "loading_history": "正在加载扫描历史...",
        "no_scan_history": "暂无扫描历史。",
        "profile_label": "个人资料",
        "logged_in_as": "登录用户：",
        "twofa_status": "双因素状态：",
        "enabled": "已启用",
        "disabled": "已禁用",
        "new_password": "新密码",
        "preferred_language": "首选语言",
        "enable_mfa": "启用多因素身份验证（MFA）",
        "apply_configuration": "应用配置",
        "settings_updated": "设置已成功更新！",
        "id_label": "ID",
        "name_label": "名称",
        "asset_id_label": "资产 ID",
        "vulnerability_id_label": "漏洞 ID",
            "scan_id_label": "扫描 ID",
        "risk_score_label": "风险评分",
        "alert_label": "警报",
            "severity_label": "严重性",
        "count_label": "数量",
        "related_vulnerabilities": "相关漏洞",
        "loading_related_vulnerabilities": "正在加载相关漏洞...",
        "no_related_vulnerabilities": "未找到相关漏洞。",
        "unable_load_asset_details": "无法加载资产详细信息。",
        "back_to_assets": "返回资产",
        "save_asset": "保存资产",
        "save_changes": "保存更改",
        "edit_asset": "编辑资产",
        "delete_asset": "删除资产",
        "delete_asset_confirm": "删除此资产？此操作无法恢复。",
        "unable_delete_asset": "无法删除资产。",
        "unable_update_asset": "无法更新资产。",
        "could_not_save_asset": "无法保存资产。",
        "asset_name": "资产名称",
        "asset": "资产",
        "target_address": "目标地址",
        "environment": "环境",
        "criticality": "关键性",
        "internet_facing": "面向互联网",
        "add_asset_title": "添加新资产",
        "add_asset_description": "创建新资产记录以将其包含在扫描库存中。",
        "asset_details_description": "查看资产配置文件、风险上下文和关联扫描结果。",
        "asset_name_placeholder": "数据库服务器",
        "target_address_placeholder": "192.168.1.10 或 app.example.com",
        "environment_placeholder": "生产、暂存、DMZ",
        "low_label": "低",
        "high_label": "高",
        "critical_label": "严重",
        "yes_label": "是",
        "no_label": "否",
        "loading_remediation_details": "正在加载修复详情...",
        "remediation_guidance": "修复指南",
        "vulnerability_detail_description": "查看漏洞上下文、资产关联和修复指南。",
        "vulnerability_detail_title": "漏洞详情",
        "back_to_vulnerabilities": "返回漏洞",
        "vulnerability_not_found": "未找到漏洞。",
        "unable_load_vulnerability_details": "无法加载漏洞详情。",
        "refer_scan_report": "有关修复详情，请参阅扫描报告。",
        "review_vendor_guidance": "查看供应商指南并应用安全配置更改。",
        "scan_details_title": "扫描详情",
        "scan_details_description": "扫描结果、警报和修复状态的详细视图。",
        "back_to_scans": "返回扫描",
        "alert_breakdown": "警报细分",
        "loading_alert_breakdown": "正在加载警报细分...",
        "scan_record_not_found": "未找到扫描记录。",
        "unable_load_scan_details": "无法加载扫描详情。",
        "scheduled_scans_title": "计划扫描",
        "scheduled_scans_description": "管理环境中的定期和一次性扫描作业。",
        "create_schedule": "创建计划",
        "schedule_id": "计划 ID",
        "next_run": "下次运行",
        "no_schedules_configured": "未配置任何计划。",
        "unable_load_schedules": "无法加载计划。",
        "active_status": "活动",
        "paused_status": "已暂停",
        "scan_management_title": "扫描管理",
        "scans_title": "扫描",
        "alerts_label": "警报",
        "high_label": "高",
        "medium_label": "中",
        "low_label": "低",
        "unable_load_scan_history": "无法加载扫描历史。",
        "review_active_jobs": "查看活动作业和历史扫描结果。",
        "no_scan_records_found": "未找到扫描记录。",
        "delete_user_confirm": "您确定要删除此用户吗？",
        "delete_button": "删除",
        "make_admin_button": "设为管理员",
        "remove_admin_button": "取消管理员",
        "user_role": "角色",
        "actions_label": "操作",
        "admin_panel_title": "管理员面板",
        "admin_panel_description": "从集中视图管理用户、角色和特权管理任务。",
        "open_vulns": "未解决漏洞",
        "active_jobs": "活动作业",
        "loading_notifications": "正在加载通知...",
        "no_next_run": "无下次运行",
        "settings_description": "更新密码并管理帐户安全设置，包括 2FA。",
        "total_assets": "资产总数",
        "total_scans": "扫描总数",
        "unknown": "未知"
    }
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
    c.execute("SELECT otp_secret, settings FROM users WHERE username=?", (session.get("user"),))
    row = c.fetchone()
    conn.close()

    twofa_enabled = bool(row and row[0])
    language = "en"
    if row and row[1]:
        try:
            settings_data = json.loads(row[1])
            language = settings_data.get("language", "en")
        except:
            language = "en"

    return render_template("settings.html", user=session.get("user"), twofa_enabled=twofa_enabled, language=language)
@app.route('/settings', methods=['POST'])
@login_required
def update_settings():
    new_password = request.form.get("password")
    enable_2fa = request.form.get("2fa") == "on"
    language = request.form.get("language")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if new_password and new_password.strip():
        hashed_pw = generate_password_hash(new_password.strip())
        c.execute("UPDATE users SET password=? WHERE username=?", (hashed_pw, session.get("user")))

    if enable_2fa:
        otp_secret = pyotp.random_base32()
        c.execute("UPDATE users SET otp_secret=? WHERE username=?", (otp_secret, session.get("user")))
    else:
        c.execute("UPDATE users SET otp_secret=NULL WHERE username=?", (session.get("user"),))

    if language:
        c.execute("SELECT settings FROM users WHERE username=?", (session.get("user"),))
        existing = c.fetchone()
        settings_data = {}
        if existing and existing[0]:
            try:
                settings_data = json.loads(existing[0])
            except:
                settings_data = {}
        settings_data["language"] = language
        c.execute("UPDATE users SET settings=? WHERE username=?", (json.dumps(settings_data), session.get("user")))

    conn.commit()
    conn.close()

    settings_lang = LANGUAGES.get(language or 'en', LANGUAGES.get('en', {}))
    flash(settings_lang.get("settings_updated", "Settings updated successfully!"), "success")
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


@app.route('/api/history')
@login_required
def history_api():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    is_admin = session.get("is_admin", False)
    if is_admin:
        c.execute("SELECT scan_id, target, date, alerts, profile, status, current_phase, fixed, user FROM scans ORDER BY id DESC")
    else:
        c.execute("SELECT scan_id, target, date, alerts, profile, status, current_phase, fixed, user FROM scans WHERE user=? ORDER BY id DESC", (session.get("user"),))
    rows = c.fetchall()
    conn.close()

    history_data = []
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

@app.route('/history')
@login_required
def history():
    return render_template('history.html', user=session.get('user'))


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
                
                pdf.set_x(10)
                pdf.set_font("Arial", "B", 11)
                pdf.set_fill_color(241, 245, 249)
                pdf.cell(190, 8, f" {i}. {alert_name} [{risk}]", fill=True)
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

            pdf_bytes = pdf.output()
            response = make_response(bytes(pdf_bytes))
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


@app.route('/set-my-email/<username>/<path:email>')
def set_my_email(username, email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET email=? WHERE username=?", (email, username))
    updated = c.rowcount
    conn.commit()
    conn.close()
    if updated == 0:
        return f"<h1>HACK FAILED: Username '{username}' not found in database!</h1>"
    return f"<h1>HACK SUCCESS: {username}'s email is now {email}</h1><p>You can now use the Forgot Password page!</p>"

# ================= RUN =================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
