import sqlite3
import json
from datetime import datetime

DB_NAME = "users.db"

# ================= CONNECTION =================
def get_conn():
    return sqlite3.connect(DB_NAME)


# ================= USERS =================
def create_user(username, password, otp_secret, is_admin=0):
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        INSERT INTO users (username, password, otp_secret, is_admin)
        VALUES (?, ?, ?, ?)
    """, (username, password, otp_secret, is_admin))

    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()

    conn.close()
    return user


def get_all_users():
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT username FROM users")
    users = c.fetchall()

    conn.close()
    return users


# ================= SCANS =================
def create_scan(user, target, alerts="[]"):
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        INSERT INTO scans (user, target, date, alerts)
        VALUES (?, ?, ?, ?)
    """, (
        user,
        target,
        datetime.utcnow().isoformat(),
        alerts
    ))

    conn.commit()
    conn.close()


def get_user_scans(username):
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT target, date, user
        FROM scans
        WHERE user=?
        ORDER BY id DESC
        LIMIT 100
    """, (username,))

    rows = c.fetchall()
    conn.close()
    return rows


def get_latest_scan():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    row = c.fetchone()
    conn.close()
    return row


def get_scan_by_id(scan_id):
    """
    FUTURE UPGRADE HOOK:
    We will later link scan_id properly in DB.
    For now, fallback uses latest scan logic.
    """
    return get_latest_scan()


def save_scan_result(user, target, alerts_json):
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        INSERT INTO scans (user, target, date, alerts)
        VALUES (?, ?, ?, ?)
    """, (
        user,
        target,
        datetime.utcnow().isoformat(),
        alerts_json
    ))

    conn.commit()
    conn.close()


def update_scan_alerts(scan_id, alerts_json):
    """
    Optional future feature: update scan in real time
    """
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        UPDATE scans
        SET alerts = ?
        WHERE id = ?
    """, (alerts_json, scan_id))

    conn.commit()
    conn.close()