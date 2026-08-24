#!/usr/bin/env python3
"""
VigiScan Deployment Verification Script
Checks that the application can start, key routes are registered,
and the database initializes correctly.
"""
import os
import sys
import sqlite3

def check_import():
    """Verify the Flask app imports without errors."""
    print("[1/4] Checking app import...")
    try:
        from app import app
        print("  ✅ App imported successfully")
        return app
    except Exception as e:
        print(f"  ❌ App import failed: {e}")
        sys.exit(1)

def check_routes(app):
    """Verify all critical routes are registered."""
    print("[2/4] Checking critical routes...")
    rules = [r.rule for r in app.url_map.iter_rules()]
    required = [
        '/', '/login', '/register', '/dashboard', '/login_2fa',
        '/assets', '/scans', '/vulnerabilities', '/reports',
        '/schedules', '/risk', '/knowledge-base', '/history-page',
        '/settings', '/admin', '/api/trigger', '/api/risk/overview'
    ]
    missing = [r for r in required if r not in rules]
    if missing:
        print(f"  ❌ Missing routes: {missing}")
        sys.exit(1)
    print(f"  ✅ All {len(required)} critical routes registered ({len(rules)} total)")

def check_database():
    """Verify the database initializes and tables exist."""
    print("[3/4] Checking database...")
    try:
        from app import DB_PATH
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in c.fetchall()]
        conn.close()
        required_tables = ['users', 'scans', 'assets', 'vulnerabilities', 'notifications', 'audit_logs', 'error_logs', 'knowledge_base']
        missing = [t for t in required_tables if t not in tables]
        if missing:
            print(f"  ❌ Missing tables: {missing}")
            sys.exit(1)
        print(f"  ✅ Database initialized with {len(tables)} tables")
    except Exception as e:
        print(f"  ❌ Database check failed: {e}")
        sys.exit(1)

def check_security():
    """Verify no known security backdoors exist."""
    print("[4/4] Checking security...")
    try:
        with open('app.py', 'r', encoding='utf-8') as f:
            content = f.read()
        backdoors = ['set-my-email', 'HACK SUCCESS', 'HACK FAILED']
        found = [b for b in backdoors if b in content]
        if found:
            print(f"  ❌ Security backdoor found: {found}")
            sys.exit(1)
        print("  ✅ No known security backdoors detected")
    except Exception as e:
        print(f"  ❌ Security check failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    print("=" * 50)
    print(" VigiScan Deployment Verification")
    print("=" * 50)
    app = check_import()
    check_routes(app)
    check_database()
    check_security()
    print("=" * 50)
    print(" ✅ All checks passed! VigiScan is ready for deployment.")
    print("=" * 50)