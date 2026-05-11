import sqlite3
from datetime import datetime
import json

def add_sample_articles():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    sample_articles = [
        {
            "title": "SQL Injection: Understanding and Prevention",
            "category": "Vulnerabilities",
            "content": """# SQL Injection Vulnerabilities

## What is SQL Injection?
SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in an application's software by injecting malicious SQL code into a query.

## Common Attack Vectors
- User input in database queries without proper sanitization
- Dynamic SQL queries built with string concatenation
- Stored procedures with unsanitized parameters

## Prevention Techniques
1. **Use Prepared Statements**: Always use parameterized queries
2. **Input Validation**: Validate and sanitize all user inputs
3. **Stored Procedures**: Use stored procedures with parameters
4. **Least Privilege**: Run database connections with minimal privileges
5. **Web Application Firewall (WAF)**: Implement WAF rules to detect SQLi attempts

## Example of Vulnerable Code
```sql
-- Vulnerable
query = "SELECT * FROM users WHERE username = '" + username + "'"

-- Safe
query = "SELECT * FROM users WHERE username = ?"
```

## Detection
- Look for unusual database errors in logs
- Monitor for suspicious query patterns
- Use automated scanning tools like SQLMap""",
            "tags": ["SQL Injection", "Injection", "Database", "Security"],
            "author": "admin",
            "is_public": True
        },
        {
            "title": "Cross-Site Scripting (XSS) Mitigation Guide",
            "category": "Vulnerabilities",
            "content": """# Cross-Site Scripting (XSS) Mitigation

## Types of XSS
1. **Reflected XSS**: Malicious script is reflected back to the user
2. **Stored XSS**: Malicious script is stored in the database
3. **DOM-based XSS**: Vulnerability exists in client-side code

## Prevention Strategies

### Input Validation
- Validate all user inputs on both client and server side
- Use whitelist approach for allowed characters
- Reject inputs containing script tags

### Output Encoding
- HTML encode user content before displaying
- Use appropriate encoding for different contexts:
  - HTML body: `&lt;` for `<`
  - HTML attributes: `&quot;` for `"`
  - JavaScript: `\\x22` for `"`

### Content Security Policy (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com
```

### Safe JavaScript Practices
- Avoid `innerHTML` for user content
- Use `textContent` or `innerText` instead
- Sanitize HTML with libraries like DOMPurify

## Testing for XSS
- Manual testing with payloads like `<script>alert('XSS')</script>`
- Automated tools: OWASP ZAP, Burp Suite
- Fuzzing with various encoding attempts""",
            "tags": ["XSS", "JavaScript", "Frontend", "Injection"],
            "author": "admin",
            "is_public": True
        },
        {
            "title": "OWASP Top 10: 2021 Edition Overview",
            "category": "Compliance",
            "content": """# OWASP Top 10: 2021 Edition

## A01:2021 - Broken Access Control
- **Description**: Restrictions on what authenticated users can do are not properly enforced
- **Common Issues**: IDOR, privilege escalation, metadata manipulation
- **Prevention**: Implement proper access controls, use role-based access control (RBAC)

## A02:2021 - Cryptographic Failures
- **Description**: Failures related to cryptography (or lack thereof)
- **Common Issues**: Weak encryption, exposed secrets, poor key management
- **Prevention**: Use strong encryption algorithms, proper key management, avoid custom crypto

## A03:2021 - Injection
- **Description**: User-controlled input is interpreted as commands
- **Common Issues**: SQL injection, command injection, LDAP injection
- **Prevention**: Use parameterized queries, input validation, prepared statements

## A04:2021 - Insecure Design
- **Description**: Design flaws that lead to security vulnerabilities
- **Common Issues**: Missing security controls, improper threat modeling
- **Prevention**: Secure design patterns, threat modeling, security requirements

## A05:2021 - Security Misconfiguration
- **Description**: Incorrect security settings or configurations
- **Common Issues**: Default credentials, unnecessary features enabled, misconfigured permissions
- **Prevention**: Secure defaults, automated configuration checks, minimal attack surface

## A06:2021 - Vulnerable and Outdated Components
- **Description**: Using components with known vulnerabilities
- **Common Issues**: Outdated libraries, unpatched software
- **Prevention**: Regular updates, vulnerability scanning, software composition analysis

## A07:2021 - Identification and Authentication Failures
- **Description**: Authentication mechanisms are improperly implemented
- **Common Issues**: Weak passwords, poor session management, credential stuffing
- **Prevention**: Multi-factor authentication, secure session management, password policies

## A08:2021 - Software and Data Integrity Failures
- **Description**: Code and infrastructure are not protected against integrity violations
- **Common Issues**: Insecure CI/CD pipelines, insecure deserialization
- **Prevention**: Digital signatures, integrity checks, secure update mechanisms

## A09:2021 - Security Logging and Monitoring Failures
- **Description**: Insufficient logging and monitoring capabilities
- **Common Issues**: Lack of visibility, inadequate alerting
- **Prevention**: Comprehensive logging, real-time monitoring, incident response

## A10:2021 - Server-Side Request Forgery (SSRF)
- **Description**: Server makes requests to unexpected destinations
- **Common Issues**: Internal network exposure, cloud metadata access
- **Prevention**: Input validation, network segmentation, allow lists""",
            "tags": ["OWASP", "Top 10", "Compliance", "Standards"],
            "author": "admin",
            "is_public": True
        },
        {
            "title": "Implementing Secure Headers",
            "category": "Best Practices",
            "content": """# Security Headers Implementation Guide

## Essential Security Headers

### Content Security Policy (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://trusted.cdn.com; style-src 'self' 'unsafe-inline'
```
**Purpose**: Prevents XSS attacks by controlling resource loading
**Implementation**: Start with restrictive policy and gradually allow needed resources

### X-Frame-Options
```http
X-Frame-Options: SAMEORIGIN
```
**Purpose**: Prevents clickjacking attacks
**Options**: DENY, SAMEORIGIN, ALLOW-FROM uri

### X-Content-Type-Options
```http
X-Content-Type-Options: nosniff
```
**Purpose**: Prevents MIME type sniffing attacks
**Implementation**: Always set to nosniff

### Strict-Transport-Security (HSTS)
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
**Purpose**: Forces HTTPS connections
**Implementation**: Use with care, especially preload directive

### Referrer-Policy
```http
Referrer-Policy: strict-origin-when-cross-origin
```
**Purpose**: Controls referrer information leakage
**Options**: no-referrer, strict-origin, strict-origin-when-cross-origin

## Implementation by Web Server

### Apache
```apache
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

### Nginx
```nginx
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Express.js (Node.js)
```javascript
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});
```

## Testing Headers
- Use browser developer tools
- Securityheaders.com
- OWASP ZAP security headers check
- curl -I https://yourdomain.com""",
            "tags": ["Headers", "HTTP", "Security", "Web Server"],
            "author": "admin",
            "is_public": True
        }
    ]

    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    for article in sample_articles:
        c.execute("""INSERT INTO knowledge_base 
                     (title, category, content, tags, author, created_date, updated_date, is_public, views) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (article["title"], article["category"], article["content"],
                   json.dumps(article["tags"]), article["author"], now, now,
                   1 if article["is_public"] else 0, 0))

    conn.commit()
    conn.close()
    print("Sample knowledge base articles added successfully!")

if __name__ == "__main__":
    add_sample_articles()