import sqlite3
from werkzeug.security import generate_password_hash
import pyotp

# ✅ Your admin account details
ADMIN_USERNAME = "Abrahamdagr8"        # your admin username
NEW_PASSWORD = "StrongPassword123!"    # your new password

# Connect to the database
conn = sqlite3.connect("users.db")
c = conn.cursor()

# Generate a hashed password
hashed_pw = generate_password_hash(NEW_PASSWORD)

# Generate a fresh 2FA secret
otp_secret = pyotp.random_base32()

# Update or insert the admin account
c.execute("SELECT * FROM users WHERE username=?", (ADMIN_USERNAME,))
user = c.fetchone()

if user:
    c.execute("UPDATE users SET password=?, otp_secret=?, is_admin=1 WHERE username=?",
              (hashed_pw, otp_secret, ADMIN_USERNAME))
else:
    c.execute("INSERT INTO users (username, password, otp_secret, is_admin) VALUES (?, ?, ?, 1)",
              (ADMIN_USERNAME, hashed_pw, otp_secret))

conn.commit()
conn.close()

print(f"✅ Admin account '{ADMIN_USERNAME}' reset successfully.")
print(f"➡️ New password: {NEW_PASSWORD}")
print(f"➡️ Scan this QR in Google Authenticator: otpauth://totp/VigiScan:{ADMIN_USERNAME}?secret={otp_secret}&issuer=VigiScan")
