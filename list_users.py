import sqlite3

# Connect to your database
conn = sqlite3.connect("users.db")
c = conn.cursor()

# Fetch all users
c.execute("SELECT id, username FROM users")
rows = c.fetchall()

conn.close()

# Print results
print("Current users in the database:")
for r in rows:
    print(f"ID: {r[0]}, Username: {r[1]}")
