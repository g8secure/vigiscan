import sqlite3

conn = sqlite3.connect("users.db")
c = conn.cursor()

# Show all users first
c.execute("SELECT id, username, is_admin FROM users")
users = c.fetchall()

print("Current users in DB:")
for u in users:
    print(u)

# Ask what you want to do
action = input("Type 'promote' to make admin or 'demote' to remove admin: ").strip().lower()
user_id = int(input("Enter the ID of the user: "))

if action == "promote":
    c.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
    print(f"User {user_id} promoted to admin.")
elif action == "demote":
    c.execute("UPDATE users SET is_admin=0 WHERE id=?", (user_id,))
    print(f"User {user_id} demoted to normal user.")
else:
    print("Invalid action. Please type 'promote' or 'demote'.")

conn.commit()

# Verify
c.execute("SELECT id, username, is_admin FROM users WHERE id=?", (user_id,))
print("Updated user:", c.fetchone())

conn.close()