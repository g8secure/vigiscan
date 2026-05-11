import sqlite3

# Connect to your database file
conn = sqlite3.connect("users.db")
c = conn.cursor()

# Delete the unwanted user
c.execute("DELETE FROM users WHERE username=?", ("0W45pz4p",))

# Save changes
conn.commit()

# Close connection
conn.close()

print("User 0W45pz4p deleted successfully")
