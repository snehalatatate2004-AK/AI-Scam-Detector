import sqlite3

conn = sqlite3.connect("scam.db")
cursor = conn.cursor()

cursor.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    ("admin", "Admin123")
)

conn.commit()
conn.close()

print("Admin user created successfully!")