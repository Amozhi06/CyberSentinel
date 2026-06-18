import sqlite3

conn = sqlite3.connect("cybersentinel.db")
cur = conn.cursor()

cur.execute("SELECT * FROM users")
rows = cur.fetchall()

print(f"Total users: {len(rows)}")

for row in rows:
    print(row)

conn.close()