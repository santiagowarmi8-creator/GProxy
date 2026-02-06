import sqlite3

conn = sqlite3.connect("data.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS ordenes(
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER,
cantidad INTEGER,
tipo TEXT,
estado TEXT
)
""")

conn.commit()
