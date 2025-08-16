import os
import hashlib
import sqlite3

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

# Unsafe use of eval
user_input = input("Enter a command: ")
eval(user_input)

# Insecure hashing
password = "user_password"
hashed = hashlib.md5(password.encode()).hexdigest()
print("Hashed password:", hashed)

# SQL injection vulnerability
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

username = input("Enter username: ")
query = f"SELECT * FROM users WHERE name = '{username}'"
cursor.execute(query)
print(cursor.fetchall())
