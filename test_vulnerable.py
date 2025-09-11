# Test file with intentional vulnerabilities for testing

import os
import subprocess
import pickle
import hashlib

# High severity issues
def dangerous_eval():
    user_input = "print('hello')"
    eval(user_input)  # Code injection vulnerability

def unsafe_subprocess():
    command = "ls -la"
    subprocess.run(command, shell=True)  # Command injection

def unsafe_pickle():
    with open('data.pkl', 'rb') as f:
        pickle.load(f)  # Unsafe deserialization

# Medium severity issues  
def weak_hash():
    password = "secret123"
    hashlib.md5(password.encode()).hexdigest()  # Weak hash
    hashlib.sha1(password.encode()).hexdigest()  # Weak hash

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
SECRET = "my_secret_password"

# SQL injection example
def unsafe_query(user_id):
    query = "SELECT * FROM users WHERE id = %s" % user_id
    db.execute(query)  # SQL injection risk