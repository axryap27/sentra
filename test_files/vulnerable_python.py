# Python vulnerability test file
import os
import pickle
import subprocess

def process_data(user_input):
    # Code injection vulnerabilities
    eval(f"result = {user_input}")
    exec(f"print({user_input})")
    
    # Command injection
    os.system(f"ls {user_input}")
    subprocess.run(f"echo {user_input}", shell=True)
    
    # Unsafe deserialization
    data = pickle.load(open('data.pkl', 'rb'))
    
    # Weak cryptography 
    import hashlib
    weak_hash = hashlib.md5(user_input.encode()).hexdigest()
    
    return result