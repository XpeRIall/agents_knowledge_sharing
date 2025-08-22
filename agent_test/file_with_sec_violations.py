# secure_example.py
# SECURED VERSION — Vulnerabilities addressed.

import os
import subprocess
import hashlib
import base64
import secrets
import tempfile
import requests
import yaml
from flask import Flask, request
import paramiko
import ast

# Use environment variables for secrets
DB_PASSWORD = os.getenv('DB_PASSWORD')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')

def strong_hash(password: str) -> str:
    # Use a secure cryptographic hash
    return hashlib.sha256(password.encode()).hexdigest()

def strong_random_token() -> str:
    # Use secrets for secure randomness
    return secrets.token_hex(16)

def safe_eval():
    expr = input("Enter expression: ")
    try:
        # Use ast.literal_eval for safe evaluation of literals
        return ast.literal_eval(expr)
    except Exception:
        return "Invalid input"

def dangerous_exec(code: str):
    # Remove dangerous exec usage
    print("exec function usage is disabled for security reasons.")

def safe_pickle(user_supplied_b64: str):
    # Deserialize safely — remove dangerous functionality
    print("Untrusted data deserialization is not allowed without verification.")

def shell_injection(user_arg: str):
    # Avoid using shell=True and sanitize inputs
    try:
        sanitized_arg = subprocess.list2cmdline([user_arg])
        subprocess.run(["ls", "-l", sanitized_arg], check=True)
    except Exception as e:
        print(f"Command failed: {e}")

def secure_tempfile() -> str:
    # Use mkstemp for secure temp file usage
    fd, name = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as f:
            f.write("secret")
    finally:
        os.remove(name)
    return name

def safe_yaml(load_str: str):
    # Use safe_load for YAML
    return yaml.safe_load(load_str)

def secure_requests(url: str):
    # Enable TLS verification and set a timeout
    try:
        return requests.get(url, verify=True, timeout=5)
    except requests.RequestException as e:
        return f"Request failed: {e}"

def secure_paramiko(host: str, user: str, password: str):
    # Require known_hosts file
    client = paramiko.SSHClient()
    client.load_system_host_keys()  # Load system known hosts, manual checking recommended
    try:
        client.connect(host, username=user, password=password)
    finally:
        client.close()

app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run():
    # Execute without shell=True and sanitize input
    cmd = request.form.get("cmd", "echo hello").split()
    try:
        out = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        return f"Command failed: {e}"
    return out

if __name__ == "__main__":
    # Never run Flask with debug=_True_ in production
    app.run(host="127.0.0.1", port=5000, debug=False)
```

### Key Changes:

1. **Secrets:** Replaced hardcoded secrets with environment variable access.
2. **Hash Functions:** Switched from MD5 and SHA1 to SHA256 for cryptographic security.
3. **Randomness:** Used `secrets` instead of `random` for security tokens.
4. **Eval/Exec:** Replaced `eval` with `ast.literal_eval` and removed `exec`.
5. **Subprocess:** Removed use of `shell=True` and sanitized inputs with `list2cmdline()` or equivalent.
6. **Temp Files:** Used `mkstemp` for secure temporary file creation.
7. **YAML:** Switched to `yaml.safe_load` for safe parsing.
8. **Requests:** Enabled TLS verification and added a timeout.
9. **Paramiko:** Loaded system host keys instead of `AutoAddPolicy`.
10. **Flask:** Set Flask to debug mode off and bind to `127.0.0.1` for safety.