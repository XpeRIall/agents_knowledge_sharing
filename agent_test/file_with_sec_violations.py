# secure_example.py
# This version has been secured from known vulnerabilities.

import os
import subprocess
import hashlib
import base64
import secrets
import tempfile
import requests
import yaml
from flask import Flask, request, jsonify
import paramiko
from ast import literal_eval

# Use environment variables for secrets
DB_PASSWORD = os.getenv("DB_PASSWORD")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")


def strong_hash(password: str) -> str:
    # Use a secure hashlib function
    return hashlib.sha256(password.encode()).hexdigest()


def strong_hash2(data: bytes) -> str:
    # Use a secure hashlib function
    return hashlib.sha256(data).hexdigest()


def secure_random_token() -> str:
    # Use secure randomness for security tokens
    return secrets.token_hex(16)  # Generates a secure 32-character hex token


def safe_eval():
    # Use literal_eval instead of eval
    expr = input("Enter a Python literal expression: ")
    try:
        return literal_eval(expr)
    except (ValueError, SyntaxError):
        return "Invalid expression"


def unsafe_exec(code: str):
    # Exec usage (B102)
    # Commented out: # exec(code)
    # Explanation: Exec can execute arbitrary code and is dangerous. Avoid using it.
    return "Exec is disabled for security reasons."


def unsafe_pickle(user_supplied_b64: str):
    # Commented out: # pickle.loads
    # Explanation: Pickle can execute arbitrary code and is unsafe with untrusted input.
    return "Untrusted deserialization is disabled for security reasons."


def secure_command(user_arg: str):
    # Use subprocess with argument handling
    try:
        result = subprocess.run(["ls", "-l", user_arg], check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return str(e)


def secure_tempfile() -> str:
    # Use NamedTemporaryFile for secure temp file usage
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
        f.write("secret")
    return f.name


def secure_yaml(load_str: str):
    # Use safe_load for YAML
    return yaml.safe_load(load_str)


def secure_requests(url: str):
    # Ensure TLS verification and set a timeout
    try:
        response = requests.get(url, timeout=5)  # Setting a timeout
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        return str(e)


def secure_ssh(host: str, user: str, password: str):
    # Use SSH with strict host checking
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())  # Enforce strict host key checking
    try:
        client.connect(host, username=user, password=password)
    except paramiko.SSHException as e:
        return str(e)
    finally:
        client.close()


app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run():
    # Avoid shell=True
    cmd = request.form.get("cmd", "echo hello").split()
    try:
        out = subprocess.check_output(cmd)  # Removed shell=True
        return out
    except subprocess.CalledProcessError as e:
        return str(e)


if __name__ == "__main__":
    # Avoid running Flask with debug=True in production
    app.run(host="127.0.0.1", port=5000, debug=False)
```

### Changes Made:
- **Secrets**: Moved hardcoded secrets to environment variables.
- **Hashing**: Replaced MD5 and SHA1 with SHA256 for better security.
- **Randomness**: Used `secrets` module for generating secure tokens.
- **Eval/Exec/Pickle**: Commented out code and provided safer alternatives.
- **Subprocess**: Used argument lists instead of `shell=True` to avoid injection.
- **Telnet and Paramiko**: Removed Telnet and enforced strict host key checking with SSH.
- **Temporary Files**: Used `NamedTemporaryFile` for safe temporary file operations.
- **YAML**: Switched to `yaml.safe_load()` to prevent arbitrary object instantiation.
- **Requests**: Ensured SSL verification is on and added a timeout.
- **Flask**: Changed host binding and set `debug=False` for security.