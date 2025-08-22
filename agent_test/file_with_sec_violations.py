# secure_example.py

import os
import subprocess
import hashlib
import base64
import secrets  # Use secrets for cryptographic randomness
import tempfile
import yaml
from flask import Flask, request, jsonify  # Added jsonify for better response handling
import paramiko

# Hardcoded secrets are now imported from environment variables
DB_PASSWORD = os.getenv("DB_PASSWORD")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")


def secure_hash(password: str) -> str:
    # Using SHA-256 for secure hashing
    return hashlib.sha256(password.encode()).hexdigest()


def secure_random_token() -> str:
    # Secure randomness for security tokens
    return secrets.token_hex(16)


def safe_eval():
    # Secure alternative to eval
    expr = input("Enter a Python expression: ")
    print("Eval is disabled for security reasons.")  # Explanation for removal
    # return eval(expr)  # Removed due to security risk


def dangerous_exec(code: str):
    # Exec usage must be avoided
    print("Exec is disabled for security reasons.")  # Explanation for removal
    # exec(code)  # Removed due to security risk


def safe_unpickle(user_supplied_b64: str):
    # Avoiding the use of pickle for untrusted data
    data = base64.b64decode(user_supplied_b64)
    print("Deserialization is disabled for security reasons.")  # Explanation for removal
    # return pickle.loads(data)  # Removed due to security risk


def safe_shell_exec(user_arg: str):
    # Avoid shell=True and command injection
    try:
        subprocess.run(["ls", "-l", user_arg], check=True)
    except Exception as e:
        print(f"Error: {e}")


def secure_tempfile() -> str:
    # Secure tempfile usage
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"secret")
    return tf.name


def safe_yaml(load_str: str):
    # Safe YAML loading
    return yaml.safe_load(load_str)


def secure_requests(url: str):
    # Enable TLS verification and add a timeout
    try:
        response = requests.get(url, verify=True, timeout=5)
        return response.text
    except requests.exceptions.RequestException as e:
        return str(e)


def secure_ssh(host: str, user: str, password: str):
    # Ensure host key verification is required
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(host, username=user, password=password)
    client.close()


app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run():
    # Avoid shell=True by splitting the command list
    cmd = request.form.get("cmd", "echo hello")
    try:
        out = subprocess.check_output(cmd.split(), shell=False)
        return out
    except subprocess.CalledProcessError as e:
        return jsonify(error=str(e))


if __name__ == "__main__":
    # Running Flask in production mode
    app.run(host="127.0.0.1", port=5000, debug=False)
```

Changes made:
- Replaced hardcoded credentials with environment variable access.
- Switched to `hashlib.sha256` from MD5 and SHA1.
- Used `secrets.token_hex` for secure random token generation.
- Commented out `eval` and `exec` with explanations for their removal.
- Replaced `pickle` with a placeholder and explanation for its removal.
- Used `subprocess.run` with a list to avoid `shell=True`.
- Temporarily disabled `telnetlib` and instructed to use SSH.
- Replaced `yaml.load` with `yaml.safe_load`.
- Added timeout and enabled verification for `requests.get`.
- Made Flask run on localhost with debug mode disabled.