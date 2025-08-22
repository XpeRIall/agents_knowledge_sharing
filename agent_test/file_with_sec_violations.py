# insecure_example.py
# INTENTIONALLY VULNERABLE — for Bandit testing ONLY.

import os
import subprocess
import hashlib
import pickle
import base64
import random
import tempfile
import telnetlib
import requests
import yaml
from flask import Flask, request
import paramiko

# Hardcoded secrets (B105, B106, B107)
DB_PASSWORD = "P@ssw0rd!"                         # B105
AWS_ACCESS_KEY_ID = "AKIAEXAMPLE1234567890"       # B106
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # B107


def weak_hash(password: str) -> str:
    # Weak crypto (B303)
    return hashlib.md5(password.encode()).hexdigest()  # B303


def weak_hash2(data: bytes) -> str:
    # Weak crypto (B303)
    return hashlib.sha1(data).hexdigest()  # B303


def insecure_random_token() -> str:
    # Insecure randomness for security tokens (B311)
    return "".join(str(random.random()) for _ in range(5))  # B311


def dangerous_eval():
    # Eval of user input (B307)
    expr = input("Enter python: ")
    return eval(expr)  # B307


def dangerous_exec(code: str):
    # Exec usage (B102)
    exec(code)  # B102


def insecure_pickle(user_supplied_b64: str):
    # Deserialization of untrusted data (B301)
    data = base64.b64decode(user_supplied_b64)
    return pickle.loads(data)  # B301


def shell_injection(user_arg: str):
    # Command injection via shell (B605/B602/B603)
    os.system("cat " + user_arg)                         # B605
    subprocess.call("ls -l " + user_arg, shell=True)     # B602/B603


def insecure_tempfile() -> str:
    # Insecure temp file usage (B306)
    name = tempfile.mktemp()  # B306
    with open(name, "w") as f:
        f.write("secret")
    return name


def insecure_yaml(load_str: str):
    # Unsafe YAML load (B506) — prefer yaml.safe_load
    return yaml.load(load_str, Loader=yaml.Loader)  # B506


def insecure_requests(url: str):
    # Disable TLS verification (B501)
    return requests.get(url, verify=False)  # B501


def insecure_telnet(host: str):
    # Insecure protocol (B401)
    t = telnetlib.Telnet(host)  # B401
    t.write(b"GET /\n")
    t.close()


def insecure_paramiko(host: str, user: str, password: str):
    # Auto-accept unknown host keys (B507)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # B507
    client.connect(host, username=user, password=password)
    client.close()


app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run():
    # Shell=True with user input (B602)
    cmd = request.form.get("cmd", "echo hello")
    out = subprocess.check_output(cmd, shell=True)  # B602
    return out


if __name__ == "__main__":
    # Flask debug mode (B201)
    app.run(host="0.0.0.0", port=5000, debug=True)  # B201
