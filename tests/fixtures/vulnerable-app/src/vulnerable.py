import hashlib
import os
import pickle
import requests
import yaml

# Intentionally vulnerable SAST fixture (Python) for Indicative regression testing.

def get_account_unsafe(cursor, account_id):
    # Expected: indicative.python.sql-injection.cursor-execute
    cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")

def run_diagnostics_unsafe(target):
    # Expected: indicative.python.command-injection.shell-true
    os.system("nslookup " + target)

def hash_token_weak(token: bytes):
    # Expected: indicative.python.insecure-crypto.weak-hash
    return hashlib.sha1(token).hexdigest()

def load_session_unsafe(raw_bytes: bytes):
    # Expected: indicative.python.unsafe-deserialization.pickle-yaml
    return pickle.loads(raw_bytes)

def load_yaml_unsafe(raw_yaml: str):
    # Expected: indicative.python.unsafe-deserialization.pickle-yaml
    return yaml.load(raw_yaml, Loader=yaml.Loader)

def fetch_internal_unsafe(url: str):
    # Expected: indicative.python.insecure-auth.tls-disabled
    return requests.get(url, verify=False, timeout=5)
