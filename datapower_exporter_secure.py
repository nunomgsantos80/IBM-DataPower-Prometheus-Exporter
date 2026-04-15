#!/usr/bin/env python3
import json
import os
import time
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.fernet import Fernet

CONFIG_FILE = "datapowers_secure.json"

# -------------------------------
# Password decryption
# -------------------------------
def decrypt_password(enc):
    key = os.getenv("DP_KEY")
    if not key:
        raise Exception("DP_KEY environment variable not set")
    cipher = Fernet(key.encode())
    return cipher.decrypt(enc.encode()).decode()

# -------------------------------
# Load configuration
# -------------------------------
def load_config():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

config = load_config()
appliances = config["appliances"]
refresh_interval = config["global"]["refresh_interval"]
exporter_port = config["global"]["exporter_port"]

# -------------------------------
# Cache system
# -------------------------------
cache = {}
cache_ttl = {
    "cpu": 10,
    "memory": 10,
    "tps": 10,
    "latency": 10,
    "interfaces": 30,
    "apigw": 30,
    "http": 30,
    "peering": 30,
    "filesystem": 60,
    "uptime": 60,
    "objectstatus": 120
}

def cache_get(key):
    if key in cache:
        value, ts, ttl = cache[key]
        if time.time() - ts < ttl:
            return value
    return None

def cache_set(key, value, ttl):
    cache[key] = (value, time.time(), ttl)

# -------------------------------
# Run curl command
# -------------------------------
def run_curl(url, user, password):
    try:
        cmd = ["curl", "-sk", "-u", f"{user}:{password}", url]
        result = subprocess.check_output(cmd).decode()
        return result
    except Exception:
        return None

# -------------------------------
# Collect metrics
# -------------------------------
def collect_metrics():
    output = []

    for ap in appliances:
        name = ap["name"]
        host = ap["host"]
        user = ap["user"]

        # Password handling
        if "password_enc" in ap:
            password = decrypt_password(ap["password_enc"])
        else:
            password = ap["password"]

        # Example metric (CPU)
        cache_key = f"cpu_{name}"
        cached = cache_get(cache_key)
        if cached:
            output.append(cached)
        else:
            url = f"https://{host}:5554/mgmt/status/default/CPUUsage"
            data = run_curl(url, user, password)
            if data:
                metric = f'datapower_cpu_usage{{appliance="{name}"}} {data.strip()}'
                output.append(metric)
                cache_set(cache_key, metric, cache_ttl["cpu"])

    return "\n".join(output)

# -------------------------------
# HTTP Server
# -------------------------------
class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            metrics = collect_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(metrics.encode())
        else:
            self.send_response(404)
            self.end_headers()

# -------------------------------
# Main
# -------------------------------
def main():
    print(f"Starting DataPower exporter on port {exporter_port}")
    server = HTTPServer(("0.0.0.0", exporter_port), MetricsHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
