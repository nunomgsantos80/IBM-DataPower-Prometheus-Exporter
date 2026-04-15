# IBM-DataPower-Prometheus-Exporter
This exporter collects metrics from IBM DataPower appliances through the HTTPS management interface (port 5554) and exposes those metrics on a Prometheus‑compatible HTTP endpoint (/metrics).  It requires no external dependencies and works with Python 3.6.8 or later. All calls are made via curl to ensure compatibility with restricted environments.

**Files:**

datapower_exporter.py → Full exporter

datapowers.json → Configuration example

README.txt → This file


**Make sure you have Python 3 installed:**
python3 --version

**Make the script executable:**
chmod +x datapower_exporter.py

**Run the exporter:**
nohup python3 datapower_exporter.py >/dev/null 2>&1 &

**Access the metrics in a browser or via curl:**
http://localhost:9101/metrics



# datapowers.json

The configuration file defines:

Exporter port
Refresh interval
List of DataPower appliances

**Example:**

{
"global": {
"exporter_port": 9101,
"refresh_interval": 15
},
"appliances": [
{
"name": "dp1",
"host": "10.0.0.10",
"user": "admin",
"password": "password"
}
]
}

**Each appliance must include:**

**name →** Logical name (used in metrics)

**host →** DataPower IP or hostname

**user →** Username with read permissions

**password →** Corresponding password



# The exporter collects global and per‑domain metrics.

**Global metrics:**

datapower_cpu_usage

datapower_memory_total / used / free / pressure

datapower_system_load

datapower_system_worklist

datapower_fs_total_* and datapower_fs_free_*

datapower_interface_status

datapower_interface_rx_bytes

datapower_interface_tx_bytes

**Per‑domain metrics:**

datapower_domain_status

datapower_domainsettings_opstate

datapower_domainsettings_adminstate

datapower_xmlmanager_opstate

datapower_api_gateway_status

datapower_http_service_status

datapower_tps

datapower_http_mean_tx_ms (10s, 1m, 10m, 1h, 1d)

datapower_uptime_seconds

datapower_boot_uptime_seconds

**Gateway Peering:**

datapower_gateway_peering_link_status

datapower_gateway_peering_pending_updates


# Caching e performance

The exporter uses an internal cache with different TTLs per endpoint:

10s → CPU, memory, TPS, latency

30s → interfaces, API Gateway, HTTP Services, Gateway Peering

60s → filesystem, uptime

120s → ObjectStatus (heavy)

If an endpoint fails, the exporter keeps the previous value.


# Logs are sent to stdout and include:

Cycle start

Execution time

Endpoint failures

Cache warnings

Global timeouts

# Testing
curl http://localhost:9101/metrics

You should see metrics such as:

datapower_cpu_usage{appliance="dp1"} 12
datapower_system_load{appliance="dp1"} 0.42
datapower_gateway_peering_link_status{appliance="dp1",domain="prod",name="peer1"} 1

# Add to prometheus.yml:

scrape_configs:

job_name: "datapower"
static_configs:

targets: ["localhost:9101"]

# Images from Grafana
<img width="789" height="331" alt="image" src="https://github.com/user-attachments/assets/fa695a58-cc6e-4991-b807-a906e637ea29" />
<img width="773" height="264" alt="image" src="https://github.com/user-attachments/assets/ecbd47fa-d3ff-4e67-854c-d0811b881d67" />
<img width="1549" height="301" alt="image" src="https://github.com/user-attachments/assets/1266bd6e-dbef-4d4a-aff3-99c5e446fd78" />
<img width="1322" height="332" alt="image" src="https://github.com/user-attachments/assets/11ac04c0-f368-4b54-8129-a86b726b4601" />



# Release Notes — Upcoming Version - v1.0b

**New Feature: Encrypted Password Storage in JSON**

The next version introduces a significant security enhancement: all passwords stored in the JSON configuration file will now be encrypted.
This update strengthens credential protection, reduces exposure risks, and aligns the project with best practices for secure configuration management.

**Example:**
<img width="1161" height="168" alt="image" src="https://github.com/user-attachments/assets/2f43e81b-0729-4337-9311-53f756ae51a9" />

## Security: Encrypted Passwords

The exporter now supports encrypted passwords using AES/Fernet.

### How it works
- A secret key (`DP_KEY`) is stored as an environment variable. **KEEP THIS KEY to avoid regenerate all process.** In case of an reboot e can use the same DP_KEY without change **JSON FILE**.
- Passwords are encrypted once and stored in `datapowers_secure.json` as `password_enc`.
- The exporter decrypts the password at runtime.

### Steps

1. Generate a key and encrypt a password:
   python3 encrypt_password.py

2. Export the key:
   export DP_KEY="your_generated_key"

3. Add the encrypted password to **datapowers_secure.json**:
   "password_enc": "gAAAAABl..."

This ensures no plaintext passwords exist in the repository.


