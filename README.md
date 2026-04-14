# IBM-DataPower-Prometheus-Exporter
This exporter collects metrics from IBM DataPower appliances through the HTTPS management interface (port 5554) and exposes those metrics on a Prometheus‑compatible HTTP endpoint (/metrics).  It requires no external dependencies and works with Python 3.6.8 or later. All calls are made via curl to ensure compatibility with restricted environments.

Files:

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
