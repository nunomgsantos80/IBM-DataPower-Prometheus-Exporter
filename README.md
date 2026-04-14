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
