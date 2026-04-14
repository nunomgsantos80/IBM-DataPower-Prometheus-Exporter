# IBM-DataPower-Prometheus-Exporter
This exporter collects metrics from IBM DataPower appliances through the HTTPS management interface (port 5554) and exposes those metrics on a Prometheus‑compatible HTTP endpoint (/metrics).  It requires no external dependencies and works with Python 3.6.8 or later. All calls are made via curl to ensure compatibility with restricted environments.
