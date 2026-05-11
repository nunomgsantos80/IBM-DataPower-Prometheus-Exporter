#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import json
import time
import threading
import re
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from cryptography.fernet import Fernet

CONFIG_FILE = "datapowers.json"
metrics_text = ""
metrics_lock = threading.Lock()

# ============================================================
#  LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("datapower_exporter")

# ============================================================
#  PASSWORD DECRYPTION
# ============================================================

def decrypt_password(enc):
    key = os.getenv("DP_KEY")
    if not key:
        raise Exception("DP_KEY environment variable not set")
    cipher = Fernet(key.encode())
    return cipher.decrypt(enc.encode()).decode()

def get_password(dp):
    if "password_enc" in dp:
        return decrypt_password(dp["password_enc"])
    return dp["password"]

# ============================================================
#  PROMETHEUS LABEL ESCAPING
# ============================================================

def prom_escape(value):
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\t", "\\t")
    return s

# ============================================================
#  HTTP SERVER MULTI-THREAD
# ============================================================

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

# ============================================================
#  CACHE
# ============================================================

cache = {}

def cached_fetch(key, ttl, fetch_fn):
    now = time.time()
    entry = cache.get(key, {"ts": 0, "data": None})

    if now - entry["ts"] > ttl:
        data = fetch_fn()
        if data is None:
            log.warning("Falha ao atualizar cache para %s — mantendo valor antigo", key)
            return entry["data"]
        cache[key] = {"ts": now, "data": data}
        return data

    return entry["data"]

# ============================================================
#  CONFIG
# ============================================================

def load_config():
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception as e:
        log.error("Falha ao carregar %s: %s", CONFIG_FILE, e)
        exit(1)

# ============================================================
#  CURL + RETRY
# ============================================================

def call_curl_once(url, user, password, timeout=10):
    cmd = [
        "curl", "-k", "-s",
        "--max-time", str(timeout),
        "-u", "{}:{}".format(user, password),
        "-H", "Accept: application/json",
        url
    ]
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        data = json.loads(result)
        if not isinstance(data, dict):
            log.warning("Resposta inválida de %s", url)
            return None
        return data
    except Exception as e:
        log.warning("Erro curl %s: %s", url, e)
        return None

def call_curl(url, user, password, retries=3, timeout=10):
    for attempt in range(retries):
        data = call_curl_once(url, user, password, timeout)
        if data is not None:
            return data
        time.sleep(0.2 * (2 ** attempt))
    log.error("Falha definitiva ao chamar %s", url)
    return None

# ============================================================
#  HELPERS
# ============================================================

def get_status(dp, domain, endpoint):
    url = "https://{}:5554/mgmt/status/{}/{}".format(dp["host"], domain, endpoint)
    return call_curl(url, dp["user"], get_password(dp))

def detect_gateway_type(entry):
    if isinstance(entry, dict) and entry.get("serviceClass") == "apiGateway":
        return "v10"
    if isinstance(entry, list):
        return "v5"
    return "unknown"

def get_service_name(entry, domain):
    return next(
        (entry.get(k) for k in ("proxy", "service", "name") if entry.get(k)),
        domain
    )

# ============================================================
#  MÉTRICAS
# ============================================================

def generate_metrics(config):
    output = []

    for dp in config["appliances"]:
        name_raw = dp["name"]
        name = prom_escape(name_raw)

        log.info("Recolhendo métricas de %s", name_raw)

        # ====================================================
        #  MÉTRICAS GLOBAIS
        # ====================================================

        cpu = cached_fetch(
            f"{name_raw}_cpu", 10,
            lambda: get_status(dp, "default", "CPUUsage")
        )
        if isinstance(cpu, dict):
            output.append(
                f'datapower_cpu_usage{{appliance="{name}"}} {cpu.get("CPUUsage", {}).get("oneMinute", 0)}'
            )

        mem = cached_fetch(
            f"{name_raw}_memory", 10,
            lambda: get_status(dp, "default", "MemoryStatus")
        )
        if isinstance(mem, dict):
            m = mem.get("MemoryStatus", {})
            output.append(f'datapower_memory_total{{appliance="{name}"}} {m.get("TotalMemory", 0)}')
            output.append(f'datapower_memory_used{{appliance="{name}"}} {m.get("UsedMemory", 0)}')
            output.append(f'datapower_memory_free{{appliance="{name}"}} {m.get("FreeMemory", 0)}')
            output.append(f'datapower_memory_pressure{{appliance="{name}"}} {m.get("Usage", 0)}')
            output.append(f'datapower_request_memory{{appliance="{name}"}} {m.get("ReqMemory", 0)}')

        sys_data = cached_fetch(
            f"{name_raw}_system", 10,
            lambda: get_status(dp, "default", "SystemUsage")
        )
        if isinstance(sys_data, dict) and "SystemUsage" in sys_data:
            sys = sys_data["SystemUsage"]
            output.append(
                f'datapower_system_load{{appliance="{name}"}} {sys.get("Load", 0)}'
            )
            output.append(
                f'datapower_system_worklist{{appliance="{name}"}} {sys.get("WorkList", 0)}'
            )

        # ====================================================
        #  FILESYSTEMSTATUS
        # ====================================================

        fs = cached_fetch(
            f"{name_raw}_fs", 60,
            lambda: get_status(dp, "default", "FilesystemStatus")
        )

        if isinstance(fs, dict) and "FilesystemStatus" in fs:
            f = fs["FilesystemStatus"]
            output.append(f'datapower_fs_free_encrypted{{appliance="{name}"}} {f.get("FreeEncrypted", 0)}')
            output.append(f'datapower_fs_total_encrypted{{appliance="{name}"}} {f.get("TotalEncrypted", 0)}')
            output.append(f'datapower_fs_free_temporary{{appliance="{name}"}} {f.get("FreeTemporary", 0)}')
            output.append(f'datapower_fs_total_temporary{{appliance="{name}"}} {f.get("TotalTemporary", 0)}')
            output.append(f'datapower_fs_free_internal{{appliance="{name}"}} {f.get("FreeInternal", 0)}')
            output.append(f'datapower_fs_total_internal{{appliance="{name}"}} {f.get("TotalInternal", 0)}')

        # ====================================================
        #  INTERFACES
        # ====================================================

        iface = cached_fetch(
            f"{name_raw}_iface", 30,
            lambda: get_status(dp, "default", "EthernetInterfaceStatus")
        )

        if isinstance(iface, dict) and "EthernetInterfaceStatus" in iface:
            for i in iface["EthernetInterfaceStatus"]:
                if not isinstance(i, dict):
                    continue

                iname_raw = i.get("Name", "unknown")
                iname = prom_escape(iname_raw)

                status = 1 if i.get("Status", "").lower() in ["ok", "up"] else 0

                rx = i.get("RxHCBytes") or i.get("RxBytes") or 0
                tx = i.get("TxHCBytes") or i.get("TxBytes") or 0

                output.append(
                    f'datapower_interface_status{{appliance="{name}",interface="{iname}"}} {status}'
                )
                output.append(
                    f'datapower_interface_rx_bytes{{appliance="{name}",interface="{iname}"}} {rx}'
                )
                output.append(
                    f'datapower_interface_tx_bytes{{appliance="{name}",interface="{iname}"}} {tx}'
                )

        # ====================================================
        #  DOMÍNIOS
        # ====================================================

        domains = cached_fetch(
            f"{name_raw}_domains", 30,
            lambda: get_status(dp, "default", "DomainStatus")
        )
        if not isinstance(domains, dict):
            continue

        for dom in domains.get("DomainStatus", []):
            if not isinstance(dom, dict):
                continue

            domain_raw = dom.get("Domain")
            domain = prom_escape(domain_raw)

            op = 1 if dom.get("OpState", "").lower() == "up" else 0
            output.append(
                f'datapower_domain_status{{appliance="{name}",domain="{domain}"}} {op}'
            )

            # ====================================================
            #  OBJECTSTATUS (DomainSettings + XMLManager)
            # ====================================================

            obj = cached_fetch(
                f"{name_raw}_{domain_raw}_objects", 120,
                lambda: get_status(dp, domain_raw, "ObjectStatus")
            )

            if isinstance(obj, dict) and "ObjectStatus" in obj:

                # DomainSettings
                for ds in obj["ObjectStatus"]:
                    if not isinstance(ds, dict):
                        continue

                    if ds.get("Class") == "DomainSettings":
                        ds_name_raw = ds.get("Name", "domain-settings")
                        ds_name = prom_escape(ds_name_raw)

                        opstate = 1 if ds.get("OpState") == "up" else 0
                        adminstate = 1 if ds.get("AdminState") == "enabled" else 0

                        output.append(
                            f'datapower_domainsettings_opstate{{appliance="{name}",domain="{domain}",object="{ds_name}"}} {opstate}'
                        )
                        output.append(
                            f'datapower_domainsettings_adminstate{{appliance="{name}",domain="{domain}",object="{ds_name}"}} {adminstate}'
                        )

                # XMLManager
                for xm in obj["ObjectStatus"]:
                    if not isinstance(xm, dict):
                        continue

                    if xm.get("Class") == "XMLManager":
                        xml_name_raw = xm.get("Name", "xml-manager")
                        xml_name = prom_escape(xml_name_raw)

                        xml_op = 1 if xm.get("OpState") == "up" else 0

                        output.append(
                            f'datapower_xmlmanager_opstate{{appliance="{name}",domain="{domain}",object="{xml_name}"}} {xml_op}'
                        )

            # ====================================================
            #  APIHTTPConnections (APIC v10)
            # ====================================================

            apihttp = cached_fetch(
                f"{name_raw}_{domain_raw}_apihttpconnections", 30,
                lambda: get_status(dp, domain_raw, "APIHTTPConnections")
            )

            if isinstance(apihttp, dict) and "APIHTTPConnections" in apihttp:
                c = apihttp["APIHTTPConnections"]

                metrics_map = {
                    "requests": [
                        ("10s", "reqTenSec"),
                        ("1m", "reqOneMin"),
                        ("10m", "reqTenMin"),
                        ("1h", "reqOneHr"),
                        ("1d", "reqOneDay"),
                    ],
                    "reuse": [
                        ("10s", "reuseTenSec"),
                        ("1m", "reuseOneMin"),
                        ("10m", "reuseTenMin"),
                        ("1h", "reuseOneHr"),
                        ("1d", "reuseOneDay"),
                    ],
                    "create": [
                        ("10s", "createTenSec"),
                        ("1m", "createOneMin"),
                        ("10m", "createTenMin"),
                        ("1h", "createOneHr"),
                        ("1d", "createOneDay"),
                    ],
                    "return": [
                        ("10s", "returnTenSec"),
                        ("1m", "returnOneMin"),
                        ("10m", "returnTenMin"),
                        ("1h", "returnOneHr"),
                        ("1d", "returnOneDay"),
                    ],
                    "offer": [
                        ("10s", "offerTenSec"),
                        ("1m", "offerOneMin"),
                        ("10m", "offerTenMin"),
                        ("1h", "offerOneHr"),
                        ("1d", "offerOneDay"),
                    ],
                    "destroy": [
                        ("10s", "destroyTenSec"),
                        ("1m", "destroyOneMin"),
                        ("10m", "destroyTenMin"),
                        ("1h", "destroyOneHr"),
                        ("1d", "destroyOneDay"),
                    ],
                }

                for metric_name, intervals in metrics_map.items():
                    for label, key in intervals:
                        value = c.get(key, 0)
                        output.append(
                            f'datapower_apihttpconnections_{metric_name}{{appliance="{name}",domain="{domain}",interval="{label}"}} {value}'
                        )

            # ====================================================
            #  TPS UNIVERSAL
            # ====================================================

            trx = cached_fetch(
                f"{name_raw}_{domain_raw}_tps", 10,
                lambda: get_status(dp, domain_raw, "HTTPTransactions2")
            )
            if isinstance(trx, dict) and "HTTPTransactions2" in trx:
                raw_t = trx["HTTPTransactions2"]
                gw_type_raw = detect_gateway_type(raw_t)
                gw_type = prom_escape(gw_type_raw)

                if isinstance(raw_t, dict):
                    entries_t = [raw_t]
                elif isinstance(raw_t, list):
                    entries_t = [e for e in raw_t if isinstance(e, dict)]
                else:
                    entries_t = []

                for entry in entries_t:
                    svc_raw = get_service_name(entry, domain_raw)
                    svc = prom_escape(svc_raw)

                    output.append(
                        f'datapower_tps{{appliance="{name}",domain="{domain}",service="{svc}",gateway_type="{gw_type}"}} {entry.get("tenSeconds", 0)}'
                    )

            # ====================================================
            #  LATÊNCIA UNIVERSAL
            # ====================================================

            lat = cached_fetch(
                f"{name_raw}_{domain_raw}_latency", 10,
                lambda: get_status(dp, domain_raw, "HTTPMeanTransactionTime2")
            )

            if domain_raw != "default" and isinstance(lat, dict) and "HTTPMeanTransactionTime2" in lat:
                raw = lat["HTTPMeanTransactionTime2"]
                gw_type_raw = detect_gateway_type(raw)
                gw_type = prom_escape(gw_type_raw)

                if isinstance(raw, dict):
                    entries = [raw]
                elif isinstance(raw, list):
                    entries = [e for e in raw if isinstance(e, dict)]
                else:
                    entries = []

                for entry in entries:
                    svc_raw = get_service_name(entry, domain_raw)
                    svc = prom_escape(svc_raw)

                    for label, key in [
                        ("10s", "tenSeconds"),
                        ("1m", "oneMinute"),
                        ("10m", "tenMinutes"),
                        ("1h", "oneHour"),
                        ("1d", "oneDay")
                    ]:
                        lbl = prom_escape(label)
                        output.append(
                            f'datapower_http_mean_tx_ms{{appliance="{name}",domain="{domain}",service="{svc}",interval="{lbl}",gateway_type="{gw_type}"}} {entry.get(key, 0)}'
                        )

            # ====================================================
            #  UPTIME (DEFAULT DOMAIN)
            # ====================================================

            if domain_raw == "default":
                dt = cached_fetch(
                    f"{name_raw}_uptime", 60,
                    lambda: get_status(dp, "default", "DateTimeStatus")
                )
                if isinstance(dt, dict) and "DateTimeStatus" in dt:
                    d = dt["DateTimeStatus"]
                    for key, metric in [
                        ("uptime2", "datapower_uptime_seconds"),
                        ("bootuptime2", "datapower_boot_uptime_seconds")
                    ]:
                        txt = d.get(key, "0 days 00:00:00")
                        m = re.search(r"(?:(\d+)\s+days?,\s+)?(\d+):(\d+):(\d+)", txt)
                        if m:
                            days = int(m.group(1)) if m.group(1) else 0
                            hours = int(m.group(2))
                            minutes = int(m.group(3))
                            seconds = int(m.group(4))
                            sec = days * 86400 + hours * 3600 + minutes * 60 + seconds
                            output.append(
                                f'{metric}{{appliance="{name}",domain="{domain}"}} {sec}'
                            )

    return "\n".join(output)

# ============================================================
#  CICLO COM TIMEOUT
# ============================================================

def run_cycle_with_timeout(config, interval):
    result = {"done": False}

    def worker():
        try:
            data = generate_metrics(config)
            global metrics_text
            with metrics_lock:
                metrics_text = data
            result["done"] = True
        except Exception as e:
            log.error("Erro no ciclo: %s", e)

    t = threading.Thread(target=worker)
    t.start()
    t.join(interval * 0.8)

    if not result["done"]:
        log.warning("Timeout global — mantendo métricas anteriores")

# ============================================================
#  HTTP SERVER
# ============================================================

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            with metrics_lock:
                self.wfile.write(metrics_text.encode())
        else:
            self.send_response(404)
            self.end_headers()

# ============================================================
#  MAIN LOOP
# ============================================================

def metrics_updater(config, interval):
    while True:
        start = time.time()
        run_cycle_with_timeout(config, interval)
        elapsed = time.time() - start
        log.info("Ciclo concluído em %.2fs", elapsed)
        time.sleep(max(0, interval - elapsed))

# ============================================================
#  MAIN
# ============================================================

def main():
    config = load_config()
    port = config["global"]["exporter_port"]
    interval = config["global"]["refresh_interval"]

    log.info("Exporter ativo na porta %s", port)
    log.info("Monitorizando %s DataPowers", len(config["appliances"]))

    t = threading.Thread(target=metrics_updater, args=(config, interval), daemon=True)
    t.start()

    server = ThreadedHTTPServer(("", port), MetricsHandler)
    server.serve_forever()

if __name__ == "__main__":
    main()
