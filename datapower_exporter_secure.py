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

# ============================================================
#  MÉTRICAS
# ============================================================

def generate_metrics(config):
    output = []

    for dp in config["appliances"]:
        name = dp["name"]
        host = dp["host"]

        log.info("Recolhendo métricas de %s (%s)", name, host)

        # ====================================================
        #  MÉTRICAS GLOBAIS
        # ====================================================

        cpu = cached_fetch(
            f"{name}_cpu", 10,
            lambda: get_status(dp, "default", "CPUUsage")
        )
        if cpu:
            output.append(
                f'datapower_cpu_usage{{appliance="{name}"}} {cpu.get("CPUUsage", {}).get("oneMinute", 0)}'
            )

        mem = cached_fetch(
            f"{name}_memory", 10,
            lambda: get_status(dp, "default", "MemoryStatus")
        )
        if mem:
            m = mem.get("MemoryStatus", {})
            output.append(f'datapower_memory_total{{appliance="{name}"}} {m.get("TotalMemory", 0)}')
            output.append(f'datapower_memory_used{{appliance="{name}"}} {m.get("UsedMemory", 0)}')
            output.append(f'datapower_memory_free{{appliance="{name}"}} {m.get("FreeMemory", 0)}')
            output.append(f'datapower_memory_pressure{{appliance="{name}"}} {m.get("Usage", 0)}')

            # ====================================================
            #  ADICIONADO: ReqMemory (modo A → sempre exportado)
            # ====================================================
            req = m.get("ReqMemory", 0)
            output.append(f'datapower_request_memory{{appliance="{name}"}} {req}')

        sys_data = cached_fetch(
            f"{name}_system", 10,
            lambda: get_status(dp, "default", "SystemUsage")
        )

        if sys_data and "SystemUsage" in sys_data:
            sys = sys_data["SystemUsage"]
            output.append(
                f'datapower_system_load{{appliance="{name}"}} {sys.get("Load", 0)}'
            )
            output.append(
                f'datapower_system_worklist{{appliance="{name}"}} {sys.get("WorkList", 0)}'
            )

        fs = cached_fetch(
            f"{name}_fs", 60,
            lambda: get_status(dp, "default", "FilesystemStatus")
        )

        if fs and "FilesystemStatus" in fs:
            f = fs["FilesystemStatus"]
            output.append(f'datapower_fs_free_encrypted{{appliance="{name}"}} {f.get("FreeEncrypted", 0)}')
            output.append(f'datapower_fs_total_encrypted{{appliance="{name}"}} {f.get("TotalEncrypted", 0)}')
            output.append(f'datapower_fs_free_temporary{{appliance="{name}"}} {f.get("FreeTemporary", 0)}')
            output.append(f'datapower_fs_total_temporary{{appliance="{name}"}} {f.get("TotalTemporary", 0)}')
            output.append(f'datapower_fs_free_internal{{appliance="{name}"}} {f.get("FreeInternal", 0)}')
            output.append(f'datapower_fs_total_internal{{appliance="{name}"}} {f.get("TotalInternal", 0)}')

        iface = cached_fetch(
            f"{name}_iface", 30,
            lambda: get_status(dp, "default", "EthernetInterfaceStatus")
        )

        if iface and "EthernetInterfaceStatus" in iface:
            for i in iface["EthernetInterfaceStatus"]:
                iname = i.get("Name", "unknown")
                status = 1 if i.get("Status", "").lower() in ["ok", "up"] else 0

                output.append(
                    f'datapower_interface_status{{appliance="{name}",interface="{iname}"}} {status}'
                )
                output.append(
                    f'datapower_interface_rx_bytes{{appliance="{name}",interface="{iname}"}} {i.get("RxHCBytes", 0)}'
                )
                output.append(
                    f'datapower_interface_tx_bytes{{appliance="{name}",interface="{iname}"}} {i.get("TxHCBytes", 0)}'
                )

        # ====================================================
        #  DOMÍNIOS
        # ====================================================

        domains = cached_fetch(
            f"{name}_domains", 30,
            lambda: get_status(dp, "default", "DomainStatus")
        )

        if not domains:
            continue

        for dom in domains.get("DomainStatus", []):
            domain = dom.get("Domain")
            op = 1 if dom.get("OpState", "").lower() == "up" else 0

            output.append(
                f'datapower_domain_status{{appliance="{name}",domain="{domain}"}} {op}'
            )

            obj = cached_fetch(
                f"{name}_{domain}_objects", 120,
                lambda: get_status(dp, domain, "ObjectStatus")
            )

            if obj and "ObjectStatus" in obj:

                for ds in obj["ObjectStatus"]:
                    if ds.get("Class") == "DomainSettings":
                        ds_name = ds.get("Name", "domain-settings")
                        opstate = 1 if ds.get("OpState") == "up" else 0
                        adminstate = 1 if ds.get("AdminState") == "enabled" else 0

                        output.append(
                            f'datapower_domainsettings_opstate{{appliance="{name}",domain="{domain}",object="{ds_name}"}} {opstate}'
                        )
                        output.append(
                            f'datapower_domainsettings_adminstate{{appliance="{name}",domain="{domain}",object="{ds_name}"}} {adminstate}'
                        )

                for xm in obj["ObjectStatus"]:
                    if xm.get("Class") == "XMLManager":
                        xml_name = xm.get("Name", "xml-manager")
                        xml_op = 1 if xm.get("OpState") == "up" else 0

                        output.append(
                            f'datapower_xmlmanager_opstate{{appliance="{name}",domain="{domain}",object="{xml_name}"}} {xml_op}'
                        )

            peering = cached_fetch(
                f"{name}_{domain}_gatewaypeering", 30,
                lambda: get_status(dp, domain, "GatewayPeeringStatus")
            )

            if peering and "GatewayPeeringStatus" in peering:
                for p in peering["GatewayPeeringStatus"]:
                    pname = p.get("Name", "unknown")
                    link = 1 if p.get("LinkStatus", "").lower() == "ok" else 0
                    pending = p.get("PendingUpdates", 0)

                    output.append(
                        f'datapower_gateway_peering_link_status{{appliance="{name}",domain="{domain}",name="{pname}"}} {link}'
                    )
                    output.append(
                        f'datapower_gateway_peering_pending_updates{{appliance="{name}",domain="{domain}",name="{pname}"}} {pending}'
                    )

            apigw = cached_fetch(
                f"{name}_{domain}_apigw", 30,
                lambda: get_status(dp, domain, "APIGatewayStatus")
            )

            if apigw and "APIGatewayStatus" in apigw:
                for gw in apigw["APIGatewayStatus"]:
                    state = 1 if gw.get("OperationalState", "").lower() == "up" else 0
                    gw_name = gw.get("GatewayName", "default")

                    output.append(
                        f'datapower_api_gateway_status{{appliance="{name}",domain="{domain}",gateway="{gw_name}"}} {state}'
                    )

            http = cached_fetch(
                f"{name}_{domain}_http", 30,
                lambda: get_status(dp, domain, "HTTPServiceStatus")
            )

            if http and "HTTPServiceStatus" in http:
                for svc in http["HTTPServiceStatus"]:
                    svc_name = svc.get("ServiceName", "unknown")
                    state = 1 if svc.get("OperationalState", "").lower() == "up" else 0

                    output.append(
                        f'datapower_http_service_status{{appliance="{name}",domain="{domain}",service="{svc_name}"}} {state}'
                    )

            trx = cached_fetch(
                f"{name}_{domain}_tps", 10,
                lambda: get_status(dp, domain, "HTTPTransactions2")
            )

            if trx and "HTTPTransactions2" in trx:
                for t in trx["HTTPTransactions2"]:
                    if t.get("proxy") == "webapi":
                        output.append(
                            f'datapower_tps{{appliance="{name}",domain="{domain}"}} {t.get("tenSeconds", 0)}'
                        )

            lat = cached_fetch(
                f"{name}_{domain}_latency", 10,
                lambda: get_status(dp, domain, "HTTPMeanTransactionTime2")
            )

            if lat and "HTTPMeanTransactionTime2" in lat:
                for entry in lat["HTTPMeanTransactionTime2"]:
                    svc = entry.get("proxy", "unknown")

                    for label, key in [
                        ("10s", "tenSeconds"),
                        ("1m", "oneMinute"),
                        ("10m", "tenMinutes"),
                        ("1h", "oneHour"),
                        ("1d", "oneDay")
                    ]:
                        output.append(
                            f'datapower_http_mean_tx_ms{{appliance="{name}",domain="{domain}",service="{svc}",interval="{label}"}} {entry.get(key, 0)}'
                        )

            if domain == "default":
                dt = cached_fetch(
                    f"{name}_uptime", 60,
                    lambda: get_status(dp, "default", "DateTimeStatus")
                )

                if dt and "DateTimeStatus" in dt:
                    d = dt["DateTimeStatus"]

                    for key, metric in [
                        ("uptime2", "datapower_uptime_seconds"),
                        ("bootuptime2", "datapower_boot_uptime_seconds")
                    ]:
                        txt = d.get(key, "0 days 00:00:00")
                        m = re.match(r"(\d+)\s+days\s+(\d+):(\d+):(\d+)", txt)

                        if m:
                            days, hours, minutes, seconds = map(int, m.groups())
                            sec = days * 86400 + hours * 3600 + minutes * 60 + seconds

                            output.append(
                                f'{metric}{{appliance="{name}",domain="default"}} {sec}'
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
