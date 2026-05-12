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
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("datapower_exporter")

# ============================================================
# PASSWORD DECRYPTION
# ============================================================

def decrypt_password(enc):
    key = os.getenv("DP_KEY")
    if not key:
        raise Exception("DP_KEY environment variable not set")
    return Fernet(key.encode()).decrypt(enc.encode()).decode()

def get_password(dp):
    return decrypt_password(dp["password_enc"]) if "password_enc" in dp else dp["password"]

# ============================================================
# PROMETHEUS ESCAPING
# ============================================================

def prom_escape(v):
    return (
        str(v)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )

# ============================================================
# THREAD HTTP SERVER
# ============================================================

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

# ============================================================
# CIRCUIT BREAKER + BACKPRESSURE
# ============================================================

breaker_state = {}
backpressure_factor = {}
appliance_host_map = {}
breaker_lock = threading.Lock()

CB_FAIL_THRESHOLD = 3
CB_OPEN_SECONDS = 60
BP_MAX_FACTOR = 4

def _extract_host_from_url(url):
    try:
        rest = url.split("://", 1)[1]
        hostport = rest.split("/", 1)[0]
        host = hostport.split(":", 1)[0]
        return host
    except:
        return None

def _can_call_host(host):
    if not host:
        return True
    now = time.time()
    with breaker_lock:
        st = breaker_state.get(host, {"state": "closed", "fail_count": 0, "opened_at": 0})
        if st["state"] == "open":
            if now - st["opened_at"] < CB_OPEN_SECONDS:
                return False
            st["state"] = "half"
            breaker_state[host] = st
        return True

def _on_call_success(host):
    if not host:
        return
    with breaker_lock:
        st = breaker_state.get(host, {"state": "closed", "fail_count": 0, "opened_at": 0})
        st["state"] = "closed"
        st["fail_count"] = 0
        st["opened_at"] = 0
        breaker_state[host] = st

        f = backpressure_factor.get(host, 1)
        if f > 1:
            f = max(1, f // 2)
        backpressure_factor[host] = f

def _on_call_failure(host):
    if not host:
        return
    now = time.time()
    with breaker_lock:
        st = breaker_state.get(host, {"state": "closed", "fail_count": 0, "opened_at": 0})
        if st["state"] in ("closed", "half"):
            st["fail_count"] += 1
            if st["fail_count"] >= CB_FAIL_THRESHOLD:
                st["state"] = "open"
                st["opened_at"] = now
        breaker_state[host] = st

        f = backpressure_factor.get(host, 1)
        if f < BP_MAX_FACTOR:
            f *= 2
        backpressure_factor[host] = f

def _get_backpressure_factor_for_key(key):
    name_raw = key.split("_", 1)[0]
    host = appliance_host_map.get(name_raw)
    if not host:
        return 1
    with breaker_lock:
        return backpressure_factor.get(host, 1)

# ============================================================
# CURL ROBUSTO
# ============================================================

def call_curl_once(url, user, password, timeout=10):
    cmd = [
        "curl","-k","-s","--fail","--compressed","--http1.1","--no-buffer",
        "-H","Accept: application/json",
        "--connect-timeout","3","--max-time",str(timeout),
        "-u",f"{user}:{password}", url
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        data = json.loads(out)
        if not isinstance(data, dict):
            return None
        return data
    except:
        return None

def call_curl(url, user, password, retries=3, timeout=10):
    host = _extract_host_from_url(url)

    if not _can_call_host(host):
        return None

    for _ in range(retries):
        data = call_curl_once(url, user, password, timeout)
        if data is not None:
            _on_call_success(host)
            return data
        time.sleep(0.2)

    _on_call_failure(host)
    return None

# ============================================================
# HELPERS
# ============================================================

def get_status(dp, domain, endpoint):
    return call_curl(
        f"https://{dp['host']}:5554/mgmt/status/{domain}/{endpoint}",
        dp["user"],
        get_password(dp)
    )

def detect_gateway_type(entry):
    if isinstance(entry, dict) and entry.get("serviceClass") == "apiGateway":
        return "v10"
    if isinstance(entry, list):
        return "v5"
    return "unknown"

def get_service_name(entry, domain):
    return next((entry.get(k) for k in ("proxy","service","name") if entry.get(k)), domain)

UPTIME_RE = re.compile(r"(?:(\d+)\s+days?,?)?\s*(\d+):(\d+):(\d+)")

def parse_uptime_to_seconds(txt):
    m = UPTIME_RE.search(str(txt).strip())
    if not m:
        return 0
    d = int(m.group(1)) if m.group(1) else 0
    h, mi, s = map(int, m.group(2,3,4))
    return d*86400 + h*3600 + mi*60 + s

# ============================================================
# CACHE + LOCKS
# ============================================================

cache = {}
cache_hits = 0
cache_misses = 0
stats_lock = threading.Lock()

def cached_fetch(key, ttl, fn):
    global cache_hits, cache_misses

    eff_ttl = ttl * _get_backpressure_factor_for_key(key)
    now = time.time()
    entry = cache.get(key)

    if entry and now - entry["ts"] < eff_ttl:
        with stats_lock:
            cache_hits += 1
        return entry["data"]

    data = fn()

    with stats_lock:
        cache_misses += 1

    if data is not None:
        cache[key] = {"ts": now, "data": data}

    return data

# ============================================================
# METRICS
# ============================================================

exporter_calls = 0
exporter_errors = 0
exporter_cycle_seconds = 0

def generate_metrics(config):
    global exporter_calls

    out = []

    # ============================================================
    # LOG ANTIGO — TOTAL DE DATAPOWERS
    # ============================================================
    total = len(config["appliances"])
    log.info(f"A recolher métricas de {total} DataPowers")

    for dp in config["appliances"]:
        name_raw = dp["name"]
        name = prom_escape(name_raw)
        appliance_host_map[name_raw] = dp["host"]

        # ============================================================
        # LOG ANTIGO — POR APPLIANCE
        # ============================================================
        log.info(f"Recolhendo métricas de {name_raw}")

        with stats_lock:
            exporter_calls += 1

        # CPU
        cpu = cached_fetch(f"{name_raw}_cpu", 10,
                           lambda: get_status(dp,"default","CPUUsage"))
        if isinstance(cpu, dict):
            out.append(f'datapower_cpu_usage{{appliance="{name}"}} {cpu.get("CPUUsage",{}).get("oneMinute",0)}')

        # MEMORY
        mem = cached_fetch(f"{name_raw}_memory", 10,
                           lambda: get_status(dp,"default","MemoryStatus"))
        if isinstance(mem, dict):
            m = mem.get("MemoryStatus",{})
            out.append(f'datapower_memory_total{{appliance="{name}"}} {m.get("TotalMemory",0)}')
            out.append(f'datapower_memory_used{{appliance="{name}"}} {m.get("UsedMemory",0)}')
            out.append(f'datapower_memory_free{{appliance="{name}"}} {m.get("FreeMemory",0)}')
            out.append(f'datapower_memory_pressure{{appliance="{name}"}} {m.get("Usage",0)}')
            out.append(f'datapower_request_memory{{appliance="{name}"}} {m.get("ReqMemory",0)}')

        # SYSTEM
        sysd = cached_fetch(f"{name_raw}_system", 10,
                            lambda: get_status(dp,"default","SystemUsage"))
        if isinstance(sysd, dict) and "SystemUsage" in sysd:
            s = sysd["SystemUsage"]
            out.append(f'datapower_system_load{{appliance="{name}"}} {s.get("Load",0)}')
            out.append(f'datapower_system_worklist{{appliance="{name}"}} {s.get("WorkList",0)}')

        # FILESYSTEM
        fs = cached_fetch(f"{name_raw}_fs", 60,
                          lambda: get_status(dp,"default","FilesystemStatus"))
        if isinstance(fs, dict) and "FilesystemStatus" in fs:
            f = fs["FilesystemStatus"]
            out.append(f'datapower_fs_free_encrypted{{appliance="{name}"}} {f.get("FreeEncrypted",0)}')
            out.append(f'datapower_fs_total_encrypted{{appliance="{name}"}} {f.get("TotalEncrypted",0)}')
            out.append(f'datapower_fs_free_temporary{{appliance="{name}"}} {f.get("FreeTemporary",0)}')
            out.append(f'datapower_fs_total_temporary{{appliance="{name}"}} {f.get("TotalTemporary",0)}')
            out.append(f'datapower_fs_free_internal{{appliance="{name}"}} {f.get("FreeInternal",0)}')
            out.append(f'datapower_fs_total_internal{{appliance="{name}"}} {f.get("TotalInternal",0)}')

        # INTERFACES
        iface = cached_fetch(f"{name_raw}_iface", 30,
                             lambda: get_status(dp,"default","EthernetInterfaceStatus"))
        if isinstance(iface, dict) and "EthernetInterfaceStatus" in iface:
            for i in iface["EthernetInterfaceStatus"]:
                if not isinstance(i, dict):
                    continue

                iname = prom_escape(i.get("Name","unknown"))
                st = 1 if i.get("Status","").lower() in ("ok","up") else 0
                rx = i.get("RxHCBytes") or i.get("RxBytes") or 0
                tx = i.get("TxHCBytes") or i.get("TxBytes") or 0

                out.append(f'datapower_interface_status{{appliance="{name}",interface="{iname}"}} {st}')
                out.append(f'datapower_interface_rx_bytes{{appliance="{name}",interface="{iname}"}} {rx}')
                out.append(f'datapower_interface_tx_bytes{{appliance="{name}",interface="{iname}"}} {tx}')

        # DOMAINS
        domains = cached_fetch(f"{name_raw}_domains", 60,
                               lambda: get_status(dp,"default","DomainStatus"))
        if not isinstance(domains, dict):
            continue

        for dom in domains.get("DomainStatus", []):
            domain_raw = dom.get("Domain","unknown")
            domain = prom_escape(domain_raw)

            op = 1 if dom.get("OpState","").lower()=="up" else 0
            out.append(f'datapower_domain_status{{appliance="{name}",domain="{domain}"}} {op}')

            # OBJECT STATUS
            obj = cached_fetch(f"{name_raw}_{domain_raw}_objects", 120,
                               lambda: get_status(dp,domain_raw,"ObjectStatus"))
            if isinstance(obj, dict) and "ObjectStatus" in obj:
                for item in obj["ObjectStatus"]:
                    if not isinstance(item, dict):
                        continue

                    cls = item.get("Class")

                    if cls == "DomainSettings":
                        nm = prom_escape(item.get("Name","domain-settings"))
                        out.append(f'datapower_domainsettings_opstate{{appliance="{name}",domain="{domain}",object="{nm}"}} {1 if item.get("OpState")=="up" else 0}')
                        out.append(f'datapower_domainsettings_adminstate{{appliance="{name}",domain="{domain}",object="{nm}"}} {1 if item.get("AdminState")=="enabled" else 0}')

                    elif cls == "XMLManager":
                        nm = prom_escape(item.get("Name","xml-manager"))
                        out.append(f'datapower_xmlmanager_opstate{{appliance="{name}",domain="{domain}",object="{nm}"}} {1 if item.get("OpState")=="up" else 0}')

            # APIHTTPConnections
            apihttp = cached_fetch(f"{name_raw}_{domain_raw}_apihttp", 20,
                                   lambda: get_status(dp,domain_raw,"APIHTTPConnections"))
            if isinstance(apihttp, dict) and "APIHTTPConnections" in apihttp:
                c = apihttp["APIHTTPConnections"]

                groups = {
                    "requests":["reqTenSec","reqOneMin","reqTenMin","reqOneHr","reqOneDay"],
                    "reuse":["reuseTenSec","reuseOneMin","reuseTenMin","reuseOneHr","reuseOneDay"],
                    "create":["createTenSec","createOneMin","createTenMin","createOneHr","createOneDay"],
                    "return":["returnTenSec","returnOneMin","returnTenMin","returnOneHr","returnOneDay"],
                    "offer":["offerTenSec","offerOneMin","offerTenMin","offerOneHr","offerOneDay"],
                    "destroy":["destroyTenSec","destroyOneMin","destroyTenMin","destroyOneHr","destroyOneDay"]
                }

                intervals = ["10s","1m","10m","1h","1d"]

                for g, keys in groups.items():
                    for lbl, key in zip(intervals, keys):
                        out.append(
                            f'datapower_apihttpconnections_{g}{{appliance="{name}",domain="{domain}",interval="{lbl}"}} {c.get(key,0)}'
                        )

            # TPS
            trx = cached_fetch(f"{name_raw}_{domain_raw}_tps", 10,
                               lambda: get_status(dp,domain_raw,"HTTPTransactions2"))
            if isinstance(trx, dict) and "HTTPTransactions2" in trx:
                raw = trx["HTTPTransactions2"]
                gw = prom_escape(detect_gateway_type(raw))
                entries = raw if isinstance(raw, list) else [raw]

                for e in entries:
                    if isinstance(e, dict):
                        svc = prom_escape(get_service_name(e, domain_raw))
                        out.append(
                            f'datapower_tps{{appliance="{name}",domain="{domain}",service="{svc}",gateway_type="{gw}"}} {e.get("tenSeconds",0)}'
                        )

            # LATENCY
            lat = cached_fetch(f"{name_raw}_{domain_raw}_lat", 10,
                               lambda: get_status(dp,domain_raw,"HTTPMeanTransactionTime2"))

            if domain_raw!="default" and isinstance(lat, dict):
                raw = lat.get("HTTPMeanTransactionTime2")

                if not raw:
                    log.warning(
                        "Latência ausente no domínio %s do appliance %s. Resposta DP: %s",
                        domain_raw, name_raw, lat
                    )
                    continue

                gw = prom_escape(detect_gateway_type(raw))
                entries = raw if isinstance(raw, list) else [raw]

                for e in entries:
                    if isinstance(e, dict):
                        svc = prom_escape(get_service_name(e, domain_raw))
                        for lbl, key in [
                            ("10s","tenSeconds"),
                            ("1m","oneMinute"),
                            ("10m","tenMinutes"),
                            ("1h","oneHour"),
                            ("1d","oneDay")
                        ]:
                            out.append(
                                f'datapower_http_mean_tx_ms{{appliance="{name}",domain="{domain}",service="{svc}",interval="{lbl}",gateway_type="{gw}"}} {e.get(key,0)}'
                            )

            # UPTIME
            if domain_raw=="default":
                dt = cached_fetch(f"{name_raw}_uptime", 60,
                                  lambda: get_status(dp,"default","DateTimeStatus"))
                if isinstance(dt, dict):
                    d = dt["DateTimeStatus"]
                    for key, metric in [
                        ("uptime2","datapower_uptime_seconds"),
                        ("bootuptime2","datapower_boot_uptime_seconds")
                    ]:
                        out.append(
                            f'{metric}{{appliance="{name}",domain="{domain}"}} {parse_uptime_to_seconds(d.get(key,"0 days 00:00:00"))}'
                        )

    # METRICAS INTERNAS
    with stats_lock:
        out.append(f'datapower_exporter_cache_hits_total {cache_hits}')
        out.append(f'datapower_exporter_cache_misses_total {cache_misses}')
        out.append(f'datapower_exporter_calls_total {exporter_calls}')
        out.append(f'datapower_exporter_errors_total {exporter_errors}')
        out.append(f'datapower_exporter_cycle_seconds {exporter_cycle_seconds}')

    return "\n".join(out)

# ============================================================
# SERVER
# ============================================================

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type","text/plain")
            self.end_headers()
            with metrics_lock:
                self.wfile.write(metrics_text.encode())
        else:
            self.send_response(404)
            self.end_headers()

# ============================================================
# MAIN
# ============================================================

def main():
    global metrics_text, exporter_cycle_seconds, exporter_errors

    config = json.load(open(CONFIG_FILE))
    port = config["global"]["exporter_port"]
    interval = config["global"]["refresh_interval"]

    log.info(f"Exporter ativo na porta {port}")

    def loop():
        global metrics_text, exporter_cycle_seconds, exporter_errors

        while True:
            start = time.time()
            try:
                metrics = generate_metrics(config)
                with metrics_lock:
                    metrics_text = metrics
            except Exception as e:
                with stats_lock:
                    exporter_errors += 1
                log.error("Erro no ciclo: %s", e)

            with stats_lock:
                exporter_cycle_seconds = time.time() - start

            # Log final do ciclo — formato antigo
            log.info(f"Ciclo concluído em {exporter_cycle_seconds:.2f}s")

            time.sleep(interval)

    threading.Thread(target=loop, daemon=True).start()

    ThreadedHTTPServer(("", port), MetricsHandler).serve_forever()

if __name__ == "__main__":
    main()
