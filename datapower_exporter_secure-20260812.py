#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import json
import time
import threading
import re
import logging
import os
from collections import defaultdict
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
    if "password_enc" in dp:
        return decrypt_password(dp["password_enc"])
    if "password" in dp:
        return dp["password"]
    raise KeyError(f"Appliance '{dp.get('name','unknown')}' não tem 'password' nem 'password_enc' no config.")

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

# FIX: mapa explícito cache-key -> host, para não depender de fazer
# split() ao nome do appliance (que pode conter underscores)
key_host_map = {}
key_host_lock = threading.Lock()

CB_FAIL_THRESHOLD = 3
CB_OPEN_SECONDS = 60
BP_MAX_FACTOR = 4

def _extract_host_from_url(url):
    try:
        rest = url.split("://", 1)[1]
        hostport = rest.split("/", 1)[0]
        host = hostport.split(":", 1)[0]
        return host
    except Exception:
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
    # FIX: usa o mapa explícito em vez de key.split("_", 1)[0],
    # que partia nomes de appliance com underscore
    with key_host_lock:
        host = key_host_map.get(key)
    if not host:
        return 1
    with breaker_lock:
        return backpressure_factor.get(host, 1)

# ============================================================
# MÉTRICA DE ERROS HTTP/CURL
# ============================================================

http_error_totals = defaultdict(int)
http_error_lock = threading.Lock()

def _record_http_error(appliance_name, error_type):
    with http_error_lock:
        http_error_totals[(appliance_name, error_type)] += 1

def _classify_curl_exit_code(code):
    # códigos de saída do curl: https://curl.se/libcurl/c/libcurl-errors.html
    mapping = {
        6:  "dns_resolve",
        7:  "connection_refused",
        28: "timeout",
        35: "ssl_error",
        52: "empty_reply",
        56: "recv_error",
    }
    return mapping.get(code, f"curl_exit_{code}")

# ============================================================
# CURL ROBUSTO
# ============================================================

def _escape_curl_cfg(value):
    # escapa para uso dentro de um ficheiro de config do curl (-K -)
    return str(value).replace("\\", "\\\\").replace('"', '\\"')

STATUS_MARKER = "__STATUS__"

def call_curl_once(url, user, password, timeout=10, appliance_name="unknown"):
    # FIX: credenciais deixam de ir no argv (visíveis em `ps aux` /
    # /proc/<pid>/cmdline) e passam a ser enviadas via stdin como
    # ficheiro de config do curl (-K -)
    config = (
        f'url = "{_escape_curl_cfg(url)}"\n'
        f'user = "{_escape_curl_cfg(user)}:{_escape_curl_cfg(password)}"\n'
        f'header = "Accept: application/json"\n'
    )
    # NOTA: já não usamos --fail. Precisamos do corpo E do código HTTP
    # real (via -w) para conseguirmos distinguir 4xx de 5xx na métrica
    # de erros, em vez de um "falhou" genérico.
    cmd = [
        "curl", "-k", "-s", "--compressed", "--http1.1", "--no-buffer",
        "--connect-timeout", "3", "--max-time", str(timeout),
        "-w", f"\n{STATUS_MARKER}%{{http_code}}",
        "-K", "-"
    ]
    try:
        result = subprocess.run(
            cmd,
            input=config.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 5
        )
    except subprocess.TimeoutExpired:
        _record_http_error(appliance_name, "timeout")
        return None
    except Exception:
        _record_http_error(appliance_name, "process_error")
        return None

    if result.returncode != 0:
        # falha ao nível do curl: DNS, ligação recusada, timeout interno, etc.
        _record_http_error(appliance_name, _classify_curl_exit_code(result.returncode))
        return None

    raw = result.stdout.decode("utf-8", errors="replace")
    if STATUS_MARKER not in raw:
        _record_http_error(appliance_name, "malformed_response")
        return None

    body, _, status_part = raw.rpartition(STATUS_MARKER)
    status_code = status_part.strip()

    if not status_code.startswith("2"):
        _record_http_error(appliance_name, status_code or "unknown")
        return None

    try:
        data = json.loads(body)
    except Exception:
        _record_http_error(appliance_name, "json_decode")
        return None

    if not isinstance(data, dict):
        return None

    return data

def call_curl(url, user, password, retries=3, timeout=10, appliance_name="unknown"):
    host = _extract_host_from_url(url)

    if not _can_call_host(host):
        _record_http_error(appliance_name, "circuit_open")
        return None

    for _ in range(retries):
        data = call_curl_once(url, user, password, timeout, appliance_name=appliance_name)
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
        get_password(dp),
        appliance_name=dp.get("name", "unknown")
    )

def detect_gateway_type(entry):
    if isinstance(entry, dict) and entry.get("serviceClass") == "apiGateway":
        return "v10"
    if isinstance(entry, list):
        return "v5"
    return "unknown"

def get_service_name(entry, domain):
    return next((entry.get(k) for k in ("proxy", "service", "name") if entry.get(k)), domain)

UPTIME_RE = re.compile(r"(?:(\d+)\s+days?,?)?\s*(\d+):(\d+):(\d+)")

def parse_uptime_to_seconds(txt):
    m = UPTIME_RE.search(str(txt).strip())
    if not m:
        return 0
    d = int(m.group(1)) if m.group(1) else 0
    h, mi, s = map(int, m.group(2, 3, 4))
    return d * 86400 + h * 3600 + mi * 60 + s

# ============================================================
# CACHE + LOCKS
# ============================================================

cache = {}
cache_lock = threading.Lock()
cache_hits = 0
cache_misses = 0
stats_lock = threading.Lock()

def cached_fetch(key, ttl, fn, host=None):
    global cache_hits, cache_misses

    # FIX: regista a relação key -> host para o backpressure,
    # sem depender de parsear a própria key
    if host:
        with key_host_lock:
            key_host_map[key] = host

    eff_ttl = ttl * _get_backpressure_factor_for_key(key)
    now = time.time()

    with cache_lock:
        entry = cache.get(key)
        if entry and now - entry["ts"] < eff_ttl:
            with stats_lock:
                cache_hits += 1
            return entry["data"]

    data = fn()

    with stats_lock:
        cache_misses += 1

    if data is not None:
        with cache_lock:
            cache[key] = {"ts": now, "data": data}

    return data

# ============================================================
# EXTENDED METRICS (v10.0.6 / v11.x)
# ============================================================

ENABLE_EXTENDED = True
EXTENDED_TTL = 30

def safe_get(data, key, default=0):
    return data.get(key, default) if isinstance(data, dict) else default

def _as_dict(value):
    # FIX: normaliza um campo que devia ser um único objeto mas que,
    # em alguns appliances/firmwares (ex: vsobagwt* vs vsothgwt*), vem
    # como lista em vez de dict. Evita "'list' object has no attribute 'get'".
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item
        return {}
    return {}

def parse_iso8601_duration(s):
    if not s or not s.startswith("P"):
        return 0
    days = hours = minutes = seconds = 0
    t = s.replace("P", "")
    if "D" in t:
        days, t = t.split("D")
        days = int(days)
    if "T" in t:
        t = t.split("T")[1]
        if "H" in t:
            hours, t = t.split("H")
            hours = int(hours)
        if "M" in t:
            minutes, t = t.split("M")
            minutes = int(minutes)
        if "S" in t:
            seconds = int(t.replace("S", ""))
    return days*86400 + hours*3600 + minutes*60 + seconds

def collect_extended_metrics(dp, name_raw, name, domain_raw, domain, output):
    if not ENABLE_EXTENDED:
        return

    host = dp["host"]

    # DateTimeStatus2
    dt2 = cached_fetch(
        f"{name_raw}_{domain_raw}_dt2", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "DateTimeStatus2"),
        host=host
    )
    if isinstance(dt2, dict) and "DateTimeStatus2" in dt2:
        uptime3 = _as_dict(dt2["DateTimeStatus2"]).get("uptime3", "")
        output.append(
            f'datapower_uptime3_seconds{{appliance="{name}",domain="{domain}"}} {parse_iso8601_duration(uptime3)}'
        )

    # MemoryStatus2
    mem2 = cached_fetch(
        f"{name_raw}_{domain_raw}_mem2", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "MemoryStatus2"),
        host=host
    )
    if isinstance(mem2, dict) and "MemoryStatus2" in mem2:
        m = _as_dict(mem2["MemoryStatus2"])
        for key in ["current", "oneMinute", "fiveMinutes", "tenMinutes", "oneHour", "twelveHours", "oneDay"]:
            output.append(
                f'datapower_memory2_{key}{{appliance="{name}",domain="{domain}"}} {safe_get(m, key)}'
            )

    # DomainsMemoryStatus2
    dmem2 = cached_fetch(
        f"{name_raw}_{domain_raw}_dmem2", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "DomainsMemoryStatus2"),
        host=host
    )
    if isinstance(dmem2, dict) and "DomainsMemoryStatus2" in dmem2:
        for item in dmem2["DomainsMemoryStatus2"]:
            dom = prom_escape(item.get("domain", domain_raw))
            for key in ["current", "oneMinute", "fiveMinutes", "tenMinutes", "oneHour", "twelveHours", "oneDay"]:
                output.append(
                    f'datapower_domain_memory2_{key}{{appliance="{name}",domain="{dom}"}} {safe_get(item, key)}'
                )

    # ServicesMemoryStatus2
    smem2 = cached_fetch(
        f"{name_raw}_{domain_raw}_smem2", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "ServicesMemoryStatus2"),
        host=host
    )
    if isinstance(smem2, dict) and "ServicesMemoryStatus2" in smem2:
        s = _as_dict(smem2["ServicesMemoryStatus2"])
        svc = prom_escape(s.get("serviceName", "unknown"))
        for key in ["current", "oneMinute", "fiveMinutes", "tenMinutes", "oneHour", "twelveHours", "oneDay"]:
            output.append(
                f'datapower_service_memory2_{key}{{appliance="{name}",domain="{domain}",service="{svc}"}} {safe_get(s, key)}'
            )

    # SystemUsage2Table
    sys2 = cached_fetch(
        f"{name_raw}_{domain_raw}_sys2", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "SystemUsage2Table"),
        host=host
    )
    if isinstance(sys2, dict) and "SystemUsage2Table" in sys2:
        for task in sys2["SystemUsage2Table"]:
            tname = prom_escape(task.get("TaskName", "unknown"))
            for key in ["Load", "WorkList", "CPU", "Memory", "FileCount"]:
                output.append(
                    f'datapower_system_task_{key.lower()}{{appliance="{name}",domain="{domain}",task="{tname}"}} {safe_get(task, key)}'
                )

    # NetworkReceiveDataThroughput
    rx_data = cached_fetch(
        f"{name_raw}_{domain_raw}_rxdata", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "NetworkReceiveDataThroughput"),
        host=host
    )
    if isinstance(rx_data, dict) and "NetworkReceiveDataThroughput" in rx_data:
        for iface in rx_data["NetworkReceiveDataThroughput"]:
            iname = prom_escape(iface.get("InterfaceName", "unknown"))
            for key in ["TenSecondsBits", "OneMinuteBits", "TenMinutesBits", "OneHourBits", "OneDayBits"]:
                output.append(
                    f'datapower_net_rx_bits{{appliance="{name}",domain="{domain}",interface="{iname}",interval="{key}"}} {safe_get(iface, key)}'
                )

    # NetworkTransmitDataThroughput
    tx_data = cached_fetch(
        f"{name_raw}_{domain_raw}_txdata", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "NetworkTransmitDataThroughput"),
        host=host
    )
    if isinstance(tx_data, dict) and "NetworkTransmitDataThroughput" in tx_data:
        for iface in tx_data["NetworkTransmitDataThroughput"]:
            iname = prom_escape(iface.get("InterfaceName", "unknown"))
            for key in ["TenSecondsBits", "OneMinuteBits", "TenMinutesBits", "OneHourBits", "OneDayBits"]:
                output.append(
                    f'datapower_net_tx_bits{{appliance="{name}",domain="{domain}",interface="{iname}",interval="{key}"}} {safe_get(iface, key)}'
                )

    # NetworkReceivePacketThroughput
    rx_pkt = cached_fetch(
        f"{name_raw}_{domain_raw}_rxpkt", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "NetworkReceivePacketThroughput"),
        host=host
    )
    if isinstance(rx_pkt, dict) and "NetworkReceivePacketThroughput" in rx_pkt:
        for iface in rx_pkt["NetworkReceivePacketThroughput"]:
            iname = prom_escape(iface.get("InterfaceName", "unknown"))
            for key in ["tenSeconds", "oneMinute", "tenMinutes", "oneHour", "oneDay"]:
                output.append(
                    f'datapower_net_rx_packets{{appliance="{name}",domain="{domain}",interface="{iname}",interval="{key}"}} {safe_get(iface, key)}'
                )

    # NetworkTransmitPacketThroughput
    tx_pkt = cached_fetch(
        f"{name_raw}_{domain_raw}_txpkt", EXTENDED_TTL,
        lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "NetworkTransmitPacketThroughput"),
        host=host
    )
    if isinstance(tx_pkt, dict) and "NetworkTransmitPacketThroughput" in tx_pkt:
        for iface in tx_pkt["NetworkTransmitPacketThroughput"]:
            iname = prom_escape(iface.get("InterfaceName", "unknown"))
            for key in ["tenSeconds", "oneMinute", "tenMinutes", "oneHour", "oneDay"]:
                output.append(
                    f'datapower_net_tx_packets{{appliance="{name}",domain="{domain}",interface="{iname}",interval="{key}"}} {safe_get(iface, key)}'
                )

# ============================================================
# METRICS
# ============================================================

exporter_calls = 0
exporter_errors = 0
exporter_cycle_seconds = 0

def generate_metrics(config):
    global exporter_calls, exporter_errors

    out = []

    # FIX: HELP/TYPE emitidos uma única vez para todo o output,
    # em vez de repetidos a cada iteração do loop de appliances
    out.append('# HELP datapower_cpu_usage CPU usage (1 min avg)')
    out.append('# TYPE datapower_cpu_usage gauge')
    out.append('# HELP datapower_memory_total Total memory (bytes)')
    out.append('# TYPE datapower_memory_total gauge')

    total = len(config["appliances"])
    log.info(f"A recolher métricas de {total} DataPowers")

    for dp in config["appliances"]:
        name_raw = dp.get("name", "unknown")
        name = prom_escape(name_raw)

        # FIX: isola falhas por appliance — um appliance com erro
        # (ex: password em falta, host inacessível de forma inesperada)
        # já não aborta a recolha dos restantes
        try:
            appliance_host_map[name_raw] = dp["host"]
            host = dp["host"]

            log.info(f"Recolhendo métricas de {name_raw}")

            with stats_lock:
                exporter_calls += 1

            # CPU
            cpu = cached_fetch(f"{name_raw}_cpu", 10,
                               lambda _dp=dp: get_status(_dp, "default", "CPUUsage"),
                               host=host)
            if isinstance(cpu, dict):
                out.append(f'datapower_cpu_usage{{appliance="{name}"}} {_as_dict(cpu.get("CPUUsage", {})).get("oneMinute", 0)}')

            # MEMORY
            mem = cached_fetch(f"{name_raw}_memory", 10,
                               lambda _dp=dp: get_status(_dp, "default", "MemoryStatus"),
                               host=host)
            if isinstance(mem, dict):
                m = _as_dict(mem.get("MemoryStatus", {}))
                out.append(f'datapower_memory_total{{appliance="{name}"}} {m.get("TotalMemory", 0)}')
                out.append(f'datapower_memory_used{{appliance="{name}"}} {m.get("UsedMemory", 0)}')
                out.append(f'datapower_memory_free{{appliance="{name}"}} {m.get("FreeMemory", 0)}')
                out.append(f'datapower_memory_pressure{{appliance="{name}"}} {m.get("Usage", 0)}')
                out.append(f'datapower_request_memory{{appliance="{name}"}} {m.get("ReqMemory", 0)}')

            # SYSTEM
            sysd = cached_fetch(f"{name_raw}_system", 10,
                                lambda _dp=dp: get_status(_dp, "default", "SystemUsage"),
                                host=host)
            if isinstance(sysd, dict) and "SystemUsage" in sysd:
                s = _as_dict(sysd["SystemUsage"])
                out.append(f'datapower_system_load{{appliance="{name}"}} {s.get("Load", 0)}')
                out.append(f'datapower_system_worklist{{appliance="{name}"}} {s.get("WorkList", 0)}')

            # FILESYSTEM
            fs = cached_fetch(f"{name_raw}_fs", 60,
                              lambda _dp=dp: get_status(_dp, "default", "FilesystemStatus"),
                              host=host)
            if isinstance(fs, dict) and "FilesystemStatus" in fs:
                f = _as_dict(fs["FilesystemStatus"])
                out.append(f'datapower_fs_free_encrypted{{appliance="{name}"}} {f.get("FreeEncrypted", 0)}')
                out.append(f'datapower_fs_total_encrypted{{appliance="{name}"}} {f.get("TotalEncrypted", 0)}')
                out.append(f'datapower_fs_free_temporary{{appliance="{name}"}} {f.get("FreeTemporary", 0)}')
                out.append(f'datapower_fs_total_temporary{{appliance="{name}"}} {f.get("TotalTemporary", 0)}')
                out.append(f'datapower_fs_free_internal{{appliance="{name}"}} {f.get("FreeInternal", 0)}')
                out.append(f'datapower_fs_total_internal{{appliance="{name}"}} {f.get("TotalInternal", 0)}')

            # INTERFACES
            iface = cached_fetch(f"{name_raw}_iface", 30,
                                 lambda _dp=dp: get_status(_dp, "default", "EthernetInterfaceStatus"),
                                 host=host)
            if isinstance(iface, dict) and "EthernetInterfaceStatus" in iface:
                for i in iface["EthernetInterfaceStatus"]:
                    if not isinstance(i, dict):
                        continue

                    iname = prom_escape(i.get("Name", "unknown"))
                    st = 1 if i.get("Status", "").lower() in ("ok", "up") else 0

                    # FIX: "or" trocava um 0 legítimo de RxHCBytes/TxHCBytes
                    # pelo valor de fallback. Agora só cai no fallback
                    # quando o campo realmente não existe (None).
                    rx = i.get("RxHCBytes")
                    if rx is None:
                        rx = i.get("RxBytes")
                    if rx is None:
                        rx = 0

                    tx = i.get("TxHCBytes")
                    if tx is None:
                        tx = i.get("TxBytes")
                    if tx is None:
                        tx = 0

                    out.append(f'datapower_interface_status{{appliance="{name}",interface="{iname}"}} {st}')
                    out.append(f'datapower_interface_rx_bytes{{appliance="{name}",interface="{iname}"}} {rx}')
                    out.append(f'datapower_interface_tx_bytes{{appliance="{name}",interface="{iname}"}} {tx}')

            # DOMAINS
            domains = cached_fetch(f"{name_raw}_domains", 60,
                                   lambda _dp=dp: get_status(_dp, "default", "DomainStatus"),
                                   host=host)
            if not isinstance(domains, dict):
                continue

            for dom in domains.get("DomainStatus", []):
                domain_raw = dom.get("Domain", "unknown")
                domain = prom_escape(domain_raw)

                op = 1 if dom.get("OpState", "").lower() == "up" else 0
                out.append(f'datapower_domain_status{{appliance="{name}",domain="{domain}"}} {op}')

                # OBJECT STATUS
                obj = cached_fetch(f"{name_raw}_{domain_raw}_objects", 120,
                                   lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "ObjectStatus"),
                                   host=host)
                if isinstance(obj, dict) and "ObjectStatus" in obj:
                    for item in obj["ObjectStatus"]:
                        if not isinstance(item, dict):
                            continue

                        cls = item.get("Class")

                        if cls == "DomainSettings":
                            nm = prom_escape(item.get("Name", "domain-settings"))
                            out.append(f'datapower_domainsettings_opstate{{appliance="{name}",domain="{domain}",object="{nm}"}} {1 if item.get("OpState") == "up" else 0}')
                            out.append(f'datapower_domainsettings_adminstate{{appliance="{name}",domain="{domain}",object="{nm}"}} {1 if item.get("AdminState") == "enabled" else 0}')

                        elif cls == "XMLManager":
                            nm = prom_escape(item.get("Name", "xml-manager"))
                            out.append(f'datapower_xmlmanager_opstate{{appliance="{name}",domain="{domain}",object="{nm}"}} {1 if item.get("OpState") == "up" else 0}')

                # APIHTTPConnections
                apihttp = cached_fetch(f"{name_raw}_{domain_raw}_apihttp", 20,
                                       lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "APIHTTPConnections"),
                                       host=host)
                if isinstance(apihttp, dict) and "APIHTTPConnections" in apihttp:
                    raw_c = apihttp["APIHTTPConnections"]
                    # FIX: em alguns appliances (ex: gateways v5) o DataPower
                    # devolve uma lista de entradas em vez de um único objeto,
                    # o que rebentava com "'list' object has no attribute 'get'".
                    # Normaliza para lista e soma os contadores das entradas.
                    entries_c = raw_c if isinstance(raw_c, list) else [raw_c]
                    entries_c = [e for e in entries_c if isinstance(e, dict)]

                    groups = {
                        "requests": ["reqTenSec", "reqOneMin", "reqTenMin", "reqOneHr", "reqOneDay"],
                        "reuse":    ["reuseTenSec", "reuseOneMin", "reuseTenMin", "reuseOneHr", "reuseOneDay"],
                        "create":   ["createTenSec", "createOneMin", "createTenMin", "createOneHr", "createOneDay"],
                        "return":   ["returnTenSec", "returnOneMin", "returnTenMin", "returnOneHr", "returnOneDay"],
                        "offer":    ["offerTenSec", "offerOneMin", "offerTenMin", "offerOneHr", "offerOneDay"],
                        "destroy":  ["destroyTenSec", "destroyOneMin", "destroyTenMin", "destroyOneHr", "destroyOneDay"]
                    }

                    intervals = ["10s", "1m", "10m", "1h", "1d"]

                    for g, keys in groups.items():
                        for lbl, key in zip(intervals, keys):
                            total = sum(safe_get(e, key, 0) for e in entries_c)
                            out.append(
                                f'datapower_apihttpconnections_{g}{{appliance="{name}",domain="{domain}",interval="{lbl}"}} {total}'
                            )

                # TPS
                trx = cached_fetch(f"{name_raw}_{domain_raw}_tps", 10,
                                   lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "HTTPTransactions2"),
                                   host=host)
                if isinstance(trx, dict) and "HTTPTransactions2" in trx:
                    raw = trx["HTTPTransactions2"]
                    gw = prom_escape(detect_gateway_type(raw))
                    entries = raw if isinstance(raw, list) else [raw]

                    for e in entries:
                        if isinstance(e, dict):
                            svc = prom_escape(get_service_name(e, domain_raw))
                            out.append(
                                f'datapower_tps{{appliance="{name}",domain="{domain}",service="{svc}",gateway_type="{gw}"}} {e.get("tenSeconds", 0)}'
                            )

                # LATENCY
                # FIX: só faz o fetch quando realmente é usado
                # (domain_raw != "default"), poupando uma chamada
                # REST por domínio "default" a cada ciclo
                if domain_raw != "default":
                    lat = cached_fetch(f"{name_raw}_{domain_raw}_lat", 10,
                                       lambda _dp=dp, _dr=domain_raw: get_status(_dp, _dr, "HTTPMeanTransactionTime2"),
                                       host=host)

                    if isinstance(lat, dict):
                        raw = lat.get("HTTPMeanTransactionTime2")

                        if not raw:
                            log.warning(
                                "Latência ausente no domínio %s do appliance %s. Resposta DP: %s",
                                domain_raw, name_raw, lat
                            )
                        else:
                            gw = prom_escape(detect_gateway_type(raw))
                            entries = raw if isinstance(raw, list) else [raw]

                            for e in entries:
                                if isinstance(e, dict):
                                    svc = prom_escape(get_service_name(e, domain_raw))
                                    for lbl, key in [
                                        ("10s",  "tenSeconds"),
                                        ("1m",   "oneMinute"),
                                        ("10m",  "tenMinutes"),
                                        ("1h",   "oneHour"),
                                        ("1d",   "oneDay")
                                    ]:
                                        out.append(
                                            f'datapower_http_mean_tx_ms{{appliance="{name}",domain="{domain}",service="{svc}",interval="{lbl}",gateway_type="{gw}"}} {e.get(key, 0)}'
                                        )

                # UPTIME
                if domain_raw == "default":
                    dt = cached_fetch(f"{name_raw}_uptime", 60,
                                      lambda _dp=dp: get_status(_dp, "default", "DateTimeStatus"),
                                      host=host)
                    if isinstance(dt, dict):
                        d = _as_dict(dt.get("DateTimeStatus", {}))
                        for key, metric in [
                            ("uptime2",     "datapower_uptime_seconds"),
                            ("bootuptime2", "datapower_boot_uptime_seconds")
                        ]:
                            out.append(
                                f'{metric}{{appliance="{name}",domain="{domain}"}} {parse_uptime_to_seconds(d.get(key, "0 days 00:00:00"))}'
                            )

                # EXTENDED METRICS
                collect_extended_metrics(dp, name_raw, name, domain_raw, domain, out)

        except Exception as e:
            with stats_lock:
                exporter_errors += 1
            log.error("Erro ao processar appliance %s: %s", name_raw, e)
            continue

    # MÉTRICAS INTERNAS
    with stats_lock:
        out.append(f'# HELP datapower_exporter_cache_hits_total Cache hits')
        out.append(f'# TYPE datapower_exporter_cache_hits_total counter')
        out.append(f'datapower_exporter_cache_hits_total {cache_hits}')
        out.append(f'datapower_exporter_cache_misses_total {cache_misses}')
        out.append(f'datapower_exporter_calls_total {exporter_calls}')
        out.append(f'datapower_exporter_errors_total {exporter_errors}')
        out.append(f'datapower_exporter_cycle_seconds {exporter_cycle_seconds}')

    # ERROS HTTP/CURL por appliance e tipo
    with http_error_lock:
        if http_error_totals:
            out.append('# HELP datapower_exporter_http_errors_total Erros HTTP/curl por appliance e tipo')
            out.append('# TYPE datapower_exporter_http_errors_total counter')
            for (appliance_name, err_type), count in http_error_totals.items():
                out.append(
                    f'datapower_exporter_http_errors_total{{appliance="{prom_escape(appliance_name)}",error="{prom_escape(err_type)}"}} {count}'
                )

    return "\n".join(out)

# ============================================================
# SERVER
# ============================================================

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            with metrics_lock:
                self.wfile.write(metrics_text.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_):
        pass

# ============================================================
# MAIN
# ============================================================

def main():
    global metrics_text, exporter_cycle_seconds, exporter_errors

    with open(CONFIG_FILE) as f:
        config = json.load(f)

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

            elapsed = time.time() - start
            with stats_lock:
                exporter_cycle_seconds = elapsed

            log.info(f"Ciclo concluído em {elapsed:.2f}s")

            time.sleep(interval)

    threading.Thread(target=loop, daemon=True).start()

    ThreadedHTTPServer(("", port), MetricsHandler).serve_forever()

if __name__ == "__main__":
    main()
