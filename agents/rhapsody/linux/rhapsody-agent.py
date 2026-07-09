#!/usr/bin/env python3
import glob
import json
import os
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


CONFIG_PATH = "/etc/rhapsody-monitoring-agent.env"
AGENT_VERSION = "1.0.0-rhapsody"


def load_env_file(path):
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file(CONFIG_PATH)

API_URL = os.environ.get("RHAPSODY_API_URL") or os.environ.get("MONITORING_RHAPSODY_API_URL")
TOKEN = os.environ.get("RHAPSODY_AGENT_TOKEN") or os.environ.get("MONITORING_AGENT_TOKEN")
INTERVAL = int(os.environ.get("RHAPSODY_INTERVAL", "60"))
VERIFY_TLS = os.environ.get("RHAPSODY_VERIFY_TLS", "true").lower() not in ["0", "false", "no"]
CA_FILE = os.environ.get("RHAPSODY_CA_FILE", "")


def command_output(args):
    try:
        return subprocess.check_output(args, universal_newlines=True, stderr=subprocess.DEVNULL, timeout=10).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def split_env(name, default_values):
    configured = os.environ.get(name, "")
    if configured:
        return [item.strip() for item in configured.split(",") if item.strip()]
    return default_values


def log_patterns():
    return split_env(
        "RHAPSODY_LOG_PATHS",
        [
            "/opt/rhapsody/logs/*.log",
            "/opt/rhapsody*/logs/*.log",
            "/var/log/rhapsody/*.log",
            "/var/opt/rhapsody/logs/*.log",
        ],
    )


def keywords():
    return [item.lower() for item in split_env(
        "RHAPSODY_KEYWORDS",
        ["fatal", "error", "route stopped", "channel stopped", "message failed", "queue full", "outofmemory", "license expired"],
    )]


def configured_service_names():
    return [item.lower() for item in split_env("RHAPSODY_SERVICE_NAMES", [])]


def collect_services():
    output = command_output(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"])
    configured = configured_service_names()
    services = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name = parts[0]
        description = parts[4] if len(parts) >= 5 else ""
        haystack = f"{name} {description}".lower()
        if "rhapsody" not in haystack and name.lower() not in configured:
            continue
        services.append(
            {
                "name": name,
                "display_name": description or name,
                "load": parts[1],
                "state": parts[2],
                "sub_state": parts[3],
                "description": description,
            }
        )
    return services[:40]


def collect_processes():
    output = command_output(["ps", "-eo", "pid,user,pcpu,pmem,etime,comm,args", "--no-headers"])
    processes = []
    for line in output.splitlines():
        if "rhapsody" not in line.lower():
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        processes.append(
            {
                "pid": parts[0],
                "user": parts[1],
                "cpu_percent": parts[2],
                "memory_percent": parts[3],
                "time": parts[4],
                "name": parts[5],
                "path": parts[6] if len(parts) > 6 else "",
            }
        )
    return processes[:40]


def collect_ports():
    output = command_output(["ss", "-lntup"])
    ports = []
    for line in output.splitlines():
        if "rhapsody" not in line.lower():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local_address = parts[4]
        port = local_address.rsplit(":", 1)[-1] if ":" in local_address else local_address
        ports.append(
            {
                "protocol": parts[0].upper(),
                "local_address": local_address,
                "local_port": port,
                "status": parts[1],
                "process": " ".join(parts[5:]) if len(parts) > 5 else "",
            }
        )
    return ports[:80]


def collect_log_findings():
    findings = []
    file_paths = []
    for pattern in log_patterns():
        file_paths.extend(glob.glob(pattern))
    for path in sorted(set(file_paths))[-8:]:
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
        except OSError:
            continue
        for line in lines:
            lower_line = line.lower()
            matched = next((keyword for keyword in keywords() if keyword in lower_line), "")
            if matched:
                findings.append({"file": path, "keyword": matched, "message": line[-600:]})
                if len(findings) >= 30:
                    return findings
    return findings


def build_payload():
    services = collect_services()
    processes = collect_processes()
    ports = collect_ports()
    log_findings = collect_log_findings()
    running_services = [
        service for service in services
        if str(service.get("state", "")).lower() in ["active", "running"]
        or str(service.get("sub_state", "")).lower() == "running"
    ]
    detected = bool(services or processes or ports or log_findings)
    if not detected:
        status = "not_detected"
        summary = "Rhapsody no detectado por servicio, proceso, puerto o log."
    elif not running_services and not processes:
        status = "critical"
        summary = "Rhapsody detectado, pero no se encontro servicio activo ni proceso en ejecucion."
    elif log_findings:
        status = "warning"
        summary = f"Rhapsody activo con {len(log_findings)} hallazgo(s) reciente(s) en logs."
    else:
        status = "healthy"
        summary = "Rhapsody activo sin hallazgos recientes en logs."
    return {
        "hostname": socket.gethostname(),
        "agent_version": AGENT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "summary": summary,
        "services": services,
        "processes": processes,
        "ports": ports,
        "log_findings": log_findings,
        "details": {
            "detected": detected,
            "service_count": len(services),
            "process_count": len(processes),
            "port_count": len(ports),
            "log_finding_count": len(log_findings),
        },
    }


def ssl_context():
    if not VERIFY_TLS:
        return ssl._create_unverified_context()
    if CA_FILE:
        return ssl.create_default_context(cafile=CA_FILE)
    return ssl.create_default_context()


def send_report():
    if not API_URL or not TOKEN:
        raise RuntimeError("RHAPSODY_API_URL y RHAPSODY_AGENT_TOKEN son requeridos.")
    data = json.dumps(build_payload()).encode("utf-8")
    request = Request(
        API_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=20, context=ssl_context()) as response:
        response.read()
        return response.status


def main():
    while True:
        try:
            status_code = send_report()
            print(f"{datetime.now(timezone.utc).isoformat()} status=ok http={status_code}", flush=True)
        except Exception as exc:
            print(f"{datetime.now(timezone.utc).isoformat()} error={exc}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
