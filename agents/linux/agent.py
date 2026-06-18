import os
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone

import psutil
import requests


API_URL = os.environ["MONITORING_API_URL"]
TOKEN = os.environ["MONITORING_AGENT_TOKEN"]
HOSTNAME = os.environ.get("MONITORING_HOSTNAME") or socket.gethostname()
INTERVAL = int(os.environ.get("MONITORING_INTERVAL", "60"))
VERIFY_TLS = os.environ.get("MONITORING_VERIFY_TLS", "true").lower() == "true"


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def command_output(command):
    try:
        return subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
    except Exception:
        return ""


def primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return ""


def dns_servers():
    servers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers


def network_interfaces():
    interfaces = []
    mac_addresses = []
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addresses.items():
        item = {
            "name": name,
            "is_up": stats.get(name).isup if name in stats else None,
            "speed_mbps": stats.get(name).speed if name in stats else None,
            "ips": [],
            "mac": "",
        }
        for address in addr_list:
            family = str(address.family)
            if "AF_INET" in family and address.address != "127.0.0.1":
                item["ips"].append(address.address)
            if "AF_PACKET" in family or "AF_LINK" in family:
                item["mac"] = address.address
                if address.address:
                    mac_addresses.append(address.address)
        interfaces.append(item)
    return interfaces, sorted(set(mac_addresses))


def collect_inventory():
    interfaces, mac_addresses = network_interfaces()
    return {
        "hostname": HOSTNAME,
        "fqdn": socket.getfqdn(),
        "os_name": platform.system(),
        "os_version": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "serial_number": read_file("/sys/class/dmi/id/product_serial"),
        "model": read_file("/sys/class/dmi/id/product_name"),
        "manufacturer": read_file("/sys/class/dmi/id/sys_vendor"),
        "domain": command_output(["hostname", "-d"]),
        "logged_user": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
        "primary_ip": primary_ip(),
        "gateway": command_output(["sh", "-c", "ip route | awk '/default/ {print $3; exit}'"]),
        "dns_servers": dns_servers(),
        "mac_addresses": mac_addresses,
        "interfaces": interfaces,
        "timezone": time.tzname[0] if time.tzname else "",
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def collect_metrics():
    disk_root = psutil.disk_usage("/")
    disks = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            continue
        disks.append(
            {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "percent": usage.percent,
            }
        )
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    uptime_seconds = int((datetime.now(timezone.utc) - boot_time).total_seconds())

    return {
        "hostname": HOSTNAME,
        "agent_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_root_percent": disk_root.percent,
            "disk_count": len(disks),
            "disks": disks,
            "uptime_seconds": uptime_seconds,
            "load_1m": os.getloadavg()[0] if hasattr(os, "getloadavg") else None,
        },
        "inventory": collect_inventory(),
        "services": [],
    }


def send_payload(payload):
    response = requests.post(
        API_URL,
        json=payload,
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=20,
        verify=VERIFY_TLS,
    )
    response.raise_for_status()


def main():
    while True:
        try:
            send_payload(collect_metrics())
        except Exception as exc:
            print(f"{datetime.now(timezone.utc).isoformat()} error={exc}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
