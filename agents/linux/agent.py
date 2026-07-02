import json
import os
import platform
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


API_URL = os.environ["MONITORING_API_URL"]
TOKEN = os.environ["MONITORING_AGENT_TOKEN"]
HOSTNAME = os.environ.get("MONITORING_HOSTNAME") or socket.gethostname()
INTERVAL = int(os.environ.get("MONITORING_INTERVAL", "60"))
VERIFY_TLS = os.environ.get("MONITORING_VERIFY_TLS", "true").lower() == "true"


def read_file(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def command_output(command, timeout=5):
    try:
        return subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True, timeout=timeout).strip()
    except Exception:
        return ""


def command_exists(command):
    return bool(command_output(["sh", "-c", f"command -v {command}"]))


def primary_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return ""


def dns_servers():
    servers = []
    for line in read_file("/etc/resolv.conf").splitlines():
        parts = line.strip().split()
        if len(parts) > 1 and parts[0] == "nameserver":
            servers.append(parts[1])
    return servers


def network_interfaces():
    interfaces = {}
    mac_addresses = []
    for item in Path("/sys/class/net").glob("*"):
        name = item.name
        mac = read_file(item / "address")
        speed = read_file(item / "speed")
        interfaces[name] = {
            "name": name,
            "is_up": read_file(item / "operstate") == "up",
            "speed_mbps": int(speed) if speed.isdigit() else None,
            "ips": [],
            "mac": mac,
        }
        if mac:
            mac_addresses.append(mac)

    output = command_output(["ip", "-o", "-4", "addr", "show"])
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] in interfaces:
            interfaces[parts[1]]["ips"].append(parts[3].split("/")[0])
    return list(interfaces.values()), sorted(set(mac_addresses))


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


def cpu_times():
    parts = read_file("/proc/stat").splitlines()[0].split()[1:]
    values = [int(value) for value in parts[:8]]
    idle = values[3] + values[4]
    total = sum(values)
    return idle, total


def cpu_percent():
    idle_1, total_1 = cpu_times()
    time.sleep(1)
    idle_2, total_2 = cpu_times()
    total_delta = total_2 - total_1
    idle_delta = idle_2 - idle_1
    if total_delta <= 0:
        return 0
    return round((1 - idle_delta / total_delta) * 100, 2)


def memory_percent():
    values = {}
    for line in read_file("/proc/meminfo").splitlines():
        key, raw_value = line.split(":", 1)
        number = raw_value.strip().split()[0]
        if number.isdigit():
            values[key] = int(number)
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    if not total:
        return 0
    return round((total - available) / total * 100, 2)


def uptime_seconds():
    value = read_file("/proc/uptime").split()[0]
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def disk_usage():
    output = command_output(["df", "-P", "-B1"])
    disks = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        device, total, used, _, percent, mountpoint = parts[:6]
        try:
            total_bytes = int(total)
            used_bytes = int(used)
        except ValueError:
            continue
        if total_bytes <= 0:
            continue
        disks.append(
            {
                "device": device,
                "mountpoint": mountpoint,
                "fstype": command_output(["findmnt", "-n", "-o", "FSTYPE", mountpoint]) or "",
                "total_gb": round(total_bytes / (1024**3), 2),
                "percent": round(used_bytes / total_bytes * 100, 2),
            }
        )
    root = next((disk for disk in disks if disk["mountpoint"] == "/"), disks[0] if disks else None)
    return disks, (root["percent"] if root else 0)


def collect_services():
    output = command_output(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"])
    services = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        services.append(
            {
                "name": parts[0],
                "display_name": parts[4] if len(parts) > 4 else parts[0],
                "state": parts[2],
                "sub_state": parts[3],
                "start_type": "",
            }
        )
    return services[:120]


def collect_processes():
    output = command_output(["ps", "-eo", "pid,user,pcpu,pmem,etime,comm,args", "--sort=-pmem"])
    processes = []
    for line in output.splitlines()[1:41]:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        path = parts[6] if len(parts) > 6 else parts[5]
        processes.append(
            {
                "pid": int(parts[0]) if parts[0].isdigit() else None,
                "name": parts[5],
                "user": parts[1],
                "cpu_percent": float(parts[2]) if parts[2].replace(".", "", 1).isdigit() else 0,
                "memory_percent": float(parts[3]) if parts[3].replace(".", "", 1).isdigit() else 0,
                "time": parts[4],
                "path": path,
            }
        )
    return processes


def collect_ports():
    output = command_output(["ss", "-H", "-lntuap"])
    ports = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        protocol = parts[0].upper()
        local = parts[4]
        if ":" not in local:
            continue
        address, port = local.rsplit(":", 1)
        ports.append(
            {
                "protocol": protocol,
                "local_address": address.strip("[]") or "0.0.0.0",
                "local_port": int(port) if port.isdigit() else None,
                "status": "LISTEN",
                "pid": None,
                "process": parts[-1] if len(parts) > 5 else "",
            }
        )
    return ports[:120]


def collect_firewall_status():
    for name in ["firewalld", "ufw", "nftables"]:
        if command_output(["systemctl", "is-active", name]) == "active":
            return {"enabled": True, "name": name, "detail": f"Activo ({name})"}
    return {"enabled": False, "name": "", "detail": "No activo"}


def collect_os_security_status():
    if command_exists("getenforce"):
        status = command_output(["getenforce"])
        return {"enabled": status in ["Enforcing", "Permissive"], "name": "SELinux", "detail": f"Activo ({status.lower()})"}
    if command_exists("aa-status"):
        status = command_output(["sh", "-c", "aa-status --enabled >/dev/null 2>&1 && echo enabled || echo disabled"])
        return {"enabled": status == "enabled", "name": "AppArmor", "detail": "Activo (apparmor)" if status == "enabled" else "AppArmor no activo"}
    return {"enabled": False, "name": "", "detail": "SELinux/AppArmor no detectado"}


def collect_disk_encryption_status():
    root_source = command_output(["findmnt", "-n", "-o", "SOURCE", "/"])
    if not root_source:
        return {"enabled": False, "detail": "No fue posible identificar el volumen raiz", "pending": True}
    chain = command_output(["lsblk", "-nrpo", "TYPE", "-s", root_source]).lower().split()
    encrypted = "crypt" in chain or command_output(["lsblk", "-no", "TYPE", root_source]).lower() == "crypt"
    return {
        "enabled": encrypted,
        "detail": "Volumen raiz protegido por cifrado en la cadena del dispositivo"
        if encrypted
        else "No se detecto cifrado en la cadena del volumen raiz",
    }


def collect_patch_status():
    if command_exists("apt-get"):
        output = command_output(["apt-get", "-s", "upgrade"])
        if output:
            has_updates = "upgraded," in output and "0 upgraded," not in output
            return {
                "up_to_date": not has_updates,
                "detail": "Hay actualizaciones disponibles via apt" if has_updates else "Sin actualizaciones pendientes via apt",
            }
    if command_exists("dnf") or command_exists("yum"):
        manager = "dnf" if command_exists("dnf") else "yum"
        status = subprocess.run([manager, "-q", "check-update", "--cacheonly"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if status.returncode == 0:
            return {"up_to_date": True, "detail": "Sin actualizaciones pendientes"}
        if status.returncode == 100:
            return {"up_to_date": False, "detail": "Hay actualizaciones disponibles"}
    return {"up_to_date": False, "detail": "No fue posible consultar actualizaciones desde el cache local", "pending": True}


def collect_security_status():
    return {
        "disk_encryption": collect_disk_encryption_status(),
        "firewall": collect_firewall_status(),
        "os_security": collect_os_security_status(),
        "patch_compliance": collect_patch_status(),
        "os_version": {"supported": True, "detail": platform.platform()},
    }


def collect_metrics():
    disks, disk_root_percent = disk_usage()
    return {
        "hostname": HOSTNAME,
        "agent_version": "1.1.0-stdlib",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "cpu_percent": cpu_percent(),
            "memory_percent": memory_percent(),
            "disk_root_percent": disk_root_percent,
            "disk_count": len(disks),
            "disks": disks,
            "uptime_seconds": uptime_seconds(),
            "load_1m": os.getloadavg()[0] if hasattr(os, "getloadavg") else None,
            "security": collect_security_status(),
        },
        "inventory": collect_inventory(),
        "services": collect_services(),
        "processes": collect_processes(),
        "ports": collect_ports(),
    }


def send_payload(payload):
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        API_URL,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    context = None if VERIFY_TLS else ssl._create_unverified_context()
    with urlopen(request, timeout=20, context=context) as response:
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}")


def main():
    while True:
        try:
            send_payload(collect_metrics())
        except Exception as exc:
            print(f"{datetime.now(timezone.utc).isoformat()} error={exc}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
