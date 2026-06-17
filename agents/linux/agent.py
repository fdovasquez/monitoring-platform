import os
import socket
import time
from datetime import datetime, timezone

import psutil
import requests


API_URL = os.environ["MONITORING_API_URL"]
TOKEN = os.environ["MONITORING_AGENT_TOKEN"]
HOSTNAME = os.environ.get("MONITORING_HOSTNAME") or socket.gethostname()
INTERVAL = int(os.environ.get("MONITORING_INTERVAL", "60"))
VERIFY_TLS = os.environ.get("MONITORING_VERIFY_TLS", "true").lower() == "true"


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
