from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Prefetch
from django.shortcuts import redirect
from django.utils import timezone
from django.views.generic import TemplateView

from metrics.models import MetricSample

from .models import AgentToken, Server


class DeviceListView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/device_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        latest_samples = MetricSample.objects.order_by("-timestamp")
        servers = (
            Server.objects.prefetch_related(Prefetch("metric_samples", queryset=latest_samples, to_attr="latest_samples"))
            .select_related("agent_token")
            .order_by("hostname")
        )
        now = timezone.now()
        devices = []

        for server in servers:
            sample = server.latest_samples[0] if server.latest_samples else None
            online = bool(server.last_seen and server.last_seen >= now - timedelta(minutes=5))
            devices.append(
                {
                    "server": server,
                    "sample": sample,
                    "online": online,
                    "security_score": self.security_score(sample),
                    "uptime": self.format_uptime(sample.uptime_seconds if sample else None),
                    "latency": self.synthetic_latency(server.id),
                }
            )

        context["devices"] = devices
        context["total_devices"] = len(devices)
        context["online_devices"] = sum(1 for device in devices if device["online"])
        context["offline_devices"] = sum(1 for device in devices if not device["online"])
        context["windows_devices"] = sum(1 for device in devices if device["server"].os_type == Server.OS_WINDOWS)
        context["linux_devices"] = sum(1 for device in devices if device["server"].os_type == Server.OS_LINUX)
        return context

    @staticmethod
    def security_score(sample):
        if not sample:
            return 0
        score = 100
        for value in (sample.cpu_percent, sample.memory_percent, sample.disk_percent):
            if value and value >= 90:
                score -= 20
            elif value and value >= 80:
                score -= 10
        return max(score, 0)

    @staticmethod
    def synthetic_latency(server_id):
        return 6 + (server_id % 9)

    @staticmethod
    def format_uptime(seconds):
        if not seconds:
            return "-"
        minutes = int(seconds // 60)
        days, minutes = divmod(minutes, 1440)
        hours, minutes = divmod(minutes, 60)
        if days:
            return f"{days}d {hours}h {minutes}m"
        if hours:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"


class AgentInstallWizardView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/agent_install_wizard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        server_id = self.request.GET.get("server")
        if server_id:
            try:
                server = Server.objects.select_related("agent_token").get(id=server_id)
            except Server.DoesNotExist:
                server = None
            if server:
                token, _ = AgentToken.objects.get_or_create(server=server)
                api_url = self.api_url()
                context.update(
                    {
                        "created_server": server,
                        "agent_token": token,
                        "linux_script": self.linux_script(server, token.token, api_url, "dnf"),
                        "ubuntu_script": self.linux_script(server, token.token, api_url, "apt"),
                        "windows_script": self.windows_script(server, token.token, api_url),
                    }
                )
        return context

    def post(self, request):
        hostname = request.POST.get("hostname", "").strip()
        name = request.POST.get("name", "").strip()
        ip_address = request.POST.get("ip_address", "").strip() or None
        os_type = request.POST.get("os_type", Server.OS_LINUX)
        environment = request.POST.get("environment", "produccion").strip()
        owner = request.POST.get("owner", "").strip()

        if not hostname:
            messages.error(request, "Ingresa el nombre del servidor.")
            return redirect("agent-install")

        server, created = Server.objects.get_or_create(
            hostname=hostname,
            defaults={
                "name": name,
                "ip_address": ip_address,
                "os_type": os_type,
                "environment": environment,
                "owner": owner,
                "is_active": True,
            },
        )

        if not created:
            server.name = name or server.name
            server.ip_address = ip_address or server.ip_address
            server.os_type = os_type
            server.environment = environment or server.environment
            server.owner = owner or server.owner
            server.is_active = True
            server.save()

        AgentToken.objects.get_or_create(server=server)
        return redirect(f"{request.path}?server={server.id}")

    def api_url(self):
        return self.request.build_absolute_uri("/api/v1/metrics/ingest/")

    @staticmethod
    def linux_script(server, token, api_url, package_manager):
        installer = "dnf install -y git python3 python3-pip" if package_manager == "dnf" else "apt update && apt install -y git python3 python3-venv python3-pip"
        return f"""#!/bin/bash
set -e

{installer}
cd /opt
if [ ! -d /opt/monitoring-platform ]; then
  git clone https://github.com/fdovasquez/monitoring-platform.git /opt/monitoring-platform
else
  cd /opt/monitoring-platform && git pull
fi

mkdir -p /opt/monitoring-agent
cp /opt/monitoring-platform/agents/linux/agent.py /opt/monitoring-agent/agent.py
python3 -m venv /opt/monitoring-agent/.venv
/opt/monitoring-agent/.venv/bin/pip install --upgrade pip
/opt/monitoring-agent/.venv/bin/pip install psutil requests

cat >/etc/monitoring-agent.env <<'EOF'
MONITORING_API_URL={api_url}
MONITORING_AGENT_TOKEN={token}
MONITORING_HOSTNAME={server.hostname}
MONITORING_INTERVAL=60
MONITORING_VERIFY_TLS=false
EOF

chmod 600 /etc/monitoring-agent.env
cp /opt/monitoring-platform/agents/linux/monitoring-agent.service /etc/systemd/system/monitoring-agent.service
systemctl daemon-reload
systemctl enable --now monitoring-agent
systemctl status monitoring-agent --no-pager
"""

    @staticmethod
    def windows_script(server, token, api_url):
        return f"""New-Item -ItemType Directory -Force "C:\\ProgramData\\MonitoringAgent"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fdovasquez/monitoring-platform/main/agents/windows/agent.ps1" -OutFile "C:\\ProgramData\\MonitoringAgent\\agent.ps1"

@'
$env:MONITORING_API_URL = "{api_url}"
$env:MONITORING_AGENT_TOKEN = "{token}"
$env:MONITORING_HOSTNAME = "{server.hostname}"
$env:MONITORING_SKIP_TLS_VERIFY = "true"
'@ | Set-Content "C:\\ProgramData\\MonitoringAgent\\agent.env.ps1"

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\MonitoringAgent\\agent.ps1"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "MonitoringAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Force
Start-ScheduledTask -TaskName "MonitoringAgent"
Get-ScheduledTaskInfo -TaskName "MonitoringAgent"
"""
