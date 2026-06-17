from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group, User
from django.db.models import Count, Prefetch
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.generic import TemplateView

from metrics.models import MetricSample

from .forms import ROLE_NAMES, UserCreateForm, UserEditForm, ensure_base_roles
from .models import AgentToken, DeviceGroup, Server


def sidebar_context():
    return {
        "device_groups": DeviceGroup.objects.annotate(server_count=Count("servers")).order_by("name"),
    }


class DeviceListView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/device_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        latest_samples = MetricSample.objects.order_by("-timestamp")
        group_id = self.request.GET.get("group")
        servers = (
            Server.objects.prefetch_related(Prefetch("metric_samples", queryset=latest_samples, to_attr="latest_samples"))
            .select_related("agent_token", "group")
            .order_by("hostname")
        )
        if group_id:
            servers = servers.filter(group_id=group_id)

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
        context["selected_group"] = group_id
        context.update(sidebar_context())
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


class DeviceDetailView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/device_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        server = Server.objects.select_related("group", "agent_token").get(id=kwargs["pk"])
        samples = server.metric_samples.order_by("-timestamp")[:25]
        latest = samples[0] if samples else None
        online = bool(server.last_seen and server.last_seen >= timezone.now() - timedelta(minutes=5))
        context.update(
            {
                "server": server,
                "samples": samples,
                "latest": latest,
                "online": online,
                "uptime": DeviceListView.format_uptime(latest.uptime_seconds if latest else None),
                "security_score": DeviceListView.security_score(latest),
            }
        )
        context.update(sidebar_context())
        return context


class AgentInstallWizardView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/agent_install_wizard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(sidebar_context())
        context["groups"] = DeviceGroup.objects.all()
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
        group_id = request.POST.get("group", "").strip()
        group_name = request.POST.get("group_name", "").strip()

        if not hostname:
            messages.error(request, "Ingresa el nombre del servidor.")
            return redirect("agent-install")

        group = None
        if group_name:
            group, _ = DeviceGroup.objects.get_or_create(name=group_name)
        elif group_id:
            group = DeviceGroup.objects.filter(id=group_id).first()

        server, created = Server.objects.get_or_create(
            hostname=hostname,
            defaults={
                "name": name,
                "ip_address": ip_address,
                "group": group,
                "os_type": os_type,
                "environment": environment,
                "owner": owner,
                "is_active": True,
            },
        )

        if not created:
            server.name = name or server.name
            server.ip_address = ip_address or server.ip_address
            server.group = group or server.group
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


class UserListView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/user_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ensure_base_roles()
        context["roles"] = Group.objects.filter(name__in=ROLE_NAMES).order_by("name")
        context["users"] = User.objects.prefetch_related("groups").order_by("username")
        context.update(sidebar_context())
        return context


class UserCreateView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/user_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form"] = kwargs.get("form") or UserCreateForm()
        context["form_title"] = "Crear usuario"
        context["submit_label"] = "Crear usuario"
        context.update(sidebar_context())
        return context

    def post(self, request):
        form = UserCreateForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Usuario creado correctamente.")
            return redirect("user-list")
        return self.render_to_response(self.get_context_data(form=form))


class UserEditView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/user_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = get_object_or_404(User, id=kwargs["pk"])
        context["managed_user"] = user
        context["form"] = kwargs.get("form") or UserEditForm(instance=user)
        context["form_title"] = f"Editar usuario {user.username}"
        context["submit_label"] = "Guardar cambios"
        context.update(sidebar_context())
        return context

    def post(self, request, pk):
        user = get_object_or_404(User, id=pk)
        form = UserEditForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, "Usuario actualizado correctamente.")
            return redirect("user-list")
        return self.render_to_response(self.get_context_data(form=form, pk=pk))


class UserDeleteView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/user_confirm_delete.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["managed_user"] = get_object_or_404(User, id=kwargs["pk"])
        context.update(sidebar_context())
        return context

    def post(self, request, pk):
        user = get_object_or_404(User, id=pk)
        if user == request.user:
            messages.error(request, "No puedes eliminar tu propio usuario mientras estas conectado.")
            return redirect("user-list")
        user.delete()
        messages.success(request, "Usuario eliminado correctamente.")
        return redirect("user-list")
