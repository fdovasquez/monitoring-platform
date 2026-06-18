from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import logout, update_session_auth_hash
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import Group, User
from django.db.models import Count, Prefetch
from django.shortcuts import get_object_or_404, redirect
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.generic import TemplateView

from metrics.models import MetricSample

from .forms import (
    AccountPasswordChangeForm,
    MachineCredentialForm,
    ProfileForm,
    ROLE_NAMES,
    UserCreateForm,
    UserEditForm,
    ensure_base_roles,
)
from .models import AgentToken, DeviceGroup, MachineCredential, Server, ServerInventory, UserProfile


def sidebar_context():
    return {
        "device_groups": DeviceGroup.objects.annotate(server_count=Count("servers")).order_by("name"),
    }


def user_can_manage_credentials(user):
    return user.is_superuser or user.groups.filter(name="Administrador").exists()


def user_can_manage_devices(user):
    return user.is_superuser or user.groups.filter(name__in=["Administrador", "Editor"]).exists()


class AdminRoleRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return user_can_manage_credentials(self.request.user)


class DeviceManagerRoleRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return user_can_manage_devices(self.request.user)


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
        context["can_manage_devices"] = user_can_manage_devices(self.request.user)
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
        samples = list(server.metric_samples.order_by("-timestamp")[:25])
        latest = samples[0] if samples else None
        online = bool(server.last_seen and server.last_seen >= timezone.now() - timedelta(minutes=5))
        disk_details = self.disk_details(latest)
        disk_count = self.disk_count(latest, disk_details)
        inventory = self.inventory_snapshot(server)
        context.update(
            {
                "server": server,
                "samples": samples,
                "latest": latest,
                "online": online,
                "uptime": DeviceListView.format_uptime(latest.uptime_seconds if latest else None),
                "security_score": DeviceListView.security_score(latest),
                "cpu_display": self.percent_display(latest.cpu_percent if latest else None),
                "memory_display": self.percent_display(latest.memory_percent if latest else None),
                "disk_display": self.percent_display(latest.disk_percent if latest else None),
                "cpu_tone": self.utilization_tone(latest.cpu_percent if latest else None),
                "memory_tone": self.utilization_tone(latest.memory_percent if latest else None),
                "disk_tone": self.utilization_tone(latest.disk_percent if latest else None),
                "disk_count": disk_count,
                "disk_details": disk_details,
                "inventory": inventory,
                "chart_series": self.chart_series(samples),
                "recent_events": self.recent_events(server, samples, latest, online),
                "credential_form": MachineCredentialForm(),
                "credentials": server.credentials.all(),
                "can_manage_credentials": user_can_manage_credentials(self.request.user),
                "can_manage_devices": user_can_manage_devices(self.request.user),
                "is_linux": server.os_type == Server.OS_LINUX,
            }
        )
        context.update(sidebar_context())
        return context

    @staticmethod
    def inventory_snapshot(server):
        try:
            inventory = server.inventory
        except ServerInventory.DoesNotExist:
            return None
        return {
            "record": inventory,
            "items": [
                ("FQDN", inventory.fqdn),
                ("SO detectado", inventory.os_name),
                ("Version SO", inventory.os_version),
                ("Kernel / Build", inventory.kernel),
                ("Arquitectura", inventory.architecture),
                ("Fabricante", inventory.manufacturer),
                ("Modelo", inventory.model),
                ("Serie", inventory.serial_number),
                ("Dominio", inventory.domain),
                ("Usuario conectado", inventory.logged_user),
                ("IP principal", inventory.primary_ip),
                ("Gateway", inventory.gateway),
                ("DNS", ", ".join(inventory.dns_servers or [])),
                ("Zona horaria", inventory.timezone),
                ("Recolectado", inventory.collected_at),
            ],
            "interfaces": inventory.interfaces or [],
            "mac_addresses": inventory.mac_addresses or [],
        }

    @staticmethod
    def chart_series(samples):
        ordered_samples = list(reversed(samples))
        return [
            {"label": "CPU", "points": DeviceDetailView.svg_points(ordered_samples, "cpu_percent"), "class": "cpu"},
            {"label": "Memoria", "points": DeviceDetailView.svg_points(ordered_samples, "memory_percent"), "class": "memory"},
            {"label": "Disco", "points": DeviceDetailView.svg_points(ordered_samples, "disk_percent"), "class": "disk"},
            {"label": "Red", "points": DeviceDetailView.svg_payload_points(ordered_samples, "network_percent"), "class": "network"},
        ]

    @staticmethod
    def svg_points(samples, field_name):
        values = [getattr(sample, field_name) for sample in samples if getattr(sample, field_name) is not None]
        if not values:
            return ""
        if len(values) == 1:
            x_positions = [150]
        else:
            step = 300 / (len(values) - 1)
            x_positions = [round(index * step, 2) for index in range(len(values))]
        points = []
        for x_position, value in zip(x_positions, values):
            y_position = round(80 - max(0, min(float(value), 100)) * 0.8, 2)
            points.append(f"{x_position},{y_position}")
        return " ".join(points)

    @staticmethod
    def svg_payload_points(samples, metric_name):
        values = []
        for sample in samples:
            metrics = sample.payload.get("metrics", {}) if isinstance(sample.payload, dict) else {}
            value = metrics.get(metric_name)
            if value is not None:
                values.append(value)
        if not values:
            return ""
        if len(values) == 1:
            x_positions = [150]
        else:
            step = 300 / (len(values) - 1)
            x_positions = [round(index * step, 2) for index in range(len(values))]
        points = []
        for x_position, value in zip(x_positions, values):
            y_position = round(80 - max(0, min(float(value), 100)) * 0.8, 2)
            points.append(f"{x_position},{y_position}")
        return " ".join(points)

    @staticmethod
    def disk_details(sample):
        if not sample:
            return []
        metrics = sample.payload.get("metrics", {}) if isinstance(sample.payload, dict) else {}
        disks = metrics.get("disks")
        if isinstance(disks, list) and disks:
            return [DeviceDetailView.normalize_disk(disk) for disk in disks]
        if sample.disk_percent is not None:
            return [DeviceDetailView.normalize_disk({"mountpoint": "Principal", "percent": sample.disk_percent})]
        return []

    @staticmethod
    def normalize_disk(disk):
        percent = disk.get("percent")
        total_gb = disk.get("total_gb")
        try:
            percent_value = float(percent) if percent is not None else None
        except (TypeError, ValueError):
            percent_value = None
        try:
            total_value = float(total_gb) if total_gb is not None else None
        except (TypeError, ValueError):
            total_value = None

        used_gb = None
        free_gb = None
        if total_value is not None and percent_value is not None:
            used_gb = round(total_value * percent_value / 100, 2)
            free_gb = round(total_value - used_gb, 2)
        percent_css = DeviceDetailView.percent_css(percent_value)

        return {
            "label": disk.get("mountpoint") or disk.get("device") or "Disco",
            "device": disk.get("device", ""),
            "mountpoint": disk.get("mountpoint", ""),
            "fstype": disk.get("fstype", ""),
            "total_gb": total_value,
            "used_gb": used_gb,
            "free_gb": free_gb,
            "percent": percent_value,
            "percent_css": percent_css,
            "percent_display": DeviceDetailView.percent_display(percent_value),
            "tone": DeviceDetailView.utilization_tone(percent_value),
        }

    @staticmethod
    def percent_css(value):
        if value is None:
            return "0"
        try:
            numeric = max(0, min(float(value), 100))
        except (TypeError, ValueError):
            return "0"
        return f"{numeric:.2f}".rstrip("0").rstrip(".")

    @staticmethod
    def percent_display(value):
        if value is None:
            return "-"
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return "-"
        if numeric.is_integer():
            return f"{int(numeric)}%"
        return f"{numeric:.1f}%"

    @staticmethod
    def utilization_tone(value):
        if value is None:
            return "neutral"
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return "neutral"
        if numeric >= 90:
            return "danger"
        if numeric >= 80:
            return "orange"
        if numeric >= 65:
            return "warning"
        return "success"

    @staticmethod
    def disk_count(sample, disk_details):
        if not sample:
            return 0
        metrics = sample.payload.get("metrics", {}) if isinstance(sample.payload, dict) else {}
        disk_count = metrics.get("disk_count")
        if disk_count is not None:
            try:
                return int(disk_count)
            except (TypeError, ValueError):
                pass
        return len(disk_details)

    @staticmethod
    def recent_events(server, samples, latest, online):
        events = []
        if latest:
            events.append(
                {
                    "date": latest.timestamp,
                    "type": "Agente",
                    "severity": "Info" if online else "Critico",
                    "message": "Metricas recibidas correctamente." if online else "El agente no reporta dentro de la ventana esperada.",
                    "icon": "activity",
                }
            )
            threshold_map = [
                ("CPU", latest.cpu_percent),
                ("Memoria", latest.memory_percent),
                ("Disco", latest.disk_percent),
            ]
            for label, value in threshold_map:
                if value is None:
                    continue
                if value >= 90:
                    events.append(
                        {
                            "date": latest.timestamp,
                            "type": label,
                            "severity": "Critico",
                            "message": f"{label} supera el 90% de utilizacion.",
                            "icon": "alert",
                        }
                    )
                elif value >= 80:
                    events.append(
                        {
                            "date": latest.timestamp,
                            "type": label,
                            "severity": "Advertencia",
                            "message": f"{label} supera el 80% de utilizacion.",
                            "icon": "warning",
                        }
                    )

        for sample in samples[1:4]:
            events.append(
                {
                    "date": sample.timestamp,
                    "type": "Monitoreo",
                    "severity": "Info",
                    "message": f"Muestra registrada para {server.hostname}.",
                    "icon": "activity",
                }
            )
        return events


class MachineCredentialCreateView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
    def post(self, request, pk):
        server = get_object_or_404(Server, id=pk)
        form = MachineCredentialForm(request.POST)
        if form.is_valid():
            credential = form.save(commit=False)
            credential.server = server
            credential.save()
            messages.success(request, "Credencial agregada correctamente.")
        else:
            messages.error(request, "No se pudo guardar la credencial. Revisa los campos.")
        return redirect("device-detail", pk=server.id)


class MachineCredentialDeleteView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
    def post(self, request, pk, credential_id):
        server = get_object_or_404(Server, id=pk)
        credential = get_object_or_404(MachineCredential, id=credential_id, server=server)
        credential.delete()
        messages.success(request, "Credencial eliminada correctamente.")
        return redirect("device-detail", pk=server.id)


@method_decorator(xframe_options_sameorigin, name="dispatch")
class DeviceConsoleView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
    template_name = "inventory/device_console.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        server = get_object_or_404(Server, id=kwargs["pk"])
        context["server"] = server
        context["credentials"] = server.credentials.filter(is_active=True)
        context["is_linux"] = server.os_type == Server.OS_LINUX
        context["command"] = ""
        context["output"] = ""
        context["error"] = ""
        return context

    def post(self, request, pk):
        context = self.get_context_data(pk=pk)
        server = context["server"]
        credential_id = request.POST.get("credential")
        command = request.POST.get("command", "").strip()
        context["command"] = command

        if server.os_type != Server.OS_LINUX:
            context["error"] = "La consola embebida esta disponible solo para equipos Linux."
            return self.render_to_response(context)
        if not command:
            context["error"] = "Ingresa un comando para ejecutar."
            return self.render_to_response(context)

        credential = get_object_or_404(MachineCredential, id=credential_id, server=server, is_active=True)
        try:
            import paramiko
        except ImportError:
            context["error"] = "Falta instalar paramiko en el servidor de monitoreo."
            return self.render_to_response(context)

        host = str(server.ip_address or server.hostname)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=credential.port,
                username=credential.username,
                password=credential.get_secret(),
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            _, stdout, stderr = client.exec_command(command, timeout=30)
            output = stdout.read().decode("utf-8", errors="replace")
            error = stderr.read().decode("utf-8", errors="replace")
            context["output"] = output
            context["error"] = error
            credential.last_used_at = timezone.now()
            credential.save(update_fields=["last_used_at"])
        except Exception as exc:
            context["error"] = f"No se pudo ejecutar el comando: {exc}"
        finally:
            client.close()

        return self.render_to_response(context)


class AgentInstallWizardView(LoginRequiredMixin, DeviceManagerRoleRequiredMixin, TemplateView):
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


class UserListView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
    template_name = "inventory/user_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ensure_base_roles()
        context["roles"] = Group.objects.filter(name__in=ROLE_NAMES).order_by("name")
        context["users"] = User.objects.prefetch_related("groups").order_by("username")
        context.update(sidebar_context())
        return context


class UserCreateView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
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


class UserEditView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
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


class UserDeleteView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
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


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/profile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile, _ = UserProfile.objects.get_or_create(user=self.request.user)
        initials = f"{self.request.user.first_name[:1]}{self.request.user.last_name[:1]}".strip()
        context["profile_form"] = kwargs.get("profile_form") or ProfileForm(user=self.request.user)
        context["password_form"] = kwargs.get("password_form") or AccountPasswordChangeForm(user=self.request.user)
        context["account_profile"] = profile
        context["avatar_initials"] = initials or self.request.user.username[:2].upper()
        context.update(sidebar_context())
        return context

    def post(self, request):
        form = ProfileForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Perfil actualizado correctamente.")
            return redirect("profile")
        messages.error(request, "No se pudo actualizar el perfil. Revisa los campos indicados.")
        return self.render_to_response(self.get_context_data(profile_form=form))


class AccountPasswordChangeView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/profile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile, _ = UserProfile.objects.get_or_create(user=self.request.user)
        initials = f"{self.request.user.first_name[:1]}{self.request.user.last_name[:1]}".strip()
        context["profile_form"] = kwargs.get("profile_form") or ProfileForm(user=self.request.user)
        context["password_form"] = kwargs.get("password_form") or AccountPasswordChangeForm(user=self.request.user)
        context["account_profile"] = profile
        context["avatar_initials"] = initials or self.request.user.username[:2].upper()
        context["focus_security"] = True
        context.update(sidebar_context())
        return context

    def post(self, request):
        form = AccountPasswordChangeForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, "Contrasena actualizada correctamente.")
            return redirect("password-change-done")
        messages.error(request, "No se pudo cambiar la contrasena. Revisa los campos indicados.")
        return self.render_to_response(self.get_context_data(password_form=form))


class AccountPasswordChangeDoneView(LoginRequiredMixin, TemplateView):
    template_name = "inventory/password_change_done.html"


class LogoutView(LoginRequiredMixin, TemplateView):
    def post(self, request):
        logout(request)
        return redirect("login")
