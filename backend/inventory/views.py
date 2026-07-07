from collections import defaultdict
from datetime import timedelta
import json
import shlex
import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout, update_session_auth_hash
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import Group, User
from django.http import FileResponse, Http404, HttpResponse
from django.db.models import Count, OuterRef, Subquery
from django.shortcuts import get_object_or_404, redirect
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.generic import TemplateView

from alerts.models import AlertEvent, AlertRule
from metrics.models import MetricSample

from .forms import (
    AccountPasswordChangeForm,
    MachineCredentialForm,
    ProfileForm,
    ROLE_NAMES,
    ServerEditForm,
    UserCreateForm,
    UserEditForm,
    ensure_base_roles,
)
from .models import (
    AgentToken,
    DeviceGroup,
    MachineCredential,
    Server,
    ServerInventory,
    ServerRuntimeSnapshot,
    UserProfile,
)


def sidebar_context():
    return {
        "device_groups": DeviceGroup.objects.annotate(server_count=Count("servers")).order_by("name"),
    }


def user_can_manage_credentials(user):
    return user.is_superuser or user.groups.filter(name="Administrador").exists()


def user_can_manage_devices(user):
    return user.is_superuser or user.groups.filter(name__in=["Administrador", "Editor"]).exists()


def agent_download(request, platform, filename):
    allowed_files = {
        ("linux", "agent.py"): settings.BASE_DIR.parent / "agents" / "linux" / "agent.py",
        ("linux", "monitoring-agent.service"): settings.BASE_DIR.parent / "agents" / "linux" / "monitoring-agent.service",
        ("linux", "monitoring-agent-linux-x86_64"): settings.BASE_DIR.parent
        / "agents"
        / "dist"
        / "linux"
        / "monitoring-agent-linux-x86_64",
        ("windows", "agent.ps1"): settings.BASE_DIR.parent / "agents" / "windows" / "agent.ps1",
    }
    file_path = allowed_files.get((platform, filename))
    if not file_path or not file_path.exists():
        raise Http404("Archivo de agente no encontrado.")
    return FileResponse(open(file_path, "rb"), as_attachment=True, filename=filename)


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
        group_id = self.request.GET.get("group")
        latest_sample_id = MetricSample.objects.filter(server=OuterRef("pk")).order_by("-timestamp").values("id")[:1]
        servers = (
            Server.objects.select_related("agent_token", "group")
            .annotate(latest_sample_id=Subquery(latest_sample_id))
            .order_by("hostname")
        )
        if group_id:
            servers = servers.filter(group_id=group_id)

        servers = list(servers)
        sample_ids = [server.latest_sample_id for server in servers if server.latest_sample_id]
        samples_by_id = MetricSample.objects.in_bulk(sample_ids)

        now = timezone.now()
        devices = []

        for server in servers:
            sample = samples_by_id.get(server.latest_sample_id)
            online = bool(server.last_seen and server.last_seen >= now - timedelta(minutes=1))
            security = self.security_assessment(sample)
            devices.append(
                {
                    "server": server,
                    "sample": sample,
                    "agent_version": sample.agent_version if sample and sample.agent_version else "",
                    "online": online,
                    "security_score": security["score"],
                    "security_tone": security["tone"],
                    "uptime": self.format_uptime(sample.uptime_seconds if sample else None),
                }
            )

        context["devices"] = devices
        context["alert_dashboard"] = self.alert_dashboard(devices)
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
    def alert_dashboard(devices):
        server_ids = [device["server"].id for device in devices]
        alerts_by_server = defaultdict(list)
        if server_ids:
            active_alerts = (
                AlertEvent.objects.select_related("rule", "server")
                .filter(server_id__in=server_ids, is_resolved=False)
                .order_by("-created_at")
            )
            for alert in active_alerts:
                alerts_by_server[alert.server_id].append(alert)

        priority_rank = {
            AlertRule.PRIORITY_CRITICAL: 3,
            AlertRule.PRIORITY_WARNING: 2,
            AlertRule.PRIORITY_INFO: 1,
        }
        buckets = {
            "critical": [],
            "warning": [],
            "ok": [],
        }

        for device in devices:
            alerts = alerts_by_server.get(device["server"].id, [])
            if not alerts:
                device.update(
                    {
                        "alert_count": 0,
                        "alert_level": "ok",
                        "alert_label": "Sin alertas",
                        "alert_title": "Normal",
                        "alert_message": "Sin alertas activas",
                        "alert_event": None,
                    }
                )
                buckets["ok"].append(device)
                continue

            highest_alert = max(alerts, key=lambda alert: priority_rank.get(alert.rule.priority, 1))
            is_critical = highest_alert.rule.priority == AlertRule.PRIORITY_CRITICAL
            alert_level = "critical" if is_critical else "warning"
            device.update(
                {
                    "alert_count": len(alerts),
                    "alert_level": alert_level,
                    "alert_label": "Critico" if is_critical else "Advertencia",
                    "alert_title": highest_alert.rule.name,
                    "alert_message": highest_alert.message,
                    "alert_event": highest_alert,
                }
            )
            buckets[alert_level].append(device)

        return {
            "critical": buckets["critical"],
            "warning": buckets["warning"],
            "ok": buckets["ok"],
            "critical_count": len(buckets["critical"]),
            "warning_count": len(buckets["warning"]),
            "ok_count": len(buckets["ok"]),
            "total_count": len(devices),
        }

    @staticmethod
    def security_score(sample):
        return DeviceListView.security_assessment(sample)["score"]

    @staticmethod
    def security_assessment(sample):
        if not sample:
            checks = [
                DeviceListView.security_check("Disk encryption", False, "Sin datos del agente", 5),
                DeviceListView.security_check("Firewall", False, "Sin datos del agente", 25),
                DeviceListView.security_check("OS security", False, "Sin datos del agente", 25),
                DeviceListView.security_check("Patch compliance", False, "Sin datos del agente", 25),
                DeviceListView.security_check("OS version", False, "Sin datos del agente", 20),
            ]
            return DeviceListView.security_summary(checks)

        metrics = sample.payload.get("metrics", {}) if isinstance(sample.payload, dict) else {}
        security = metrics.get("security", {}) if isinstance(metrics.get("security"), dict) else {}
        inventory = sample.payload.get("inventory", {}) if isinstance(sample.payload, dict) else {}

        disk_encryption = security.get("disk_encryption", {}) if isinstance(security.get("disk_encryption"), dict) else {}
        firewall = security.get("firewall", {}) if isinstance(security.get("firewall"), dict) else {}
        os_security = security.get("os_security", {}) if isinstance(security.get("os_security"), dict) else {}
        patch_compliance = security.get("patch_compliance", {}) if isinstance(security.get("patch_compliance"), dict) else {}
        os_version = security.get("os_version", {}) if isinstance(security.get("os_version"), dict) else {}

        checks = [
            DeviceListView.security_check(
                "Disk encryption",
                bool(disk_encryption.get("enabled")),
                disk_encryption.get("detail") or "Primary disk not encrypted",
                5,
            ),
            DeviceListView.security_check(
                "Firewall",
                bool(firewall.get("enabled")),
                firewall.get("detail") or "Firewall no activo",
                25,
            ),
            DeviceListView.security_check(
                "OS security",
                bool(os_security.get("enabled")),
                os_security.get("detail") or "Control de seguridad no activo",
                25,
            ),
            DeviceListView.security_check(
                "Patch compliance",
                bool(patch_compliance.get("up_to_date")),
                patch_compliance.get("detail") or "No evaluado",
                25,
            ),
            DeviceListView.security_check(
                "OS version",
                bool(os_version.get("supported", True)),
                os_version.get("detail") or inventory.get("os_version") or "Version no informada",
                20,
            ),
        ]
        return DeviceListView.security_summary(checks)

    @staticmethod
    def security_check(label, passed, detail, weight):
        return {
            "label": label,
            "passed": passed,
            "detail": detail,
            "weight": weight,
        }

    @staticmethod
    def security_summary(checks):
        score = sum(check["weight"] for check in checks if check["passed"])
        score = max(0, min(score, 100))
        if score >= 90:
            level = "Bajo riesgo"
            tone = "success"
        elif score >= 70:
            level = "Riesgo medio"
            tone = "warning"
        else:
            level = "Riesgo alto"
            tone = "danger"
        return {
            "score": score,
            "level": level,
            "tone": tone,
            "checks": checks,
            "gauge_rotation": round(-75 + (score * 1.5), 2),
        }

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
        online = bool(server.last_seen and server.last_seen >= timezone.now() - timedelta(minutes=1))
        disk_details = self.disk_details(latest)
        disk_count = self.disk_count(latest, disk_details)
        inventory = self.inventory_snapshot(server)
        runtime = self.runtime_snapshot(server)
        security = DeviceListView.security_assessment(latest)
        active_alerts = server.alert_events.select_related("rule").filter(is_resolved=False).order_by("-created_at")[:8]
        context.update(
            {
                "server": server,
                "samples": samples,
                "latest": latest,
                "online": online,
                "uptime": DeviceListView.format_uptime(latest.uptime_seconds if latest else None),
                "security": security,
                "security_score": security["score"],
                "cpu_display": self.percent_display(latest.cpu_percent if latest else None),
                "memory_display": self.percent_display(latest.memory_percent if latest else None),
                "disk_display": self.percent_display(latest.disk_percent if latest else None),
                "cpu_tone": self.utilization_tone(latest.cpu_percent if latest else None),
                "memory_tone": self.utilization_tone(latest.memory_percent if latest else None),
                "disk_tone": self.utilization_tone(latest.disk_percent if latest else None),
                "disk_count": disk_count,
                "disk_details": disk_details,
                "inventory": inventory,
                "runtime": runtime,
                "chart_series": self.chart_series(samples),
                "recent_events": self.recent_events(server, samples, latest, online),
                "active_alerts": active_alerts,
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
    def runtime_snapshot(server):
        try:
            runtime = server.runtime_snapshot
        except ServerRuntimeSnapshot.DoesNotExist:
            return None
        services = runtime.services or []
        processes = runtime.processes or []
        ports = runtime.ports or []
        stopped_services = [
            service
            for service in services
            if str(service.get("state", "")).lower() not in ["active", "running"]
        ]
        return {
            "record": runtime,
            "services": services[:20],
            "stopped_services": stopped_services[:12],
            "processes": processes[:15],
            "ports": ports[:30],
            "service_count": len(services),
            "process_count": len(processes),
            "port_count": len(ports),
            "stopped_count": len(stopped_services),
        }

    @staticmethod
    def chart_series(samples):
        ordered_samples = list(reversed(samples))
        return [
            DeviceDetailView.chart_definition(ordered_samples, "CPU", "cpu", "cpu_percent"),
            DeviceDetailView.chart_definition(ordered_samples, "Memoria", "memory", "memory_percent"),
            DeviceDetailView.chart_definition(ordered_samples, "Disco", "disk", "disk_percent"),
            DeviceDetailView.chart_definition(ordered_samples, "Red", "network", "network_percent", from_payload=True),
        ]

    @staticmethod
    def chart_definition(samples, label, class_name, metric_name, from_payload=False):
        points = DeviceDetailView.chart_points(samples, metric_name, from_payload)
        return {
            "label": label,
            "points": " ".join(f"{point['x']},{point['y']}" for point in points),
            "points_json": json.dumps(points),
            "class": class_name,
        }

    @staticmethod
    def chart_points(samples, metric_name, from_payload=False):
        values = []
        for sample in samples:
            if from_payload:
                metrics = sample.payload.get("metrics", {}) if isinstance(sample.payload, dict) else {}
                value = metrics.get(metric_name)
            else:
                value = getattr(sample, metric_name)
            if value is None:
                continue
            try:
                values.append((sample, float(value)))
            except (TypeError, ValueError):
                continue
        if not values:
            return []
        if len(values) == 1:
            x_positions = [150]
        else:
            step = 300 / (len(values) - 1)
            x_positions = [round(index * step, 2) for index in range(len(values))]
        points = []
        for x_position, (sample, value) in zip(x_positions, values):
            y_position = round(80 - max(0, min(float(value), 100)) * 0.8, 2)
            local_timestamp = timezone.localtime(sample.timestamp)
            points.append(
                {
                    "x": x_position,
                    "y": y_position,
                    "value": round(value, 2),
                    "label": f"{round(value, 2):g}%",
                    "timestamp": local_timestamp.strftime("%d/%m/%Y %I:%M %p").replace("AM", "a.m.").replace("PM", "p.m."),
                }
            )
        return points

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
        if sample.disk_percent is not None and float(sample.disk_percent) > 0:
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


class DeviceDeleteView(LoginRequiredMixin, AdminRoleRequiredMixin, TemplateView):
    template_name = "inventory/device_confirm_delete.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["server"] = get_object_or_404(Server, id=kwargs["pk"])
        context.update(sidebar_context())
        return context

    def post(self, request, pk):
        server = get_object_or_404(Server, id=pk)
        server_name = server.name or server.hostname
        server.delete()
        messages.success(request, f"Servidor {server_name} eliminado correctamente.")
        return redirect("device-list")


class DeviceEditView(LoginRequiredMixin, DeviceManagerRoleRequiredMixin, TemplateView):
    template_name = "inventory/device_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        server = get_object_or_404(Server, id=kwargs["pk"])
        context.update(
            {
                "server": server,
                "form": ServerEditForm(instance=server),
            }
        )
        context.update(sidebar_context())
        return context

    def post(self, request, pk):
        server = get_object_or_404(Server, id=pk)
        form = ServerEditForm(request.POST, instance=server)
        if form.is_valid():
            form.save()
            messages.success(request, "Servidor actualizado correctamente.")
            return redirect("device-detail", pk=server.id)

        context = {"server": server, "form": form}
        context.update(sidebar_context())
        return self.render_to_response(context)


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
        context["selected_platform"] = self.request.GET.get("platform", "windows")
        server_id = self.request.GET.get("server")
        if server_id:
            try:
                server = Server.objects.select_related("agent_token").get(id=server_id)
            except Server.DoesNotExist:
                server = None
            if server:
                token, _ = AgentToken.objects.get_or_create(server=server)
                api_url = self.api_url()
                download_base_url = self.download_base_url()
                context.update(
                    {
                        "created_server": server,
                        "agent_token": token,
                        "linux_script": self.linux_script(token.token, self.linux_installer_url()),
                        "ubuntu_script": self.linux_script(token.token, self.linux_installer_url()),
                        "windows_script": self.windows_script(token.token, api_url, download_base_url),
                    }
                )
        return context

    def post(self, request):
        selected_platform = request.POST.get("platform", "windows").strip()
        os_type = Server.OS_WINDOWS if selected_platform == "windows" else Server.OS_LINUX
        group_id = request.POST.get("group", "").strip()
        group_name = request.POST.get("group_name", "").strip()

        group = None
        if group_name:
            group, _ = DeviceGroup.objects.get_or_create(name=group_name)
        elif group_id:
            group = DeviceGroup.objects.filter(id=group_id).first()

        server = Server.objects.create(
            hostname=f"pendiente-{uuid.uuid4().hex[:12]}",
            name="Agente pendiente de registro",
            group=group,
            os_type=os_type,
            environment="produccion",
            is_active=True,
        )
        AgentToken.objects.create(server=server)
        messages.success(request, "Token generado. Copia el comando en el servidor cliente; el equipo se registrara automaticamente.")
        return redirect(f"{request.path}?server={server.id}&platform={selected_platform}")

    def api_url(self):
        return self.request.build_absolute_uri("/api/v1/metrics/ingest/")

    def download_base_url(self):
        return self.request.build_absolute_uri("/app/agents/download/")

    def linux_installer_url(self):
        return self.request.build_absolute_uri("/app/agents/install/linux.sh")

    @staticmethod
    def linux_script(token, installer_url):
        return f"curl -kfsSL {shlex.quote(installer_url)} | bash -s -- {shlex.quote(token)}"

    @staticmethod
    def linux_bootstrap_script(api_url, download_base_url):
        return f"""#!/bin/bash
set -e

TOKEN="${{1:-}}"
if [ -z "$TOKEN" ]; then
  echo "ERROR: Falta el token de instalacion."
  exit 1
fi

INSTALL_LOG="/var/log/monitoring-agent-install.log"
exec > >(tee -a "$INSTALL_LOG") 2>&1
trap 'status=$?; echo "ERROR: La instalacion fallo (codigo $status). Revisa $INSTALL_LOG"; exit $status' ERR

echo "Instalando agente de monitoreo. El registro quedara en $INSTALL_LOG"
mkdir -p /opt/monitoring-agent
systemctl stop monitoring-agent 2>/dev/null || true
AGENT_BASE_URL="{download_base_url}linux"
AGENT_BINARY="/opt/monitoring-agent/monitoring-agent"
AGENT_TEMP="/opt/monitoring-agent/monitoring-agent.new"
CA_CERT="/opt/monitoring-agent/monitor-ca-chain.pem"
SERVICE_FILE="/etc/systemd/system/monitoring-agent.service"

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: Se requiere openssl para registrar el certificado del monitor."
  exit 1
fi

MONITOR_HOST="$(printf '%s' "{api_url}" | sed -E 's#https?://([^/:]+).*#\\1#')"
echo | openssl s_client -showcerts -connect "${{MONITOR_HOST}}:443" -servername "${{MONITOR_HOST}}" 2>/dev/null \
  | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$CA_CERT"

if [ ! -s "$CA_CERT" ]; then
  echo "ERROR: No se pudo obtener el certificado del monitor ${{MONITOR_HOST}}."
  exit 1
fi

download_file() {{
  local url="$1"
  local destination="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --cacert "$CA_CERT" "$url" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --ca-certificate="$CA_CERT" "$url" -O "$destination"
  else
    echo "ERROR: Se requiere curl o wget para descargar el agente desde el monitor interno."
    exit 1
  fi
}}

if [ "$(uname -m)" != "x86_64" ]; then
  echo "ERROR: El paquete actual es compatible con Linux x86_64. Arquitectura detectada: $(uname -m)"
  exit 1
fi

download_file "$AGENT_BASE_URL/monitoring-agent-linux-x86_64" "$AGENT_TEMP"
download_file "$AGENT_BASE_URL/monitoring-agent.service" "$SERVICE_FILE"

cat >/etc/monitoring-agent.env <<EOF
MONITORING_API_URL={api_url}
MONITORING_AGENT_TOKEN=$TOKEN
MONITORING_INTERVAL=60
MONITORING_PACKAGE_QUERY_ONLINE=false
MONITORING_VERIFY_TLS=true
MONITORING_CA_FILE=/opt/monitoring-agent/monitor-ca-chain.pem
EOF

chmod 600 /etc/monitoring-agent.env
chmod 755 "$AGENT_TEMP"
mv -f "$AGENT_TEMP" "$AGENT_BINARY"
systemctl daemon-reload
systemctl enable --now monitoring-agent

if systemctl is-active --quiet monitoring-agent; then
  echo "INSTALACION COMPLETADA: monitoring-agent esta activo."
else
  echo "ERROR: El servicio no pudo iniciar."
  systemctl status monitoring-agent --no-pager || true
  exit 1
fi

echo "Para revisar el resultado: journalctl -u monitoring-agent -n 50 --no-pager"
"""

    @staticmethod
    def windows_script(token, api_url, download_base_url):
        return f"""$ErrorActionPreference = "Stop"
$AgentDirectory = "C:\\ProgramData\\MonitoringAgent"
$AgentScript = Join-Path $AgentDirectory "agent.ps1"
$ConfigFile = Join-Path $AgentDirectory "agent.env.ps1"

New-Item -ItemType Directory -Path $AgentDirectory -Force | Out-Null
Invoke-WebRequest -Uri "{download_base_url}windows/agent.ps1" -OutFile $AgentScript

@(
  '$env:MONITORING_API_URL = "{api_url}"'
  '$env:MONITORING_AGENT_TOKEN = "{token}"'
  '$env:MONITORING_SKIP_TLS_VERIFY = "true"'
) | Set-Content -Path $ConfigFile -Encoding UTF8

$TaskCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$AgentScript`""
schtasks.exe /Delete /TN "MonitoringAgent" /F 2>$null | Out-Null
schtasks.exe /Create /TN "MonitoringAgent" /TR $TaskCommand /SC MINUTE /MO 1 /RU SYSTEM /RL HIGHEST /F | Out-Null
schtasks.exe /Run /TN "MonitoringAgent" | Out-Null
Write-Host "Instalacion completada. Ejecutando una prueba de envio..." -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $AgentScript
if ($LASTEXITCODE -eq 0) {{
  Write-Host "Prueba enviada correctamente al servidor de monitoreo." -ForegroundColor Green
}}
Write-Host ""
schtasks.exe /Query /TN "MonitoringAgent" /V /FO LIST
Read-Host "Presiona Enter para cerrar"
"""


def linux_install_script(request):
    api_url = request.build_absolute_uri("/api/v1/metrics/ingest/")
    download_base_url = request.build_absolute_uri("/app/agents/download/")
    script = AgentInstallWizardView.linux_bootstrap_script(api_url, download_base_url)
    return HttpResponse(script, content_type="text/x-shellscript; charset=utf-8")


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
