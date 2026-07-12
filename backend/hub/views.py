from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from inventory.views import sidebar_context, user_can_manage_devices

from .models import Satellite, SatelliteAlert, SatelliteReport, SatelliteServerSnapshot
from .serializers import SatelliteReportSerializer
from .services import store_report


def number_or_none(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def server_disk_risk(server):
    metric = server.latest_metric if isinstance(server.latest_metric, dict) else {}
    payload = metric.get("payload") if isinstance(metric.get("payload"), dict) else {}
    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
    disks = metrics.get("disks")
    candidates = []

    if isinstance(disks, list):
        for disk in disks:
            if not isinstance(disk, dict):
                continue
            percent = number_or_none(disk.get("percent"))
            if percent is None:
                continue
            candidates.append(
                {
                    "server": server,
                    "label": disk.get("mountpoint") or disk.get("device") or "Disco",
                    "percent": percent,
                    "free_gb": number_or_none(disk.get("free_gb")),
                    "total_gb": number_or_none(disk.get("total_gb")),
                }
            )

    disk_percent = number_or_none(metric.get("disk_percent"))
    if not candidates and disk_percent is not None:
        candidates.append(
            {
                "server": server,
                "label": "Principal",
                "percent": disk_percent,
                "free_gb": None,
                "total_gb": None,
            }
        )

    if not candidates:
        return None
    return max(candidates, key=lambda item: item["percent"])


def average_metric(values):
    clean_values = [value for value in values if value is not None]
    if not clean_values:
        return None
    return round(sum(clean_values) / len(clean_values), 1)


def disk_status_for(risk):
    if not risk:
        return "unknown"
    if risk["percent"] >= 90:
        return "critical"
    if risk["percent"] >= 80:
        return "warning"
    return "normal"


def percent_label(value):
    if value is None:
        return "-"
    if float(value).is_integer():
        return f"{int(value)}%"
    return f"{value:.1f}%"


def incoming_token(request):
    header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return ""
    return header[len(prefix) :].strip()


def hub_api_token():
    return getattr(settings, "CENTRAL_HUB_API_TOKEN", "") or getattr(settings, "API_TOKEN", "")


class SatelliteReportIngestView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        expected_token = hub_api_token()
        if not expected_token:
            return Response(
                {"detail": "CENTRAL_HUB_API_TOKEN no configurado en el servidor central."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        if incoming_token(request) != expected_token:
            return Response({"detail": "Token invalido."}, status=status.HTTP_403_FORBIDDEN)

        serializer = SatelliteReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        report = store_report(dict(request.data), serializer.validated_data)
        return Response(
            {
                "status": "ok",
                "satellite": report.satellite.satellite_id,
                "report_id": report.id,
                "received_at": report.received_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )


class HubAccessMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        if settings.CENTRAL_PORTAL_ENABLED:
            return self.request.user.is_authenticated
        return user_can_manage_devices(self.request.user)


class HubDashboardView(HubAccessMixin, TemplateView):
    template_name = "hub/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        satellites = list(Satellite.objects.all())
        servers = list(SatelliteServerSnapshot.objects.select_related("satellite").all())
        active_servers = [server for server in servers if server.is_active]
        total_servers = len(active_servers)
        unresolved_alerts = SatelliteAlert.objects.filter(is_resolved=False).select_related("satellite")
        priority_counts = {
            item["priority"] or "sin_prioridad": item["total"]
            for item in unresolved_alerts.values("priority").annotate(total=Count("id"))
        }
        critical_terms = {"critical", "critica", "critico"}
        alert_lookup = {}
        for alert in unresolved_alerts:
            alert_lookup.setdefault((alert.satellite_id, alert.server_hostname), []).append(alert)

        server_cards = []
        for server in active_servers:
            metric = server.latest_metric if isinstance(server.latest_metric, dict) else {}
            server_alerts = alert_lookup.get((server.satellite_id, server.hostname), [])
            priority = "normal"
            if any((alert.priority or "").lower() in critical_terms for alert in server_alerts):
                priority = "critical"
            elif server_alerts:
                priority = "warning"
            disk_risk = server_disk_risk(server)
            disk_status = disk_status_for(disk_risk)
            if disk_status == "critical":
                priority = "critical"
            elif disk_status == "warning" and priority == "normal":
                priority = "warning"
            server_cards.append(
                {
                    "server": server,
                    "metric": metric,
                    "alerts": server_alerts,
                    "priority": priority,
                    "disk_risk": disk_risk,
                    "disk_status": disk_status,
                    "cpu": number_or_none(metric.get("cpu_percent")),
                    "memory": number_or_none(metric.get("memory_percent")),
                    "disk": number_or_none(metric.get("disk_percent")),
                }
            )
            server_cards[-1]["cpu_label"] = percent_label(server_cards[-1]["cpu"])
            server_cards[-1]["memory_label"] = percent_label(server_cards[-1]["memory"])
            server_cards[-1]["disk_label"] = percent_label(server_cards[-1]["disk"])

        site_cards = []
        site_status_counts = {"all": len(satellites), "critical": 0, "warning": 0, "ok": 0, "offline": 0}
        now = timezone.now()
        for satellite in satellites:
            minutes_since_report = None
            if satellite.last_report_at:
                minutes_since_report = int((now - satellite.last_report_at).total_seconds() / 60)
            satellite_servers = [server for server in active_servers if server.satellite_id == satellite.id]
            satellite_server_cards = [
                item for item in server_cards if item["server"].satellite_id == satellite.id
            ]
            critical_server_count = sum(
                1 for item in satellite_server_cards if item["priority"] == "critical"
            )
            warning_server_count = sum(
                1 for item in satellite_server_cards if item["priority"] == "warning"
            )
            normal_server_count = sum(
                1 for item in satellite_server_cards if item["priority"] == "normal"
            )
            alerted_server_count = critical_server_count + warning_server_count
            alert_status = "critical" if critical_server_count else "warning" if warning_server_count else "ok"
            satellite_online_servers = sum(1 for server in satellite_servers if server.is_active)
            disk_risks = [risk for risk in (server_disk_risk(server) for server in satellite_servers) if risk]
            worst_disk = max(disk_risks, key=lambda item: item["percent"]) if disk_risks else None
            disk_status = disk_status_for(worst_disk)
            is_stale = minutes_since_report is None or minutes_since_report > 15
            operational_status = "offline" if is_stale or satellite.status == Satellite.STATUS_OFFLINE else satellite.status
            if operational_status != "offline":
                if satellite.status == Satellite.STATUS_CRITICAL or disk_status == "critical":
                    operational_status = Satellite.STATUS_CRITICAL
                elif satellite.status == Satellite.STATUS_WARNING or disk_status == "warning":
                    operational_status = Satellite.STATUS_WARNING
            status_labels = {
                "ok": "Normal",
                "warning": "Advertencia",
                "critical": "Critico",
                "offline": "Sin reporte",
            }
            site_cards.append(
                {
                    "satellite": satellite,
                    "minutes_since_report": minutes_since_report,
                    "is_stale": is_stale,
                    "operational_status": operational_status,
                    "status_label": status_labels.get(operational_status, "Normal"),
                    "server_count": len(satellite_servers),
                    "online_count": satellite_online_servers,
                    "alerted_server_count": alerted_server_count,
                    "critical_server_count": critical_server_count,
                    "warning_server_count": warning_server_count,
                    "normal_server_count": normal_server_count,
                    "alert_status": alert_status,
                    "worst_disk": worst_disk,
                    "disk_status": disk_status,
                    "disk_warning_count": sum(1 for risk in disk_risks if risk["percent"] >= 80),
                    "disk_critical_count": sum(1 for risk in disk_risks if risk["percent"] >= 90),
                }
            )
            if operational_status == "offline":
                site_status_counts["offline"] += 1
            elif operational_status == Satellite.STATUS_CRITICAL:
                site_status_counts["critical"] += 1
            elif operational_status == Satellite.STATUS_WARNING:
                site_status_counts["warning"] += 1
            else:
                site_status_counts["ok"] += 1

        site_cards = sorted(
            site_cards,
            key=lambda item: (
                {"critical": 0, "offline": 1, "warning": 2, "ok": 3}.get(
                    item["operational_status"],
                    4,
                ),
                item["satellite"].name.lower(),
            ),
        )

        health_percent = 100
        if satellites:
            healthy = site_status_counts["ok"]
            health_percent = round((healthy / len(satellites)) * 100)

        disk_risk_sites = sum(
            1 for item in site_cards if item["disk_status"] in {"critical", "warning"}
        )
        stale_sites = site_status_counts["offline"]
        critical_total = priority_counts.get("critical", 0) + priority_counts.get("critica", 0)
        warning_total = priority_counts.get("warning", 0) + priority_counts.get("advertencia", 0)
        avg_cpu = average_metric([item["cpu"] for item in server_cards])
        avg_memory = average_metric([item["memory"] for item in server_cards])
        avg_disk = average_metric([item["disk"] for item in server_cards])
        online_servers = sum(1 for server in active_servers if server.is_active)
        critical_servers = sum(1 for item in server_cards if item["priority"] == "critical")
        warning_servers = sum(1 for item in server_cards if item["priority"] == "warning")

        context.update(
            {
                "active_menu": "hub",
                "satellites": satellites,
                "site_cards": site_cards,
                "site_status_counts": site_status_counts,
                "server_cards": sorted(
                    server_cards,
                    key=lambda item: {"critical": 0, "warning": 1, "normal": 2}[item["priority"]],
                )[:12],
                "summary": {
                    "satellites": len(satellites),
                    "servers": total_servers,
                    "servers_online": online_servers,
                    "unresolved_alerts": unresolved_alerts.count(),
                    "critical": priority_counts.get("critical", 0),
                    "critica": priority_counts.get("critica", 0),
                    "warning": priority_counts.get("warning", 0),
                    "advertencia": priority_counts.get("advertencia", 0),
                    "critical_total": critical_total,
                    "warning_total": warning_total,
                    "critical_servers": critical_servers,
                    "warning_servers": warning_servers,
                    "health_percent": health_percent,
                    "stale_sites": stale_sites,
                    "disk_risk_sites": disk_risk_sites,
                    "avg_cpu": avg_cpu,
                    "avg_memory": avg_memory,
                    "avg_disk": avg_disk,
                    "avg_cpu_label": percent_label(avg_cpu),
                    "avg_memory_label": percent_label(avg_memory),
                    "avg_disk_label": percent_label(avg_disk),
                },
                "now": timezone.now(),
            }
        )
        context.update(sidebar_context())
        return context


class HubSiteDetailView(HubAccessMixin, TemplateView):
    template_name = "hub/site_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        satellite = get_object_or_404(Satellite, pk=self.kwargs["pk"])
        servers = list(
            SatelliteServerSnapshot.objects.filter(satellite=satellite, is_active=True).order_by("name", "hostname")
        )
        unresolved_alerts = list(
            SatelliteAlert.objects.filter(satellite=satellite, is_resolved=False).order_by(
                "priority", "-source_created_at"
            )
        )
        reports = SatelliteReport.objects.filter(satellite=satellite).order_by("-received_at")[:8]
        critical_terms = {"critical", "critica", "critico"}
        warning_terms = {"warning", "advertencia"}
        alert_lookup = {}
        for alert in unresolved_alerts:
            alert_lookup.setdefault(alert.server_hostname, []).append(alert)

        server_cards = []
        disk_risks = []
        for server in servers:
            metric = server.latest_metric if isinstance(server.latest_metric, dict) else {}
            server_alerts = alert_lookup.get(server.hostname, [])
            priority = "normal"
            if any((alert.priority or "").lower() in critical_terms for alert in server_alerts):
                priority = "critical"
            elif server_alerts:
                priority = "warning"
            disk_risk = server_disk_risk(server)
            disk_status = disk_status_for(disk_risk)
            if disk_status == "critical":
                priority = "critical"
            elif disk_status == "warning" and priority == "normal":
                priority = "warning"
            if disk_risk:
                disk_risks.append(disk_risk)
            cpu = number_or_none(metric.get("cpu_percent"))
            memory = number_or_none(metric.get("memory_percent"))
            disk = number_or_none(metric.get("disk_percent"))
            server_cards.append(
                {
                    "server": server,
                    "alerts": server_alerts,
                    "priority": priority,
                    "cpu_label": percent_label(cpu),
                    "memory_label": percent_label(memory),
                    "disk_label": percent_label(disk),
                    "disk_risk": disk_risk,
                    "disk_status": disk_status,
                }
            )

        now = timezone.now()
        minutes_since_report = None
        if satellite.last_report_at:
            minutes_since_report = int((now - satellite.last_report_at).total_seconds() / 60)
        worst_disk = max(disk_risks, key=lambda item: item["percent"]) if disk_risks else None
        context.update(
            {
                "active_menu": "hub",
                "satellite": satellite,
                "server_cards": sorted(
                    server_cards,
                    key=lambda item: {"critical": 0, "warning": 1, "normal": 2}[item["priority"]],
                ),
                "alerts": unresolved_alerts,
                "recent_reports": reports,
                "minutes_since_report": minutes_since_report,
                "worst_disk": worst_disk,
                "disk_status": disk_status_for(worst_disk),
                "servers_count": len(servers),
                "servers_online": sum(1 for server in servers if server.is_active),
                "critical_count": sum(1 for item in server_cards if item["priority"] == "critical"),
                "warning_count": sum(1 for item in server_cards if item["priority"] == "warning"),
            }
        )
        context.update(sidebar_context())
        return context
