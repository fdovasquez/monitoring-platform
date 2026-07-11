from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count
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
        total_servers = len(servers)
        unresolved_alerts = SatelliteAlert.objects.filter(is_resolved=False).select_related("satellite")
        reports = SatelliteReport.objects.select_related("satellite").order_by("-received_at")[:10]
        priority_counts = {
            item["priority"] or "sin_prioridad": item["total"]
            for item in unresolved_alerts.values("priority").annotate(total=Count("id"))
        }
        critical_terms = {"critical", "critica", "critico"}
        warning_terms = {"warning", "advertencia"}
        critical_alerts = [
            alert for alert in unresolved_alerts if (alert.priority or "").lower() in critical_terms
        ]
        warning_alerts = [
            alert for alert in unresolved_alerts if (alert.priority or "").lower() in warning_terms
        ]
        alert_lookup = {}
        for alert in unresolved_alerts:
            alert_lookup.setdefault((alert.satellite_id, alert.server_hostname), []).append(alert)

        server_cards = []
        for server in servers:
            metric = server.latest_metric if isinstance(server.latest_metric, dict) else {}
            server_alerts = alert_lookup.get((server.satellite_id, server.hostname), [])
            priority = "normal"
            if any((alert.priority or "").lower() in critical_terms for alert in server_alerts):
                priority = "critical"
            elif server_alerts:
                priority = "warning"
            server_cards.append(
                {
                    "server": server,
                    "metric": metric,
                    "alerts": server_alerts,
                    "priority": priority,
                    "cpu": metric.get("cpu_percent"),
                    "memory": metric.get("memory_percent"),
                    "disk": metric.get("disk_percent"),
                }
            )

        site_cards = []
        now = timezone.now()
        for satellite in satellites:
            minutes_since_report = None
            if satellite.last_report_at:
                minutes_since_report = int((now - satellite.last_report_at).total_seconds() / 60)
            satellite_servers = [server for server in servers if server.satellite_id == satellite.id]
            disk_risks = [risk for risk in (server_disk_risk(server) for server in satellite_servers) if risk]
            worst_disk = max(disk_risks, key=lambda item: item["percent"]) if disk_risks else None
            site_cards.append(
                {
                    "satellite": satellite,
                    "minutes_since_report": minutes_since_report,
                    "is_stale": minutes_since_report is None or minutes_since_report > 15,
                    "server_count": len(satellite_servers),
                    "worst_disk": worst_disk,
                    "disk_warning_count": sum(1 for risk in disk_risks if risk["percent"] >= 80),
                    "disk_critical_count": sum(1 for risk in disk_risks if risk["percent"] >= 90),
                }
            )

        health_percent = 100
        if satellites:
            healthy = sum(1 for satellite in satellites if satellite.status == Satellite.STATUS_OK)
            health_percent = round((healthy / len(satellites)) * 100)

        context.update(
            {
                "active_menu": "hub",
                "satellites": satellites,
                "site_cards": site_cards,
                "server_cards": sorted(
                    server_cards,
                    key=lambda item: {"critical": 0, "warning": 1, "normal": 2}[item["priority"]],
                )[:12],
                "critical_alerts": critical_alerts[:8],
                "warning_alerts": warning_alerts[:8],
                "recent_reports": reports,
                "summary": {
                    "satellites": len(satellites),
                    "servers": total_servers,
                    "unresolved_alerts": unresolved_alerts.count(),
                    "critical": priority_counts.get("critical", 0),
                    "critica": priority_counts.get("critica", 0),
                    "warning": priority_counts.get("warning", 0),
                    "advertencia": priority_counts.get("advertencia", 0),
                    "health_percent": health_percent,
                },
                "now": timezone.now(),
            }
        )
        context.update(sidebar_context())
        return context
