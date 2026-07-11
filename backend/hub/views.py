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
        return user_can_manage_devices(self.request.user)


class HubDashboardView(HubAccessMixin, TemplateView):
    template_name = "hub/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        satellites = list(Satellite.objects.all())
        total_servers = SatelliteServerSnapshot.objects.count()
        unresolved_alerts = SatelliteAlert.objects.filter(is_resolved=False)
        reports = SatelliteReport.objects.select_related("satellite").order_by("-received_at")[:10]
        priority_counts = {
            item["priority"] or "sin_prioridad": item["total"]
            for item in unresolved_alerts.values("priority").annotate(total=Count("id"))
        }
        context.update(
            {
                "active_menu": "hub",
                "satellites": satellites,
                "recent_reports": reports,
                "summary": {
                    "satellites": len(satellites),
                    "servers": total_servers,
                    "unresolved_alerts": unresolved_alerts.count(),
                    "critical": priority_counts.get("critical", 0),
                    "warning": priority_counts.get("warning", 0),
                },
                "now": timezone.now(),
            }
        )
        context.update(sidebar_context())
        return context
