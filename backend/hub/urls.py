from django.urls import path

from .views import HubDashboardView, SatelliteReportIngestView


urlpatterns = [
    path("report", SatelliteReportIngestView.as_view(), name="satellite-report-ingest"),
    path("report/", SatelliteReportIngestView.as_view(), name="satellite-report-ingest-slash"),
]


app_urlpatterns = [
    path("", HubDashboardView.as_view(), name="hub-dashboard"),
]
