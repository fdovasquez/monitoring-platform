from django.urls import path

from .views import MetricIngestView, OracleIngestView, RhapsodyIngestView


urlpatterns = [
    path("ingest/", MetricIngestView.as_view(), name="metric-ingest"),
    path("rhapsody/ingest/", RhapsodyIngestView.as_view(), name="rhapsody-ingest"),
    path("oracle/ingest/", OracleIngestView.as_view(), name="oracle-ingest"),
]
