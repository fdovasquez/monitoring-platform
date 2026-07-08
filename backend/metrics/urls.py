from django.urls import path

from .views import MetricIngestView, RhapsodyIngestView


urlpatterns = [
    path("ingest/", MetricIngestView.as_view(), name="metric-ingest"),
    path("rhapsody/ingest/", RhapsodyIngestView.as_view(), name="rhapsody-ingest"),
]
