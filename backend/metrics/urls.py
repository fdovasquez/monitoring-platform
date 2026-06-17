from django.urls import path

from .views import MetricIngestView


urlpatterns = [
    path("ingest/", MetricIngestView.as_view(), name="metric-ingest"),
]
