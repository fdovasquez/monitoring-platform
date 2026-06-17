from django.urls import path

from .views import AlertHistoryExportView, AlertSettingsView


urlpatterns = [
    path("", AlertSettingsView.as_view(), name="alert-settings"),
    path("export/", AlertHistoryExportView.as_view(), name="alert-history-export"),
]
