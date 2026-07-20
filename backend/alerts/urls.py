from django.shortcuts import redirect
from django.urls import path

from .views import AlertHistoryExportView, AlertSettingsView


def alert_tab_redirect(tab):
    return lambda request: redirect(f"/app/alerts/?tab={tab}")


urlpatterns = [
    path("", AlertSettingsView.as_view(), name="alert-settings"),
    path("history/", alert_tab_redirect("history"), name="alert-history"),
    path("monitors/", alert_tab_redirect("monitors"), name="alert-monitors"),
    path("server-monitors/", alert_tab_redirect("server_monitors"), name="alert-server-monitors"),
    path("recipients/", alert_tab_redirect("recipients"), name="alert-recipients"),
    path("export/", AlertHistoryExportView.as_view(), name="alert-history-export"),
]
