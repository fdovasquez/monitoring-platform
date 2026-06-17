from django.urls import path

from .views import AgentInstallWizardView, DeviceListView


urlpatterns = [
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("agents/new/", AgentInstallWizardView.as_view(), name="agent-install"),
]
