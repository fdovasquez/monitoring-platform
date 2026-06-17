from django.urls import path

from .views import AgentInstallWizardView, DeviceDetailView, DeviceListView, UserRoleAdminView


urlpatterns = [
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/<int:pk>/", DeviceDetailView.as_view(), name="device-detail"),
    path("agents/new/", AgentInstallWizardView.as_view(), name="agent-install"),
    path("users/roles/", UserRoleAdminView.as_view(), name="user-roles"),
]
