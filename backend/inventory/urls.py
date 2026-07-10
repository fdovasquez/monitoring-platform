from django.urls import path
from django.core.exceptions import PermissionDenied

from .auth_views import CorporateLoginView, CorporateLogoutView, LoginCodeVerifyView
from .views import (
    AccountPasswordChangeDoneView,
    AccountPasswordChangeView,
    AgentInstallWizardView,
    DeviceConsoleView,
    DeviceDeleteView,
    DeviceEditView,
    DeviceListView,
    MachineCredentialCreateView,
    MachineCredentialDeleteView,
    ProfileView,
    UserCreateView,
    UserDeleteView,
    UserEditView,
    UserListView,
    agent_download,
    linux_install_script,
    oracle_db_install_script,
    rhapsody_install_script,
    windows_install_script,
)
from .monitor_assignment_views import DeviceDetailWithMonitorsView
from .portal_views import (
    CMDBView,
    ComplianceReportDownloadView,
    ComplianceView,
    ExecutiveDashboardView,
    IncidentCenterView,
    ReportsView,
)
from .runtime_views import DeviceRuntimeView
from .site_views import SiteSettingsView


def can_manage_devices(user):
    return user.is_authenticated and (
        user.is_superuser or user.groups.filter(name__in=["Administrador", "Editor"]).exists()
    )


def device_manager_required(view_func):
    def wrapped(request, *args, **kwargs):
        if can_manage_devices(request.user):
            return view_func(request, *args, **kwargs)
        raise PermissionDenied

    return wrapped


urlpatterns = [
    path("login/", CorporateLoginView.as_view(), name="login"),
    path("login/verify/", LoginCodeVerifyView.as_view(), name="login-verify"),
    path("dashboard/", ExecutiveDashboardView.as_view(), name="executive-dashboard"),
    path("cmdb/", CMDBView.as_view(), name="cmdb"),
    path("incidents/", IncidentCenterView.as_view(), name="incidents"),
    path("compliance/", ComplianceView.as_view(), name="compliance"),
    path("compliance/download/", ComplianceReportDownloadView.as_view(), name="compliance-download"),
    path("reports/", ReportsView.as_view(), name="reports"),
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/<int:pk>/", DeviceDetailWithMonitorsView.as_view(), name="device-detail"),
    path("devices/<int:pk>/edit/", DeviceEditView.as_view(), name="device-edit"),
    path("devices/<int:pk>/runtime/", DeviceRuntimeView.as_view(), name="device-runtime"),
    path("devices/<int:pk>/runtime/<str:section>/", DeviceRuntimeView.as_view(), name="device-runtime-section"),
    path("devices/<int:pk>/delete/", DeviceDeleteView.as_view(), name="device-delete"),
    path("devices/<int:pk>/console/", DeviceConsoleView.as_view(), name="device-console"),
    path("devices/<int:pk>/credentials/new/", MachineCredentialCreateView.as_view(), name="machine-credential-create"),
    path(
        "devices/<int:pk>/credentials/<int:credential_id>/delete/",
        MachineCredentialDeleteView.as_view(),
        name="machine-credential-delete",
    ),
    path("agents/new/", device_manager_required(AgentInstallWizardView.as_view()), name="agent-install"),
    path("agents/install/linux.sh", linux_install_script, name="linux-agent-install-script"),
    path("agents/install/rhapsody-linux.sh", rhapsody_install_script, name="rhapsody-agent-install-script"),
    path("agents/install/oracle-db-linux.sh", oracle_db_install_script, name="oracle-db-agent-install-script"),
    path("agents/install/windows.ps1", windows_install_script, name="windows-agent-install-script"),
    path("agents/download/<str:platform>/<str:filename>", agent_download, name="agent-download"),
    path("users/", UserListView.as_view(), name="user-list"),
    path("users/new/", UserCreateView.as_view(), name="user-create"),
    path("users/<int:pk>/edit/", UserEditView.as_view(), name="user-edit"),
    path("users/<int:pk>/delete/", UserDeleteView.as_view(), name="user-delete"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("profile/password/", AccountPasswordChangeView.as_view(), name="password-change"),
    path("profile/password/done/", AccountPasswordChangeDoneView.as_view(), name="password-change-done"),
    path("settings/", SiteSettingsView.as_view(), name="site-settings"),
    path("logout/", CorporateLogoutView.as_view(), name="logout"),
]
