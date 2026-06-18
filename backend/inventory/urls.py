from django.urls import path
from django.contrib.auth.decorators import user_passes_test

from .auth_views import CorporateLoginView, CorporateLogoutView, LoginCodeVerifyView
from .views import (
    AccountPasswordChangeDoneView,
    AccountPasswordChangeView,
    AgentInstallWizardView,
    DeviceConsoleView,
    DeviceDetailView,
    DeviceListView,
    MachineCredentialCreateView,
    MachineCredentialDeleteView,
    ProfileView,
    UserCreateView,
    UserDeleteView,
    UserEditView,
    UserListView,
)
from .site_views import SiteSettingsView


def can_manage_devices(user):
    return user.is_authenticated and (
        user.is_superuser or user.groups.filter(name__in=["Administrador", "Editor"]).exists()
    )


device_manager_required = user_passes_test(can_manage_devices)


urlpatterns = [
    path("login/", CorporateLoginView.as_view(), name="login"),
    path("login/verify/", LoginCodeVerifyView.as_view(), name="login-verify"),
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/<int:pk>/", DeviceDetailView.as_view(), name="device-detail"),
    path("devices/<int:pk>/console/", DeviceConsoleView.as_view(), name="device-console"),
    path("devices/<int:pk>/credentials/new/", MachineCredentialCreateView.as_view(), name="machine-credential-create"),
    path(
        "devices/<int:pk>/credentials/<int:credential_id>/delete/",
        MachineCredentialDeleteView.as_view(),
        name="machine-credential-delete",
    ),
    path("agents/new/", device_manager_required(AgentInstallWizardView.as_view()), name="agent-install"),
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
