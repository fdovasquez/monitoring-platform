from django.urls import path

from .views import (
    AgentInstallWizardView,
    DeviceConsoleView,
    DeviceDetailView,
    DeviceListView,
    LogoutView,
    MachineCredentialCreateView,
    MachineCredentialDeleteView,
    ProfileView,
    UserCreateView,
    UserDeleteView,
    UserEditView,
    UserListView,
)


urlpatterns = [
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/<int:pk>/", DeviceDetailView.as_view(), name="device-detail"),
    path("devices/<int:pk>/console/", DeviceConsoleView.as_view(), name="device-console"),
    path("devices/<int:pk>/credentials/new/", MachineCredentialCreateView.as_view(), name="machine-credential-create"),
    path(
        "devices/<int:pk>/credentials/<int:credential_id>/delete/",
        MachineCredentialDeleteView.as_view(),
        name="machine-credential-delete",
    ),
    path("agents/new/", AgentInstallWizardView.as_view(), name="agent-install"),
    path("users/", UserListView.as_view(), name="user-list"),
    path("users/new/", UserCreateView.as_view(), name="user-create"),
    path("users/<int:pk>/edit/", UserEditView.as_view(), name="user-edit"),
    path("users/<int:pk>/delete/", UserDeleteView.as_view(), name="user-delete"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
