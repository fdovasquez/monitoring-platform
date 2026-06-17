from django.urls import path

from .views import AgentInstallWizardView, DeviceDetailView, DeviceListView, UserCreateView, UserDeleteView, UserEditView, UserListView


urlpatterns = [
    path("devices/", DeviceListView.as_view(), name="device-list"),
    path("devices/<int:pk>/", DeviceDetailView.as_view(), name="device-detail"),
    path("agents/new/", AgentInstallWizardView.as_view(), name="agent-install"),
    path("users/", UserListView.as_view(), name="user-list"),
    path("users/new/", UserCreateView.as_view(), name="user-create"),
    path("users/<int:pk>/edit/", UserEditView.as_view(), name="user-edit"),
    path("users/<int:pk>/delete/", UserDeleteView.as_view(), name="user-delete"),
]
