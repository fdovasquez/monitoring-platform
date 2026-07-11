from django.urls import path

from .views import HubDashboardView


urlpatterns = [
    path("", HubDashboardView.as_view(), name="hub-dashboard"),
]
