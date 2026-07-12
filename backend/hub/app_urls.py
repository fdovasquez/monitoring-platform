from django.urls import path

from .views import HubDashboardView, HubSiteDetailView


urlpatterns = [
    path("", HubDashboardView.as_view(), name="hub-dashboard"),
    path("sites/<int:pk>/", HubSiteDetailView.as_view(), name="hub-site-detail"),
]
