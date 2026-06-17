from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView


urlpatterns = [
    path("", RedirectView.as_view(pattern_name="device-list", permanent=False)),
    path("admin/", admin.site.urls),
    path("app/", include("inventory.urls")),
    path("api/v1/metrics/", include("metrics.urls")),
]
