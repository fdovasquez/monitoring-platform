from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path
from django.views.generic import RedirectView


urlpatterns = [
    path("", RedirectView.as_view(pattern_name="executive-dashboard", permanent=False)),
    path("admin/", admin.site.urls),
    path("app/", include("inventory.urls")),
    path("app/alerts/", include("alerts.urls")),
    path("app/hub/", include("hub.app_urls")),
    path("api/v1/metrics/", include("metrics.urls")),
    path("api/v1/satellites/", include("hub.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
