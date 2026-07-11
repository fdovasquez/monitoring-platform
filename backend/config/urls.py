from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path
from django.shortcuts import redirect


def root_redirect(request):
    if settings.CENTRAL_PORTAL_ENABLED:
        return redirect("hub-dashboard")
    return redirect("executive-dashboard")


urlpatterns = [
    path("", root_redirect),
    path("admin/", admin.site.urls),
    path("app/", include("inventory.urls")),
    path("app/alerts/", include("alerts.urls")),
    path("app/hub/", include("hub.app_urls")),
    path("api/v1/metrics/", include("metrics.urls")),
    path("api/v1/satellites/", include("hub.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
