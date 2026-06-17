from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.views.generic import RedirectView


urlpatterns = [
    path("", RedirectView.as_view(pattern_name="device-list", permanent=False)),
    path("admin/", admin.site.urls),
    path("app/", include("inventory.urls")),
    path(
        "app/password/",
        auth_views.PasswordChangeView.as_view(
            template_name="inventory/password_change.html",
            success_url="/app/password/done/",
        ),
        name="password-change",
    ),
    path(
        "app/password/done/",
        auth_views.PasswordChangeDoneView.as_view(template_name="inventory/password_change_done.html"),
        name="password-change-done",
    ),
    path("api/v1/metrics/", include("metrics.urls")),
]
