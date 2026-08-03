import subprocess
from functools import lru_cache

from django.conf import settings as django_settings
from django.utils import timezone

from .models import SiteSettings


@lru_cache(maxsize=1)
def _app_version():
    configured_version = getattr(django_settings, "APP_VERSION", "")
    if configured_version:
        return configured_version
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=django_settings.BASE_DIR.parent,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.stdout.strip() or "dev"
    except Exception:
        return "dev"


def site_settings(request):
    user = getattr(request, "user", None)
    is_authenticated = bool(user and user.is_authenticated)
    is_admin = bool(is_authenticated and (user.is_superuser or user.groups.filter(name="Administrador").exists()))
    is_staff_admin = bool(is_authenticated and user.is_staff)
    is_editor = bool(is_authenticated and user.groups.filter(name="Editor").exists())
    is_client = bool(is_authenticated and user.groups.filter(name="Cliente").exists())
    is_client_only = bool(is_client and not is_admin and not is_editor)
    user_theme = "light"
    if is_authenticated:
        try:
            user_theme = user.profile.theme or "light"
        except Exception:
            user_theme = "light"

    try:
        settings = SiteSettings.load()
    except Exception:
        settings = None

    return {
        "site_settings": settings,
        "can_manage_devices": is_admin or is_editor,
        "can_manage_users": is_admin,
        "can_manage_site_settings": is_admin,
        "can_manage_alerts": is_admin or is_staff_admin,
        "can_view_alert_history": is_authenticated and not is_client_only,
        "user_theme": user_theme,
        "central_portal_enabled": django_settings.CENTRAL_PORTAL_ENABLED,
        "is_viewer_role": bool(
            is_authenticated
            and user.groups.filter(name="Visualizador").exists()
            and not is_admin
            and not is_editor
            and not is_client_only
        ),
        "is_client_role": is_client_only,
        "app_version": _app_version(),
        "app_year": timezone.now().year,
    }
