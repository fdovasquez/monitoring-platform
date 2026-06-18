from .models import SiteSettings


def site_settings(request):
    user = getattr(request, "user", None)
    is_authenticated = bool(user and user.is_authenticated)
    is_admin = bool(is_authenticated and (user.is_superuser or user.groups.filter(name="Administrador").exists()))
    is_editor = bool(is_authenticated and user.groups.filter(name="Editor").exists())

    try:
        settings = SiteSettings.load()
    except Exception:
        settings = None

    return {
        "site_settings": settings,
        "can_manage_devices": is_admin or is_editor,
        "can_manage_users": is_admin,
        "can_manage_site_settings": is_admin,
        "can_manage_alerts": is_admin,
        "is_viewer_role": bool(is_authenticated and user.groups.filter(name="Visualizador").exists() and not is_admin and not is_editor),
    }
