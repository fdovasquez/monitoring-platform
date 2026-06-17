from .models import SiteSettings


def site_settings(request):
    try:
        return {"site_settings": SiteSettings.load()}
    except Exception:
        return {"site_settings": None}
