from django.conf import settings
from django.utils import timezone


DEFAULT_ONLINE_WINDOW_SECONDS = 180


def online_window_seconds():
    value = getattr(settings, "AGENT_ONLINE_WINDOW_SECONDS", DEFAULT_ONLINE_WINDOW_SECONDS)
    try:
        return max(60, int(value))
    except (TypeError, ValueError):
        return DEFAULT_ONLINE_WINDOW_SECONDS


def is_recent_report(last_seen, now=None, window_seconds=None):
    if not last_seen:
        return False
    now = now or timezone.now()
    window_seconds = online_window_seconds() if window_seconds is None else window_seconds
    return last_seen >= now - timezone.timedelta(seconds=window_seconds)


def relative_report_label(last_seen, now=None):
    if not last_seen:
        return "Sin reportes"

    now = now or timezone.now()
    seconds = int((now - last_seen).total_seconds())
    if seconds < 60:
        return "hace menos de 1 minuto"

    minutes = seconds // 60
    if minutes == 1:
        return "hace 1 minuto"
    if minutes < 60:
        return f"hace {minutes} minutos"

    hours = minutes // 60
    if hours == 1:
        return "hace 1 hora"
    if hours < 24:
        return f"hace {hours} horas"

    days = hours // 24
    if days == 1:
        return "hace 1 dia"
    return f"hace {days} dias"
