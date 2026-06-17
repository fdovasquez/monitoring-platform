import smtplib
from email.utils import formataddr

from django.core.mail import EmailMessage
from django.core.mail.backends.smtp import EmailBackend
from django.utils import timezone

from .models import AlertEmailLog, AlertRule, SmtpSettings


def smtp_backend(settings):
    return EmailBackend(
        host=settings.host,
        port=settings.port,
        username=settings.username if settings.require_auth else None,
        password=settings.get_password() if settings.require_auth else None,
        use_tls=settings.security == SmtpSettings.SECURITY_TLS,
        use_ssl=settings.security == SmtpSettings.SECURITY_SSL,
        timeout=settings.timeout_seconds,
        fail_silently=False,
    )


def sender(settings):
    if settings.from_name:
        return formataddr((settings.from_name, settings.from_email))
    return settings.from_email


def test_smtp_connection(settings):
    if not settings.is_configured:
        raise ValueError("La configuracion SMTP esta incompleta.")
    backend = smtp_backend(settings)
    connection = backend.open()
    if connection:
        backend.close()
    return True


def send_test_email(settings, recipient):
    subject = "Correo de prueba - Plataforma de monitoreo"
    body = "La configuracion SMTP de la plataforma fue validada correctamente."
    return send_email(settings, [recipient], subject, body, "smtp_test", AlertRule.PRIORITY_INFO)


def send_email(settings, recipients, subject, body, alert_type, severity, server=None, service_name=""):
    recipients = [email for email in recipients if email]
    if not settings.is_configured:
        raise ValueError("La configuracion SMTP esta incompleta.")
    try:
        message = EmailMessage(
            subject=subject,
            body=body,
            from_email=sender(settings),
            to=recipients,
            connection=smtp_backend(settings),
        )
        message.send()
        AlertEmailLog.objects.create(
            status=AlertEmailLog.STATUS_SENT,
            alert_type=alert_type,
            severity=severity,
            server=server,
            service_name=service_name,
            recipients=", ".join(recipients),
            subject=subject,
            message=body,
        )
        return True
    except (smtplib.SMTPException, OSError, ValueError) as exc:
        AlertEmailLog.objects.create(
            status=AlertEmailLog.STATUS_ERROR,
            alert_type=alert_type,
            severity=severity,
            server=server,
            service_name=service_name,
            recipients=", ".join(recipients),
            subject=subject,
            message=body,
            error_message=str(exc),
        )
        raise


def value_for_rule(sample, rule):
    if rule.event_type == AlertRule.EVENT_CPU:
        return sample.cpu_percent
    if rule.event_type == AlertRule.EVENT_MEMORY:
        return sample.memory_percent
    if rule.event_type == AlertRule.EVENT_DISK:
        return sample.disk_percent
    if rule.event_type == AlertRule.EVENT_FREE_SPACE and sample.disk_percent is not None:
        return 100 - sample.disk_percent
    return None


def threshold_triggered(rule, value):
    if value is None:
        return False
    if rule.event_type == AlertRule.EVENT_FREE_SPACE:
        return value < rule.threshold
    return value > rule.threshold


def evaluate_metric_sample(sample):
    settings = SmtpSettings.load()
    rules = AlertRule.objects.filter(is_active=True, event_type__in=[
        AlertRule.EVENT_CPU,
        AlertRule.EVENT_MEMORY,
        AlertRule.EVENT_DISK,
        AlertRule.EVENT_FREE_SPACE,
    ])
    for rule in rules:
        value = value_for_rule(sample, rule)
        if not threshold_triggered(rule, value) or not rule.can_notify():
            continue
        recipients = rule.recipient_list()
        if not recipients:
            continue
        subject = f"[{rule.get_priority_display()}] {rule.name} - {sample.server.hostname}"
        body = (
            f"Servidor: {sample.server.hostname}\n"
            f"Evento: {rule.get_event_type_display()}\n"
            f"Valor actual: {value:.2f}%\n"
            f"Umbral configurado: {rule.threshold:.2f}%\n"
            f"Fecha: {timezone.localtime(sample.timestamp).strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        try:
            send_email(settings, recipients, subject, body, rule.event_type, rule.priority, sample.server, rule.service_name)
            rule.last_notified_at = timezone.now()
            rule.save(update_fields=["last_notified_at", "updated_at"])
        except Exception:
            pass
