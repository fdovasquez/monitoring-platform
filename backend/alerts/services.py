import smtplib
from email.utils import formataddr

from django.conf import settings as django_settings
from django.core.mail.backends.smtp import EmailBackend
from django.core.mail import EmailMultiAlternatives
from django.utils.html import escape
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
    return send_email(
        settings,
        [recipient],
        subject,
        body,
        "smtp_test",
        AlertRule.PRIORITY_INFO,
        title="Configuracion SMTP validada",
        details=[("Estado", "La configuracion SMTP de la plataforma fue validada correctamente.")],
    )


def severity_style(severity):
    styles = {
        AlertRule.PRIORITY_CRITICAL: ("ALERTA CRITICA", "#e11d2e"),
        AlertRule.PRIORITY_WARNING: ("ALERTA DE ADVERTENCIA", "#d97706"),
        AlertRule.PRIORITY_INFO: ("ALERTA INFORMATIVA", "#2563eb"),
    }
    return styles.get(severity, styles[AlertRule.PRIORITY_INFO])


def monitoring_url(server=None):
    base_url = getattr(django_settings, "MONITORING_PUBLIC_URL", "").rstrip("/")
    if not base_url:
        return ""
    if server:
        return f"{base_url}/app/devices/{server.id}/"
    return base_url


def alert_html(settings, title, severity, details, server=None):
    severity_label, severity_color = severity_style(severity)
    rows = "".join(
        (
            "<tr>"
            f"<td style='padding:12px 14px;border-bottom:1px solid #e5e7eb;color:#64748b;font-size:14px;width:40%;'>{escape(str(label))}</td>"
            f"<td style='padding:12px 14px;border-bottom:1px solid #e5e7eb;color:#111827;font-size:14px;'>{escape(str(value))}</td>"
            "</tr>"
        )
        for label, value in details
    )
    action_url = monitoring_url(server)
    action = (
        f"<a href='{escape(action_url)}' style='display:inline-block;background:#111827;color:#ffffff;text-decoration:none;"
        "padding:12px 18px;border-radius:6px;font-size:14px;'>Abrir detalle del servidor</a>"
        if action_url
        else ""
    )
    product_name = escape(settings.from_name or "Plataforma de monitoreo")
    return f"""<!doctype html>
<html lang="es">
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif;color:#111827;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:20px 10px;background:#f3f4f6;">
    <tr><td align="center">
      <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;">
        <tr><td style="padding:12px 18px;background:#fef3c7;border-left:4px solid #f59e0b;color:#92400e;font-size:12px;line-height:1.45;">
          Este correo fue generado por la plataforma de monitoreo. Verifica el remitente antes de abrir enlaces.
        </td></tr>
        <tr><td style="padding:25px 24px;background:#111827;color:#ffffff;">
          <span style="font-size:20px;font-weight:600;">Monitoreo de Servidores</span>
          <span style="float:right;color:#bfdbfe;font-size:12px;">{product_name}</span>
        </td></tr>
        <tr><td style="padding:18px 24px;background:{severity_color};color:#ffffff;">
          <div style="font-size:11px;font-weight:600;letter-spacing:.08em;">{severity_label}</div>
          <div style="margin-top:7px;font-size:22px;font-weight:600;line-height:1.2;">{escape(title)}</div>
        </td></tr>
        <tr><td style="padding:24px;">
          <p style="margin:0 0 18px;color:#334155;font-size:14px;line-height:1.55;">
            Se ha detectado un evento de monitoreo. Revisa el detalle para tomar las acciones correspondientes.
          </p>
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #e5e7eb;border-radius:7px;border-collapse:separate;border-spacing:0;overflow:hidden;">
            {rows}
          </table>
          <div style="margin-top:24px;">{action}</div>
          <p style="margin:24px 0 0;color:#64748b;font-size:12px;line-height:1.5;">
            Esta notificacion se genera automaticamente. Las siguientes alertas respetaran la frecuencia configurada en la regla.
          </p>
        </td></tr>
        <tr><td style="padding:15px 24px;background:#f8fafc;border-top:1px solid #e5e7eb;color:#94a3b8;font-size:11px;text-align:center;">
          {product_name} | Sistema de monitoreo | No responder a este correo
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def send_email(
    settings,
    recipients,
    subject,
    body,
    alert_type,
    severity,
    server=None,
    service_name="",
    title=None,
    details=None,
):
    recipients = [email for email in recipients if email]
    if not settings.is_configured:
        raise ValueError("La configuracion SMTP esta incompleta.")
    try:
        message = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=sender(settings),
            to=recipients,
            connection=smtp_backend(settings),
        )
        message.attach_alternative(
            alert_html(settings, title or subject, severity, details or [("Detalle", body)], server),
            "text/html",
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
            send_email(
                settings,
                recipients,
                subject,
                body,
                rule.event_type,
                rule.priority,
                sample.server,
                rule.service_name,
                title=rule.name,
                details=[
                    ("Servidor", sample.server.hostname),
                    ("Evento", rule.get_event_type_display()),
                    ("Valor actual", f"{value:.2f}%"),
                    ("Umbral configurado", f"{rule.threshold:.2f}%"),
                    ("Fecha", timezone.localtime(sample.timestamp).strftime("%Y-%m-%d %H:%M:%S")),
                ],
            )
            rule.last_notified_at = timezone.now()
            rule.save(update_fields=["last_notified_at", "updated_at"])
        except Exception:
            pass

