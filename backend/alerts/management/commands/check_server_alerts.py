from django.core.management.base import BaseCommand
from django.utils import timezone

from alerts.models import AlertEvent, AlertRule, ServerMonitorAssignment, SmtpSettings
from alerts.services import send_email
from inventory.models import Server


class Command(BaseCommand):
    help = "Evalua alertas de plataforma como servidor fuera de linea y recuperacion."

    def handle(self, *args, **options):
        settings = SmtpSettings.load()
        rules = AlertRule.objects.filter(is_active=True, event_type=AlertRule.EVENT_OFFLINE)
        total_alerts = 0
        total_recovered = 0

        for rule in rules:
            threshold_minutes = max(1, int(rule.threshold or 1))
            cutoff = timezone.now() - timezone.timedelta(minutes=threshold_minutes)
            assigned_server_ids = ServerMonitorAssignment.objects.filter(
                rule=rule,
                is_enabled=True,
            ).values_list("server_id", flat=True)
            for server in Server.objects.filter(is_active=True, id__in=assigned_server_ids):
                is_offline = not server.last_seen or server.last_seen < cutoff
                if is_offline:
                    if self.open_offline_event(rule, server, threshold_minutes, settings):
                        total_alerts += 1
                else:
                    if self.resolve_offline_event(rule, server, settings):
                        total_recovered += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Revision finalizada. Alertas offline: {total_alerts}. Recuperaciones: {total_recovered}."
            )
        )

    def open_offline_event(self, rule, server, threshold_minutes, settings):
        event = AlertEvent.objects.filter(rule=rule, server=server, is_resolved=False).first()
        if event and not rule.can_notify():
            return False

        minutes_without_report = self.minutes_without_report(server)
        message = (
            f"Servidor sin reporte por {minutes_without_report:.1f} minutos. "
            f"Umbral configurado: {threshold_minutes} minutos."
        )
        if not event:
            AlertEvent.objects.create(
                rule=rule,
                server=server,
                value=minutes_without_report,
                message=message,
            )

        recipients = rule.recipient_list()
        if not recipients:
            return False

        subject = f"[{rule.get_priority_display()}] {rule.name} - {server.hostname}"
        body = (
            f"Servidor: {server.hostname}\n"
            f"Evento: {rule.get_event_type_display()}\n"
            f"Estado: Fuera de linea\n"
            f"Ultimo reporte: {timezone.localtime(server.last_seen).strftime('%Y-%m-%d %H:%M:%S') if server.last_seen else 'Sin reportes'}\n"
            f"Minutos sin reporte: {minutes_without_report:.1f}\n"
            f"Umbral configurado: {threshold_minutes} minutos\n"
        )
        try:
            send_email(
                settings,
                recipients,
                subject,
                body,
                rule.event_type,
                rule.priority,
                server,
                rule.service_name,
                title=rule.name,
                details=[
                    ("Servidor", server.hostname),
                    ("Evento", rule.get_event_type_display()),
                    ("Estado", "Fuera de linea"),
                    ("Ultimo reporte", timezone.localtime(server.last_seen).strftime("%Y-%m-%d %H:%M:%S") if server.last_seen else "Sin reportes"),
                    ("Minutos sin reporte", f"{minutes_without_report:.1f}"),
                    ("Umbral configurado", f"{threshold_minutes} minutos"),
                ],
            )
            rule.last_notified_at = timezone.now()
            rule.save(update_fields=["last_notified_at", "updated_at"])
            return True
        except Exception:
            return False

    def resolve_offline_event(self, rule, server, settings):
        events = AlertEvent.objects.filter(rule=rule, server=server, is_resolved=False)
        if not events.exists():
            return False

        resolved_at = timezone.now()
        events.update(is_resolved=True, resolved_at=resolved_at)

        recipients = rule.recipient_list()
        if not recipients:
            return True

        subject = f"[Recuperado] {server.hostname} vuelve a reportar"
        body = (
            f"Servidor: {server.hostname}\n"
            f"Evento: Recuperacion de monitoreo\n"
            f"Estado: En linea\n"
            f"Ultimo reporte: {timezone.localtime(server.last_seen).strftime('%Y-%m-%d %H:%M:%S') if server.last_seen else '-'}\n"
            f"Fecha recuperacion: {timezone.localtime(resolved_at).strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        try:
            send_email(
                settings,
                recipients,
                subject,
                body,
                "server_recovered",
                AlertRule.PRIORITY_INFO,
                server,
                rule.service_name,
                title="Servidor recuperado",
                details=[
                    ("Servidor", server.hostname),
                    ("Evento", "Recuperacion de monitoreo"),
                    ("Estado", "En linea"),
                    ("Fecha de recuperacion", timezone.localtime(resolved_at).strftime("%Y-%m-%d %H:%M:%S")),
                ],
            )
        except Exception:
            pass
        return True

    @staticmethod
    def minutes_without_report(server):
        if not server.last_seen:
            return 999999.0
        return max(0.0, (timezone.now() - server.last_seen).total_seconds() / 60)
