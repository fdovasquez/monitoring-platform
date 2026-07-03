import csv

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import HttpResponse
from django.db.models import Q
from django.shortcuts import redirect
from django.utils import timezone
from django.views.generic import TemplateView

from inventory.models import Server
from inventory.monitor_assignment_views import DeviceDetailWithMonitorsView

from .forms import AlertHistoryFilterForm, AlertRuleForm, BulkRecipientsForm
from .models import AlertEmailLog, AlertRule, ServerMonitorAssignment


def user_can_manage_alerts(user):
    return user.is_superuser or user.groups.filter(name="Administrador").exists()


class AlertSettingsView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    template_name = "alerts/alert_settings.html"

    def test_func(self):
        return user_can_manage_alerts(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ensure_default_monitors()
        history_filter = AlertHistoryFilterForm(self.request.GET or None)
        logs = self.filtered_logs(history_filter)
        cutoff = timezone.now() - timezone.timedelta(days=30)
        edit_rule = kwargs.get("edit_rule")
        if edit_rule is None:
            edit_rule_id = self.request.GET.get("edit_rule")
            if edit_rule_id:
                edit_rule = AlertRule.objects.filter(id=edit_rule_id).first()
        show_create_rule = kwargs.get("show_create_rule")
        if show_create_rule is None:
            show_create_rule = self.request.GET.get("new_rule") == "1"
        rule_form = kwargs.get("rule_form")
        if rule_form is None:
            rule_form = AlertRuleForm(instance=edit_rule) if edit_rule else AlertRuleForm()
        servers = Server.objects.select_related("group").order_by("hostname")
        selected_server = self.selected_server(servers)
        monitor_assignments = (
            DeviceDetailWithMonitorsView.monitor_assignments(selected_server)
            if selected_server
            else None
        )
        AlertEmailLog.objects.filter(created_at__lt=cutoff).delete()
        context.update(
            {
                "active_tab": kwargs.get("active_tab") or self.request.GET.get("tab", "monitors"),
                "rule_form": rule_form,
                "bulk_recipients_form": kwargs.get("bulk_recipients_form") or BulkRecipientsForm(),
                "edit_rule": edit_rule,
                "show_create_rule": show_create_rule,
                "rules": self.filtered_rules(),
                "servers": servers,
                "selected_server": selected_server,
                "monitor_assignments": monitor_assignments,
                "history_filter": history_filter,
                "logs": logs[:200],
                "sent_count": AlertEmailLog.objects.filter(created_at__gte=cutoff, status=AlertEmailLog.STATUS_SENT).count(),
                "error_count": AlertEmailLog.objects.filter(created_at__gte=cutoff, status=AlertEmailLog.STATUS_ERROR).count(),
            }
        )
        return context

    def post(self, request):
        action = request.POST.get("action", "")

        if action in {"assign_monitor", "remove_monitor", "toggle_monitor"}:
            return self.update_server_monitor(request, action)

        if action in {"bulk_add_recipients", "bulk_remove_recipients"}:
            form = BulkRecipientsForm(request.POST)
            if form.is_valid():
                additions = form.cleaned_data["recipients"]
                updated = 0
                for rule in AlertRule.objects.all():
                    if action == "bulk_add_recipients":
                        merged = []
                        seen = set()
                        for address in [*rule.recipient_list(), *additions]:
                            key = address.lower()
                            if key not in seen:
                                seen.add(key)
                                merged.append(address)
                        recipients = ", ".join(merged)
                    else:
                        removals = {address.lower() for address in additions}
                        recipients = ", ".join(
                            address
                            for address in rule.recipient_list()
                            if address.lower() not in removals
                        )
                    if rule.recipients != recipients:
                        rule.recipients = recipients
                        rule.save(update_fields=["recipients", "updated_at"])
                        updated += 1
                verb = "agregados a" if action == "bulk_add_recipients" else "eliminados de"
                messages.success(request, f"Destinatarios {verb} {updated} alerta(s).")
                return redirect("/app/alerts/?tab=monitors")
            messages.error(request, "No se pudieron actualizar los destinatarios. Revisa los correos ingresados.")
            return self.render_to_response(
                self.get_context_data(bulk_recipients_form=form, active_tab="monitors")
            )

        if action == "create_rule":
            form = AlertRuleForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Alerta creada correctamente.")
                return redirect("/app/alerts/?tab=monitors")
            messages.error(request, "No se pudo crear la alerta. Revisa los campos.")
            return self.render_to_response(
                self.get_context_data(rule_form=form, active_tab="monitors", show_create_rule=True)
            )

        if action.startswith("update_rule:"):
            rule_id = action.split(":", 1)[1]
            rule = AlertRule.objects.filter(id=rule_id).first()
            if not rule:
                messages.error(request, "La regla seleccionada no existe.")
                return redirect("/app/alerts/?tab=monitors")
            form = AlertRuleForm(request.POST, instance=rule)
            if form.is_valid():
                form.save()
                messages.success(request, "Alerta actualizada correctamente.")
                return redirect("/app/alerts/?tab=monitors")
            messages.error(request, "No se pudo actualizar la alerta. Revisa los campos.")
            return self.render_to_response(self.get_context_data(rule_form=form, edit_rule=rule, active_tab="monitors"))

        if action.startswith("toggle_rule:"):
            rule_id = action.split(":", 1)[1]
            rule = AlertRule.objects.filter(id=rule_id).first()
            if rule:
                rule.is_active = not rule.is_active
                rule.save(update_fields=["is_active", "updated_at"])
                messages.success(request, "Estado de la alerta actualizado.")
            return redirect("/app/alerts/?tab=monitors")

        if action.startswith("delete_rule:"):
            rule_id = action.split(":", 1)[1]
            AlertRule.objects.filter(id=rule_id).delete()
            messages.success(request, "Alerta eliminada correctamente.")
            return redirect("/app/alerts/?tab=monitors")

        return redirect("alert-settings")

    def selected_server(self, servers):
        server_id = self.request.GET.get("server")
        if server_id:
            server = servers.filter(id=server_id).first()
            if server:
                return server
        return servers.first()

    def update_server_monitor(self, request, action):
        server = Server.objects.filter(id=request.POST.get("server_id")).first()
        if not server:
            messages.error(request, "Selecciona un servidor valido para modificar sus monitores.")
            return redirect("/app/alerts/?tab=monitors")

        rule = AlertRule.objects.filter(id=request.POST.get("rule_id"), is_active=True).first()
        if not rule:
            messages.error(request, "No se encontro el monitor seleccionado.")
            return redirect(f"/app/alerts/?tab=server_monitors&server={server.id}#server-monitors")

        assignment, _ = ServerMonitorAssignment.objects.get_or_create(server=server, rule=rule)
        if action == "assign_monitor":
            assignment.is_enabled = True
            assignment.save(update_fields=["is_enabled", "updated_at"])
            messages.success(request, f"Monitor '{rule.name}' asignado a {server.hostname}.")
        elif action == "remove_monitor":
            assignment.delete()
            messages.success(request, f"Monitor '{rule.name}' removido de {server.hostname}.")
        elif action == "toggle_monitor":
            assignment.is_enabled = not assignment.is_enabled
            assignment.save(update_fields=["is_enabled", "updated_at"])
            state = "habilitado" if assignment.is_enabled else "deshabilitado"
            messages.success(request, f"Monitor '{rule.name}' {state} en {server.hostname}.")

        return redirect(f"/app/alerts/?tab=server_monitors&server={server.id}#server-monitors")

    def filtered_rules(self):
        rules = AlertRule.objects.order_by("name")
        query = self.request.GET.get("q", "").strip()
        if query:
            rules = rules.filter(
                Q(name__icontains=query)
                | Q(event_type__icontains=query)
                | Q(service_name__icontains=query)
            )
        return rules

    def filtered_logs(self, form):
        cutoff = timezone.now() - timezone.timedelta(days=30)
        logs = AlertEmailLog.objects.select_related("server").filter(created_at__gte=cutoff)
        if form.is_valid():
            data = form.cleaned_data
            if data.get("date_from"):
                logs = logs.filter(created_at__date__gte=data["date_from"])
            if data.get("date_to"):
                logs = logs.filter(created_at__date__lte=data["date_to"])
            if data.get("server"):
                logs = logs.filter(server__hostname__icontains=data["server"])
            if data.get("severity"):
                logs = logs.filter(severity=data["severity"])
            if data.get("status"):
                logs = logs.filter(status=data["status"])
            if data.get("q"):
                query = data["q"]
                logs = logs.filter(
                    Q(subject__icontains=query)
                    | Q(message__icontains=query)
                    | Q(recipients__icontains=query)
                    | Q(error_message__icontains=query)
                )
        return logs.order_by("-created_at")


def ensure_default_monitors():
    defaults = [
        {
            "name": "Servidor sin conexion",
            "event_type": AlertRule.EVENT_OFFLINE,
            "threshold": 1,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 5,
            "min_interval_minutes": 5,
        },
        {
            "name": "Uso de CPU elevado",
            "event_type": AlertRule.EVENT_CPU,
            "threshold": 75,
            "priority": AlertRule.PRIORITY_WARNING,
            "notification_frequency_minutes": 10,
            "min_interval_minutes": 10,
        },
        {
            "name": "Uso de CPU critico",
            "event_type": AlertRule.EVENT_CPU,
            "threshold": 90,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 5,
            "min_interval_minutes": 5,
        },
        {
            "name": "Uso de memoria elevado",
            "event_type": AlertRule.EVENT_MEMORY,
            "threshold": 75,
            "priority": AlertRule.PRIORITY_WARNING,
            "notification_frequency_minutes": 10,
            "min_interval_minutes": 10,
        },
        {
            "name": "Uso de memoria critico",
            "event_type": AlertRule.EVENT_MEMORY,
            "threshold": 90,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 5,
            "min_interval_minutes": 5,
        },
        {
            "name": "Uso de disco advertencia",
            "event_type": AlertRule.EVENT_FREE_SPACE,
            "threshold": 20,
            "priority": AlertRule.PRIORITY_WARNING,
            "notification_frequency_minutes": 30,
            "min_interval_minutes": 30,
        },
        {
            "name": "Uso de disco critico",
            "event_type": AlertRule.EVENT_FREE_SPACE,
            "threshold": 10,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 15,
            "min_interval_minutes": 15,
        },
        {
            "name": "Servicio critico detenido",
            "event_type": AlertRule.EVENT_CRITICAL_SERVICE,
            "threshold": 1,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 5,
            "min_interval_minutes": 5,
            "service_name": "Servicios criticos",
        },
        {
            "name": "Servicio detenido",
            "event_type": AlertRule.EVENT_SERVICE_STOPPED,
            "threshold": 1,
            "priority": AlertRule.PRIORITY_WARNING,
            "notification_frequency_minutes": 10,
            "min_interval_minutes": 10,
        },
        {
            "name": "Reinicio inesperado",
            "event_type": AlertRule.EVENT_REBOOT,
            "threshold": 1,
            "priority": AlertRule.PRIORITY_WARNING,
            "notification_frequency_minutes": 60,
            "min_interval_minutes": 60,
        },
        {
            "name": "Error en respaldos",
            "event_type": AlertRule.EVENT_BACKUP,
            "threshold": 1,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 60,
            "min_interval_minutes": 60,
        },
        {
            "name": "Error de conexion a base de datos",
            "event_type": AlertRule.EVENT_DATABASE,
            "threshold": 1,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 10,
            "min_interval_minutes": 10,
        },
        {
            "name": "Estado SMART de disco",
            "event_type": AlertRule.EVENT_DISK,
            "threshold": 95,
            "priority": AlertRule.PRIORITY_CRITICAL,
            "notification_frequency_minutes": 60,
            "min_interval_minutes": 60,
            "service_name": "SMART",
        },
        {
            "name": "Tiempo encendido mayor a 30 dias",
            "event_type": AlertRule.EVENT_REBOOT,
            "threshold": 30,
            "priority": AlertRule.PRIORITY_INFO,
            "notification_frequency_minutes": 1440,
            "min_interval_minutes": 1440,
        },
    ]
    for data in defaults:
        AlertRule.objects.get_or_create(
            name=data["name"],
            defaults={
                **data,
                "is_active": True,
                "recipients": "",
            },
        )


class AlertHistoryExportView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    def test_func(self):
        return user_can_manage_alerts(self.request.user)

    def get(self, request):
        response = HttpResponse(content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = 'attachment; filename="historial-alertas.csv"'
        writer = csv.writer(response)
        writer.writerow(["Fecha", "Estado", "Tipo", "Severidad", "Servidor", "Servicio", "Destinatarios", "Asunto", "Mensaje", "Error"])
        cutoff = timezone.now() - timezone.timedelta(days=30)
        logs = AlertEmailLog.objects.select_related("server").filter(created_at__gte=cutoff).order_by("-created_at")
        form = AlertHistoryFilterForm(request.GET or None)
        if form.is_valid():
            data = form.cleaned_data
            if data.get("date_from"):
                logs = logs.filter(created_at__date__gte=data["date_from"])
            if data.get("date_to"):
                logs = logs.filter(created_at__date__lte=data["date_to"])
            if data.get("server"):
                logs = logs.filter(server__hostname__icontains=data["server"])
            if data.get("severity"):
                logs = logs.filter(severity=data["severity"])
            if data.get("status"):
                logs = logs.filter(status=data["status"])
            if data.get("q"):
                query = data["q"]
                logs = logs.filter(
                    Q(subject__icontains=query)
                    | Q(message__icontains=query)
                    | Q(recipients__icontains=query)
                    | Q(error_message__icontains=query)
                )
        for log in logs:
            writer.writerow(
                [
                    timezone.localtime(log.created_at).strftime("%Y-%m-%d %H:%M:%S"),
                    log.get_status_display(),
                    log.alert_type,
                    log.get_severity_display(),
                    log.server.hostname if log.server else "",
                    log.service_name,
                    log.recipients,
                    log.subject,
                    log.message,
                    log.error_message,
                ]
            )
        return response
