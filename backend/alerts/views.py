import csv

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.views.generic import TemplateView

from .forms import AlertHistoryFilterForm, AlertRuleForm, SmtpSettingsForm, TestEmailForm
from .models import AlertEmailLog, AlertRule, SmtpSettings
from .services import send_test_email, test_smtp_connection


def user_can_manage_alerts(user):
    return user.is_superuser or user.groups.filter(name="Administrador").exists()


class AlertSettingsView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    template_name = "alerts/alert_settings.html"

    def test_func(self):
        return user_can_manage_alerts(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        smtp = SmtpSettings.load()
        history_filter = AlertHistoryFilterForm(self.request.GET or None)
        logs = self.filtered_logs(history_filter)
        cutoff = timezone.now() - timezone.timedelta(days=30)
        AlertEmailLog.objects.filter(created_at__lt=cutoff).delete()
        context.update(
            {
                "active_tab": kwargs.get("active_tab") or self.request.GET.get("tab", "smtp"),
                "smtp_settings": smtp,
                "smtp_form": kwargs.get("smtp_form") or SmtpSettingsForm(instance=smtp),
                "test_email_form": kwargs.get("test_email_form") or TestEmailForm(),
                "rule_form": kwargs.get("rule_form") or AlertRuleForm(),
                "rules": AlertRule.objects.order_by("name"),
                "history_filter": history_filter,
                "logs": logs[:200],
                "sent_count": AlertEmailLog.objects.filter(created_at__gte=cutoff, status=AlertEmailLog.STATUS_SENT).count(),
                "error_count": AlertEmailLog.objects.filter(created_at__gte=cutoff, status=AlertEmailLog.STATUS_ERROR).count(),
            }
        )
        return context

    def post(self, request):
        action = request.POST.get("action", "")
        smtp = SmtpSettings.load()

        if action == "save_smtp":
            form = SmtpSettingsForm(request.POST, instance=smtp)
            if form.is_valid():
                form.save()
                messages.success(request, "Configuracion SMTP guardada correctamente.")
                return redirect("alert-settings")
            messages.error(request, "No se pudo guardar SMTP. Revisa los campos.")
            return self.render_to_response(self.get_context_data(smtp_form=form, active_tab="smtp"))

        if action == "test_connection":
            try:
                test_smtp_connection(smtp)
                messages.success(request, "Conexion SMTP exitosa.")
            except Exception as exc:
                messages.error(request, f"No se pudo conectar al servidor SMTP: {exc}")
            return redirect("alert-settings")

        if action == "send_test_email":
            form = TestEmailForm(request.POST)
            if form.is_valid():
                try:
                    send_test_email(smtp, form.cleaned_data["recipient"])
                    messages.success(request, "Correo de prueba enviado correctamente.")
                except Exception as exc:
                    messages.error(request, f"No se pudo enviar el correo de prueba: {exc}")
                return redirect("alert-settings")
            return self.render_to_response(self.get_context_data(test_email_form=form, active_tab="smtp"))

        if action == "create_rule":
            form = AlertRuleForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Alerta creada correctamente.")
                return redirect("/app/alerts/?tab=rules")
            messages.error(request, "No se pudo crear la alerta. Revisa los campos.")
            return self.render_to_response(self.get_context_data(rule_form=form, active_tab="rules"))

        if action.startswith("toggle_rule:"):
            rule_id = action.split(":", 1)[1]
            rule = AlertRule.objects.filter(id=rule_id).first()
            if rule:
                rule.is_active = not rule.is_active
                rule.save(update_fields=["is_active", "updated_at"])
                messages.success(request, "Estado de la alerta actualizado.")
            return redirect("/app/alerts/?tab=rules")

        if action.startswith("delete_rule:"):
            rule_id = action.split(":", 1)[1]
            AlertRule.objects.filter(id=rule_id).delete()
            messages.success(request, "Alerta eliminada correctamente.")
            return redirect("/app/alerts/?tab=rules")

        return redirect("alert-settings")

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
