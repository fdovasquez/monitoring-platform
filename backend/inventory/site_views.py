from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Count
from django.shortcuts import redirect
from django.views.generic import TemplateView

from alerts.forms import SmtpSettingsForm, TestEmailForm
from alerts.models import SmtpSettings
from alerts.services import send_test_email, test_smtp_connection
from metrics.central_reporter import test_central_connection

from .forms import DeviceGroupForm
from .models import CentralMonitorSettings, DeviceGroup, SiteSettings, TlsCertificate
from .site_forms import CentralMonitorSettingsForm, SiteSettingsForm, TlsCertificateForm


def user_can_manage_site_settings(user):
    return user.is_superuser or user.groups.filter(name="Administrador").exists()


class SiteSettingsView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    template_name = "inventory/site_settings.html"

    def test_func(self):
        return user_can_manage_site_settings(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        settings = SiteSettings.load()
        tls_certificate = TlsCertificate.load()
        central_settings = CentralMonitorSettings.load()
        smtp = SmtpSettings.load()
        context["settings_form"] = kwargs.get("settings_form") or SiteSettingsForm(instance=settings)
        context["site_settings_edit"] = settings
        context["central_settings"] = central_settings
        context["central_form"] = kwargs.get("central_form") or CentralMonitorSettingsForm(instance=central_settings)
        context["smtp_settings"] = smtp
        context["smtp_form"] = kwargs.get("smtp_form") or SmtpSettingsForm(instance=smtp)
        context["test_email_form"] = kwargs.get("test_email_form") or TestEmailForm()
        context["tls_certificate"] = tls_certificate
        context["tls_form"] = kwargs.get("tls_form") or TlsCertificateForm(instance=tls_certificate)
        context["group_form"] = kwargs.get("group_form") or DeviceGroupForm()
        context["device_groups"] = DeviceGroup.objects.annotate(server_count=Count("servers")).order_by("name")
        forwarded_proto = self.request.headers.get("X-Forwarded-Proto", "")
        context["https_active"] = self.request.is_secure() or forwarded_proto.lower() == "https"
        context["active_settings_tab"] = kwargs.get("active_settings_tab") or self.request.GET.get("tab", "site")
        return context

    def post(self, request):
        action = request.POST.get("action", "save_site")
        smtp = SmtpSettings.load()

        if action == "save_tls":
            certificate = TlsCertificate.load()
            form = TlsCertificateForm(request.POST, request.FILES, instance=certificate)
            if form.is_valid():
                form.save()
                messages.success(request, "Certificado HTTPS guardado correctamente. Exportalo en el servidor para activarlo.")
                return redirect("/app/settings/?tab=https")
            messages.error(request, "No se pudo guardar el certificado. Revisa los archivos seleccionados.")
            return self.render_to_response(self.get_context_data(tls_form=form, active_settings_tab="https"))

        if action == "save_group":
            group_id = request.POST.get("group_id")
            group = DeviceGroup.objects.filter(id=group_id).first() if group_id else None
            form = DeviceGroupForm(request.POST, instance=group)
            if form.is_valid():
                form.save()
                messages.success(request, "Grupo de dispositivos guardado correctamente.")
                return redirect("/app/settings/?tab=groups")
            messages.error(request, "No se pudo guardar el grupo. Revisa los campos.")
            return self.render_to_response(self.get_context_data(group_form=form, active_settings_tab="groups"))

        if action == "delete_group":
            group = DeviceGroup.objects.filter(id=request.POST.get("group_id")).annotate(server_count=Count("servers")).first()
            if not group:
                messages.error(request, "El grupo seleccionado no existe.")
                return redirect("/app/settings/?tab=groups")
            if group.server_count:
                messages.error(request, "No se puede eliminar un grupo con servidores asociados. Reasigna los servidores primero.")
                return redirect("/app/settings/?tab=groups")
            group.delete()
            messages.success(request, "Grupo de dispositivos eliminado correctamente.")
            return redirect("/app/settings/?tab=groups")

        if action == "save_smtp":
            form = SmtpSettingsForm(request.POST, instance=smtp)
            if form.is_valid():
                form.save()
                messages.success(request, "Configuracion SMTP guardada correctamente.")
                return redirect("/app/settings/?tab=smtp")
            messages.error(request, "No se pudo guardar SMTP. Revisa los campos.")
            return self.render_to_response(self.get_context_data(smtp_form=form, active_settings_tab="smtp"))

        if action == "save_central":
            central_settings = CentralMonitorSettings.load()
            form = CentralMonitorSettingsForm(request.POST, instance=central_settings)
            if form.is_valid():
                form.save()
                messages.success(request, "Configuracion del monitor central guardada correctamente.")
                return redirect("/app/settings/?tab=central")
            messages.error(request, "No se pudo guardar el monitor central. Revisa los campos.")
            return self.render_to_response(self.get_context_data(central_form=form, active_settings_tab="central"))

        if action == "test_central":
            try:
                test_central_connection()
                messages.success(request, "Prueba con monitor central exitosa. El endpoint recibio el reporte de prueba.")
            except Exception as exc:
                messages.error(request, f"No se pudo conectar con el monitor central: {exc}")
            return redirect("/app/settings/?tab=central")

        if action == "test_connection":
            try:
                test_smtp_connection(smtp)
                messages.success(request, "Conexion SMTP exitosa.")
            except Exception as exc:
                messages.error(request, f"No se pudo conectar al servidor SMTP: {exc}")
            return redirect("/app/settings/?tab=smtp")

        if action == "send_test_email":
            form = TestEmailForm(request.POST)
            if form.is_valid():
                try:
                    send_test_email(smtp, form.cleaned_data["recipient"])
                    messages.success(request, "Correo de prueba enviado correctamente.")
                except Exception as exc:
                    messages.error(request, f"No se pudo enviar el correo de prueba: {exc}")
                return redirect("/app/settings/?tab=smtp")
            return self.render_to_response(self.get_context_data(test_email_form=form, active_settings_tab="smtp"))

        settings = SiteSettings.load()
        form = SiteSettingsForm(request.POST, request.FILES, instance=settings)
        if form.is_valid():
            form.save()
            messages.success(request, "Configuracion del sitio actualizada correctamente.")
            return redirect("site-settings")
        messages.error(request, "No se pudo guardar la configuracion. Revisa los campos indicados.")
        return self.render_to_response(self.get_context_data(settings_form=form))
