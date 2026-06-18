from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect
from django.views.generic import TemplateView

from alerts.forms import SmtpSettingsForm, TestEmailForm
from alerts.models import SmtpSettings
from alerts.services import send_test_email, test_smtp_connection

from .models import SiteSettings
from .site_forms import SiteSettingsForm


def user_can_manage_site_settings(user):
    return user.is_superuser or user.groups.filter(name="Administrador").exists()


class SiteSettingsView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    template_name = "inventory/site_settings.html"

    def test_func(self):
        return user_can_manage_site_settings(self.request.user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        settings = SiteSettings.load()
        smtp = SmtpSettings.load()
        context["settings_form"] = kwargs.get("settings_form") or SiteSettingsForm(instance=settings)
        context["site_settings_edit"] = settings
        context["smtp_settings"] = smtp
        context["smtp_form"] = kwargs.get("smtp_form") or SmtpSettingsForm(instance=smtp)
        context["test_email_form"] = kwargs.get("test_email_form") or TestEmailForm()
        context["active_settings_tab"] = kwargs.get("active_settings_tab") or self.request.GET.get("tab", "site")
        return context

    def post(self, request):
        action = request.POST.get("action", "save_site")
        smtp = SmtpSettings.load()

        if action == "save_smtp":
            form = SmtpSettingsForm(request.POST, instance=smtp)
            if form.is_valid():
                form.save()
                messages.success(request, "Configuracion SMTP guardada correctamente.")
                return redirect("/app/settings/?tab=smtp")
            messages.error(request, "No se pudo guardar SMTP. Revisa los campos.")
            return self.render_to_response(self.get_context_data(smtp_form=form, active_settings_tab="smtp"))

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
