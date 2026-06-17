from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import redirect
from django.views.generic import TemplateView

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
        context["settings_form"] = kwargs.get("settings_form") or SiteSettingsForm(instance=settings)
        context["site_settings_edit"] = settings
        return context

    def post(self, request):
        settings = SiteSettings.load()
        form = SiteSettingsForm(request.POST, request.FILES, instance=settings)
        if form.is_valid():
            form.save()
            messages.success(request, "Configuracion del sitio actualizada correctamente.")
            return redirect("site-settings")
        messages.error(request, "No se pudo guardar la configuracion. Revisa los campos indicados.")
        return self.render_to_response(self.get_context_data(settings_form=form))
