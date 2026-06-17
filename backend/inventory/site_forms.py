from django import forms

from .models import SiteSettings


class SiteSettingsForm(forms.ModelForm):
    delete_logo = forms.BooleanField(label="Eliminar logo actual", required=False)

    allowed_content_types = {"image/jpeg", "image/png", "image/webp"}
    max_logo_size = 2 * 1024 * 1024

    class Meta:
        model = SiteSettings
        fields = ["site_name", "subtitle", "logo"]
        labels = {
            "site_name": "Nombre del sitio",
            "subtitle": "Texto inferior",
            "logo": "Logo",
        }
        widgets = {
            "logo": forms.FileInput(attrs={"class": "logo-input"}),
        }
        help_texts = {
            "subtitle": "Texto pequeno que aparece bajo el logo en la cabecera.",
        }

    def clean_logo(self):
        logo = self.cleaned_data.get("logo")
        if not logo:
            return logo
        if logo.size > self.max_logo_size:
            raise forms.ValidationError("El logo no puede superar 2 MB.")
        if getattr(logo, "content_type", "") not in self.allowed_content_types:
            raise forms.ValidationError("Solo se permiten imagenes JPG, PNG o WEBP.")
        return logo

    def save(self, commit=True):
        settings = super().save(commit=False)
        if self.cleaned_data.get("delete_logo") and settings.logo:
            settings.logo.delete(save=False)
            settings.logo = None
        if commit:
            settings.save()
        return settings
