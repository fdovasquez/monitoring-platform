from django import forms

from .models import SiteSettings


class SiteSettingsForm(forms.ModelForm):
    delete_logo = forms.BooleanField(label="Eliminar logo actual", required=False)

    allowed_content_types = {"image/jpeg", "image/png", "image/webp"}
    max_logo_size = 2 * 1024 * 1024

    class Meta:
        model = SiteSettings
        fields = ["site_name", "subtitle", "logo_width", "logo_height", "logo"]
        labels = {
            "site_name": "Nombre del sitio",
            "subtitle": "Texto inferior",
            "logo_width": "Ancho del logo",
            "logo_height": "Alto del logo",
            "logo": "Logo",
        }
        widgets = {
            "logo_width": forms.NumberInput(attrs={"min": 40, "max": 260, "step": 1}),
            "logo_height": forms.NumberInput(attrs={"min": 20, "max": 120, "step": 1}),
            "logo": forms.FileInput(attrs={"class": "logo-input"}),
        }
        help_texts = {
            "subtitle": "Texto pequeno que aparece bajo el logo en la cabecera.",
            "logo_width": "Valor en pixeles. Recomendado entre 90 y 150.",
            "logo_height": "Valor en pixeles. Recomendado entre 28 y 48.",
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

    def clean_logo_width(self):
        width = self.cleaned_data["logo_width"]
        if width < 40 or width > 260:
            raise forms.ValidationError("El ancho debe estar entre 40 y 260 px.")
        return width

    def clean_logo_height(self):
        height = self.cleaned_data["logo_height"]
        if height < 20 or height > 120:
            raise forms.ValidationError("El alto debe estar entre 20 y 120 px.")
        return height

    def save(self, commit=True):
        settings = super().save(commit=False)
        if self.cleaned_data.get("delete_logo") and settings.logo:
            settings.logo.delete(save=False)
            settings.logo = None
        if commit:
            settings.save()
        return settings
