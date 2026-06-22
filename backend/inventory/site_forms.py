from django import forms

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import SiteSettings, TlsCertificate


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


class TlsCertificateForm(forms.ModelForm):
    certificate_file = forms.FileField(label="Certificado", required=False)
    private_key_file = forms.FileField(label="Llave privada", required=False)
    remove_certificate = forms.BooleanField(label="Eliminar certificado HTTPS", required=False)

    max_file_size = 2 * 1024 * 1024

    class Meta:
        model = TlsCertificate
        fields = ["domain"]
        labels = {"domain": "Dominio o IP para HTTPS"}
        help_texts = {"domain": "Ejemplo: monitor.empresa.cl. Para una IP interna, ingresa la IP exacta."}

    def clean_certificate_file(self):
        certificate = self.cleaned_data.get("certificate_file")
        if not certificate:
            return certificate
        if certificate.size > self.max_file_size:
            raise forms.ValidationError("El certificado no puede superar 2 MB.")
        content = certificate.read()
        try:
            x509.load_pem_x509_certificate(content)
        except ValueError as exc:
            raise forms.ValidationError("El archivo no contiene un certificado PEM valido.") from exc
        certificate.seek(0)
        return certificate

    def clean_private_key_file(self):
        private_key = self.cleaned_data.get("private_key_file")
        if not private_key:
            return private_key
        if private_key.size > self.max_file_size:
            raise forms.ValidationError("La llave privada no puede superar 2 MB.")
        content = private_key.read()
        try:
            serialization.load_pem_private_key(content, password=None)
        except (TypeError, ValueError) as exc:
            raise forms.ValidationError("La llave privada debe estar en formato PEM y sin clave adicional.") from exc
        private_key.seek(0)
        return private_key

    def clean(self):
        cleaned_data = super().clean()
        has_certificate = bool(cleaned_data.get("certificate_file"))
        has_key = bool(cleaned_data.get("private_key_file"))
        removing = cleaned_data.get("remove_certificate")
        if has_certificate != has_key:
            raise forms.ValidationError("Debes cargar el certificado y su llave privada juntos.")
        if removing and (has_certificate or has_key):
            raise forms.ValidationError("No puedes eliminar y cargar un certificado en la misma accion.")
        return cleaned_data

    def save(self, commit=True):
        certificate = super().save(commit=False)
        if self.cleaned_data.get("remove_certificate"):
            certificate.clear()
        elif self.cleaned_data.get("certificate_file"):
            certificate_file = self.cleaned_data["certificate_file"]
            private_key_file = self.cleaned_data["private_key_file"]
            certificate.certificate_pem = certificate_file.read().decode("utf-8")
            certificate.set_private_key(private_key_file.read().decode("utf-8"))
            certificate.certificate_filename = certificate_file.name
        if commit:
            certificate.save()
        return certificate
