import re

from django import forms

from .models import AlertRule, SmtpSettings


class SmtpSettingsForm(forms.ModelForm):
    password = forms.CharField(label="Contrasena", widget=forms.PasswordInput, required=False)

    class Meta:
        model = SmtpSettings
        fields = [
            "host",
            "port",
            "username",
            "password",
            "from_email",
            "from_name",
            "security",
            "require_auth",
            "timeout_seconds",
        ]
        labels = {
            "host": "Servidor SMTP",
            "port": "Puerto",
            "username": "Usuario",
            "from_email": "Correo remitente",
            "from_name": "Nombre del remitente",
            "security": "Tipo de seguridad",
            "require_auth": "Requerir autenticacion",
            "timeout_seconds": "Timeout",
        }
        widgets = {
            "port": forms.NumberInput(attrs={"min": 1, "max": 65535}),
            "timeout_seconds": forms.NumberInput(attrs={"min": 3, "max": 120}),
        }

    def clean(self):
        cleaned_data = super().clean()
        require_auth = cleaned_data.get("require_auth")
        username = cleaned_data.get("username")
        password = cleaned_data.get("password")
        if require_auth and not username:
            self.add_error("username", "Ingresa el usuario SMTP.")
        if require_auth and not password and not self.instance.encrypted_password:
            self.add_error("password", "Ingresa la contrasena SMTP.")
        return cleaned_data

    def save(self, commit=True):
        settings = super().save(commit=False)
        password = self.cleaned_data.get("password")
        if password:
            settings.set_password(password)
        if commit:
            settings.save()
        return settings


class TestEmailForm(forms.Form):
    recipient = forms.EmailField(label="Correo de prueba")


class BulkRecipientsForm(forms.Form):
    recipients = forms.CharField(
        label="Destinatarios",
        widget=forms.Textarea(
            attrs={
                "rows": 2,
                "placeholder": "soporte@empresa.cl, infraestructura@empresa.cl",
            }
        ),
    )

    def clean_recipients(self):
        raw = self.cleaned_data.get("recipients", "")
        emails = [item.strip() for item in re.split(r"[,;\n]+", raw) if item.strip()]
        if not emails:
            raise forms.ValidationError("Ingresa al menos un destinatario.")
        validator = forms.EmailField()
        normalized = []
        seen = set()
        for email in emails:
            value = validator.clean(email)
            key = value.lower()
            if key not in seen:
                seen.add(key)
                normalized.append(value)
        return normalized


class AlertRuleForm(forms.ModelForm):
    class Meta:
        model = AlertRule
        fields = [
            "name",
            "event_type",
            "is_active",
            "threshold",
            "priority",
            "recipients",
            "notification_frequency_minutes",
            "min_interval_minutes",
            "service_name",
        ]
        labels = {
            "name": "Nombre de la alerta",
            "event_type": "Evento",
            "is_active": "Habilitada",
            "threshold": "Umbral",
            "priority": "Prioridad",
            "recipients": "Destinatarios",
            "notification_frequency_minutes": "Frecuencia de notificacion",
            "min_interval_minutes": "Tiempo minimo entre correos",
            "service_name": "Servicio afectado",
        }
        widgets = {
            "threshold": forms.NumberInput(attrs={"min": 0, "max": 100, "step": "0.1"}),
            "recipients": forms.Textarea(attrs={"rows": 3, "placeholder": "soporte@empresa.cl, infraestructura@empresa.cl"}),
            "notification_frequency_minutes": forms.NumberInput(attrs={"min": 1, "max": 10080}),
            "min_interval_minutes": forms.NumberInput(attrs={"min": 1, "max": 10080}),
        }

    def clean_recipients(self):
        recipients = self.cleaned_data.get("recipients", "")
        emails = [item.strip() for item in re.split(r"[,;\n]+", recipients) if item.strip()]
        if not emails:
            raise forms.ValidationError("Ingresa al menos un destinatario.")
        validator = forms.EmailField()
        for email in emails:
            validator.clean(email)
        return ", ".join(emails)


class AlertHistoryFilterForm(forms.Form):
    date_from = forms.DateField(label="Desde", required=False, widget=forms.DateInput(attrs={"type": "date"}))
    date_to = forms.DateField(label="Hasta", required=False, widget=forms.DateInput(attrs={"type": "date"}))
    server = forms.CharField(label="Servidor", required=False)
    severity = forms.ChoiceField(label="Severidad", required=False)
    status = forms.ChoiceField(label="Estado", required=False)
    q = forms.CharField(label="Buscar", required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["severity"].choices = [("", "Todas")] + list(AlertRule.PRIORITY_CHOICES)
        self.fields["status"].choices = [("", "Todos"), ("sent", "Enviado"), ("error", "Error")]

