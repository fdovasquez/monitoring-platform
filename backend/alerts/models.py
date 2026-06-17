from django.db import models
from django.utils import timezone

from inventory.models import credential_cipher


class SmtpSettings(models.Model):
    SECURITY_NONE = "none"
    SECURITY_SSL = "ssl"
    SECURITY_TLS = "tls"
    SECURITY_CHOICES = [
        (SECURITY_SSL, "SSL"),
        (SECURITY_TLS, "TLS"),
        (SECURITY_NONE, "Sin cifrado"),
    ]

    host = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(default=587)
    username = models.CharField(max_length=255, blank=True)
    encrypted_password = models.TextField(blank=True)
    from_email = models.EmailField(blank=True)
    from_name = models.CharField(max_length=160, blank=True)
    security = models.CharField(max_length=10, choices=SECURITY_CHOICES, default=SECURITY_TLS)
    require_auth = models.BooleanField(default=True)
    timeout_seconds = models.PositiveIntegerField(default=10)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuracion SMTP"
        verbose_name_plural = "Configuracion SMTP"

    def save(self, *args, **kwargs):
        self.pk = 1
        return super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        settings, _ = cls.objects.get_or_create(pk=1)
        return settings

    def set_password(self, password):
        if password:
            self.encrypted_password = credential_cipher().encrypt(password.encode("utf-8")).decode("utf-8")

    def get_password(self):
        if not self.encrypted_password:
            return ""
        return credential_cipher().decrypt(self.encrypted_password.encode("utf-8")).decode("utf-8")

    @property
    def is_configured(self):
        if not self.host or not self.port or not self.from_email:
            return False
        if self.require_auth and (not self.username or not self.encrypted_password):
            return False
        return True

    def __str__(self):
        return self.host or "SMTP sin configurar"


class AlertRule(models.Model):
    EVENT_OFFLINE = "server_offline"
    EVENT_SERVICE_STOPPED = "service_stopped"
    EVENT_CPU = "cpu_percent"
    EVENT_MEMORY = "memory_percent"
    EVENT_DISK = "disk_percent"
    EVENT_FREE_SPACE = "free_space_percent"
    EVENT_REBOOT = "unexpected_reboot"
    EVENT_BACKUP = "backup_error"
    EVENT_DATABASE = "database_connection_error"
    EVENT_CRITICAL_SERVICE = "critical_service_error"
    EVENT_CHOICES = [
        (EVENT_OFFLINE, "Servidor fuera de linea"),
        (EVENT_SERVICE_STOPPED, "Servicio detenido"),
        (EVENT_CPU, "Uso de CPU superior al umbral"),
        (EVENT_MEMORY, "Uso de memoria superior al umbral"),
        (EVENT_DISK, "Uso de disco superior al umbral"),
        (EVENT_FREE_SPACE, "Espacio libre inferior al umbral"),
        (EVENT_REBOOT, "Reinicio inesperado del servidor"),
        (EVENT_BACKUP, "Error en respaldos"),
        (EVENT_DATABASE, "Error en conexion con bases de datos"),
        (EVENT_CRITICAL_SERVICE, "Error en servicios criticos"),
    ]
    PRIORITY_INFO = "info"
    PRIORITY_WARNING = "warning"
    PRIORITY_CRITICAL = "critical"
    PRIORITY_CHOICES = [
        (PRIORITY_INFO, "Informacion"),
        (PRIORITY_WARNING, "Advertencia"),
        (PRIORITY_CRITICAL, "Critica"),
    ]
    METRIC_CHOICES = [
        ("cpu_percent", "CPU %"),
        ("memory_percent", "Memoria %"),
        ("disk_percent", "Disco %"),
    ]

    name = models.CharField(max_length=255)
    event_type = models.CharField(max_length=80, choices=EVENT_CHOICES, default=EVENT_CPU)
    metric = models.CharField(max_length=50, choices=METRIC_CHOICES, blank=True)
    threshold = models.FloatField()
    is_active = models.BooleanField(default=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default=PRIORITY_WARNING)
    recipients = models.TextField(blank=True, help_text="Correos separados por coma, punto y coma o salto de linea.")
    notification_frequency_minutes = models.PositiveIntegerField(default=60)
    min_interval_minutes = models.PositiveIntegerField(default=30)
    service_name = models.CharField(max_length=160, blank=True)
    last_notified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def recipient_list(self):
        raw = self.recipients.replace(";", ",").replace("\n", ",")
        return [email.strip() for email in raw.split(",") if email.strip()]

    def can_notify(self):
        if not self.last_notified_at:
            return True
        wait_until = self.last_notified_at + timezone.timedelta(minutes=self.min_interval_minutes)
        return timezone.now() >= wait_until


class AlertEvent(models.Model):
    rule = models.ForeignKey(AlertRule, on_delete=models.CASCADE, related_name="events")
    server = models.ForeignKey("inventory.Server", on_delete=models.CASCADE, related_name="alert_events")
    value = models.FloatField()
    message = models.CharField(max_length=500)
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.message


class AlertEmailLog(models.Model):
    STATUS_SENT = "sent"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_SENT, "Enviado"),
        (STATUS_ERROR, "Error"),
    ]

    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    alert_type = models.CharField(max_length=120)
    severity = models.CharField(max_length=20, choices=AlertRule.PRIORITY_CHOICES, default=AlertRule.PRIORITY_WARNING)
    server = models.ForeignKey("inventory.Server", on_delete=models.SET_NULL, null=True, blank=True, related_name="alert_email_logs")
    service_name = models.CharField(max_length=160, blank=True)
    recipients = models.TextField(blank=True)
    subject = models.CharField(max_length=255)
    message = models.TextField()
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"]),
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
        ]

    def __str__(self):
        return f"{self.get_status_display()} - {self.subject}"
