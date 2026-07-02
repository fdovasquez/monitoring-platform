from django.db import models


class MetricSample(models.Model):
    server = models.ForeignKey("inventory.Server", on_delete=models.CASCADE, related_name="metric_samples")
    timestamp = models.DateTimeField()
    agent_version = models.CharField(max_length=50, blank=True)
    cpu_percent = models.FloatField(null=True, blank=True)
    memory_percent = models.FloatField(null=True, blank=True)
    disk_percent = models.FloatField(null=True, blank=True)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["server", "-timestamp"]),
            models.Index(fields=["timestamp"]),
        ]

    def __str__(self):
        return f"{self.server.hostname} {self.timestamp}"


class CentralReportQueue(models.Model):
    STATUS_PENDING = "pending"
    STATUS_SENT = "sent"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pendiente"),
        (STATUS_SENT, "Enviado"),
        (STATUS_ERROR, "Error"),
    ]

    payload = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["-sent_at"]),
        ]

    def __str__(self):
        return f"Reporte central {self.get_status_display()} #{self.id}"
