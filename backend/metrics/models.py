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
