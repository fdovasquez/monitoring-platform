from django.db import models


class AlertRule(models.Model):
    METRIC_CHOICES = [
        ("cpu_percent", "CPU %"),
        ("memory_percent", "Memoria %"),
        ("disk_percent", "Disco %"),
    ]

    name = models.CharField(max_length=255)
    metric = models.CharField(max_length=50, choices=METRIC_CHOICES)
    threshold = models.FloatField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


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
