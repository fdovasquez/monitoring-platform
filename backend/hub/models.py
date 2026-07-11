from django.db import models


class Satellite(models.Model):
    STATUS_OK = "ok"
    STATUS_WARNING = "warning"
    STATUS_CRITICAL = "critical"
    STATUS_OFFLINE = "offline"
    STATUS_CHOICES = [
        (STATUS_OK, "Normal"),
        (STATUS_WARNING, "Advertencia"),
        (STATUS_CRITICAL, "Critico"),
        (STATUS_OFFLINE, "Sin reporte"),
    ]

    satellite_id = models.CharField(max_length=120, unique=True)
    name = models.CharField(max_length=160)
    hostname = models.CharField(max_length=255, blank=True)
    site_name = models.CharField(max_length=160, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OK)
    last_report_at = models.DateTimeField(null=True, blank=True)
    servers_total = models.PositiveIntegerField(default=0)
    servers_online = models.PositiveIntegerField(default=0)
    alerts_unresolved = models.PositiveIntegerField(default=0)
    critical_alerts = models.PositiveIntegerField(default=0)
    warning_alerts = models.PositiveIntegerField(default=0)
    last_payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "satellite_id"]

    def __str__(self):
        return self.name or self.satellite_id


class SatelliteReport(models.Model):
    satellite = models.ForeignKey(Satellite, on_delete=models.CASCADE, related_name="reports")
    report_timestamp = models.DateTimeField()
    source_hostname = models.CharField(max_length=255, blank=True)
    site_name = models.CharField(max_length=160, blank=True)
    agents_count = models.PositiveIntegerField(default=0)
    metrics_count = models.PositiveIntegerField(default=0)
    alerts_count = models.PositiveIntegerField(default=0)
    status_summary = models.JSONField(default=dict, blank=True)
    payload = models.JSONField(default=dict)
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-received_at"]
        indexes = [
            models.Index(fields=["satellite", "-received_at"]),
            models.Index(fields=["report_timestamp"]),
        ]

    def __str__(self):
        return f"{self.satellite} {self.report_timestamp}"


class SatelliteServerSnapshot(models.Model):
    satellite = models.ForeignKey(Satellite, on_delete=models.CASCADE, related_name="server_snapshots")
    source_server_id = models.CharField(max_length=80, blank=True)
    hostname = models.CharField(max_length=255)
    name = models.CharField(max_length=255, blank=True)
    ip_address = models.CharField(max_length=80, blank=True)
    group = models.CharField(max_length=120, blank=True)
    os_type = models.CharField(max_length=40, blank=True)
    environment = models.CharField(max_length=120, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    agent_version = models.CharField(max_length=80, blank=True)
    inventory = models.JSONField(default=dict, blank=True)
    latest_metric = models.JSONField(default=dict, blank=True)
    raw_data = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["satellite__name", "hostname"]
        unique_together = ("satellite", "hostname")
        indexes = [
            models.Index(fields=["satellite", "hostname"]),
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.satellite} / {self.hostname}"


class SatelliteAlert(models.Model):
    satellite = models.ForeignKey(Satellite, on_delete=models.CASCADE, related_name="alerts")
    source_alert_id = models.CharField(max_length=80)
    server_hostname = models.CharField(max_length=255, blank=True)
    rule = models.CharField(max_length=255, blank=True)
    event_type = models.CharField(max_length=120, blank=True)
    priority = models.CharField(max_length=40, blank=True)
    value = models.CharField(max_length=120, blank=True)
    message = models.TextField(blank=True)
    is_resolved = models.BooleanField(default=False)
    source_created_at = models.DateTimeField(null=True, blank=True)
    source_resolved_at = models.DateTimeField(null=True, blank=True)
    raw_data = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["is_resolved", "-source_created_at"]
        unique_together = ("satellite", "source_alert_id")
        indexes = [
            models.Index(fields=["satellite", "is_resolved"]),
            models.Index(fields=["priority", "is_resolved"]),
        ]

    def __str__(self):
        return f"{self.satellite} / {self.rule or self.source_alert_id}"
