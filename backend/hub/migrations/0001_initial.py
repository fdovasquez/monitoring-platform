# Generated manually for the monitoring central hub.

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Satellite",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("satellite_id", models.CharField(max_length=120, unique=True)),
                ("name", models.CharField(max_length=160)),
                ("hostname", models.CharField(blank=True, max_length=255)),
                ("site_name", models.CharField(blank=True, max_length=160)),
                ("status", models.CharField(choices=[("ok", "Normal"), ("warning", "Advertencia"), ("critical", "Critico"), ("offline", "Sin reporte")], default="ok", max_length=20)),
                ("last_report_at", models.DateTimeField(blank=True, null=True)),
                ("servers_total", models.PositiveIntegerField(default=0)),
                ("servers_online", models.PositiveIntegerField(default=0)),
                ("alerts_unresolved", models.PositiveIntegerField(default=0)),
                ("critical_alerts", models.PositiveIntegerField(default=0)),
                ("warning_alerts", models.PositiveIntegerField(default=0)),
                ("last_payload", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name", "satellite_id"]},
        ),
        migrations.CreateModel(
            name="SatelliteReport",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("report_timestamp", models.DateTimeField()),
                ("source_hostname", models.CharField(blank=True, max_length=255)),
                ("site_name", models.CharField(blank=True, max_length=160)),
                ("agents_count", models.PositiveIntegerField(default=0)),
                ("metrics_count", models.PositiveIntegerField(default=0)),
                ("alerts_count", models.PositiveIntegerField(default=0)),
                ("status_summary", models.JSONField(blank=True, default=dict)),
                ("payload", models.JSONField(default=dict)),
                ("received_at", models.DateTimeField(auto_now_add=True)),
                ("satellite", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="reports", to="hub.satellite")),
            ],
            options={"ordering": ["-received_at"]},
        ),
        migrations.CreateModel(
            name="SatelliteServerSnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_server_id", models.CharField(blank=True, max_length=80)),
                ("hostname", models.CharField(max_length=255)),
                ("name", models.CharField(blank=True, max_length=255)),
                ("ip_address", models.CharField(blank=True, max_length=80)),
                ("group", models.CharField(blank=True, max_length=120)),
                ("os_type", models.CharField(blank=True, max_length=40)),
                ("environment", models.CharField(blank=True, max_length=120)),
                ("owner", models.CharField(blank=True, max_length=255)),
                ("is_active", models.BooleanField(default=True)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("agent_version", models.CharField(blank=True, max_length=80)),
                ("inventory", models.JSONField(blank=True, default=dict)),
                ("latest_metric", models.JSONField(blank=True, default=dict)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("satellite", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="server_snapshots", to="hub.satellite")),
            ],
            options={"ordering": ["satellite__name", "hostname"], "unique_together": {("satellite", "hostname")}},
        ),
        migrations.CreateModel(
            name="SatelliteAlert",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source_alert_id", models.CharField(max_length=80)),
                ("server_hostname", models.CharField(blank=True, max_length=255)),
                ("rule", models.CharField(blank=True, max_length=255)),
                ("event_type", models.CharField(blank=True, max_length=120)),
                ("priority", models.CharField(blank=True, max_length=40)),
                ("value", models.CharField(blank=True, max_length=120)),
                ("message", models.TextField(blank=True)),
                ("is_resolved", models.BooleanField(default=False)),
                ("source_created_at", models.DateTimeField(blank=True, null=True)),
                ("source_resolved_at", models.DateTimeField(blank=True, null=True)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("satellite", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="alerts", to="hub.satellite")),
            ],
            options={"ordering": ["is_resolved", "-source_created_at"], "unique_together": {("satellite", "source_alert_id")}},
        ),
        migrations.AddIndex(
            model_name="satellitereport",
            index=models.Index(fields=["satellite", "-received_at"], name="hub_satelli_satelli_669d1d_idx"),
        ),
        migrations.AddIndex(
            model_name="satellitereport",
            index=models.Index(fields=["report_timestamp"], name="hub_satelli_report__68f7d2_idx"),
        ),
        migrations.AddIndex(
            model_name="satelliteserversnapshot",
            index=models.Index(fields=["satellite", "hostname"], name="hub_satelli_satelli_b977e7_idx"),
        ),
        migrations.AddIndex(
            model_name="satelliteserversnapshot",
            index=models.Index(fields=["ip_address"], name="hub_satelli_ip_addr_1152dc_idx"),
        ),
        migrations.AddIndex(
            model_name="satellitealert",
            index=models.Index(fields=["satellite", "is_resolved"], name="hub_satelli_satelli_e43afb_idx"),
        ),
        migrations.AddIndex(
            model_name="satellitealert",
            index=models.Index(fields=["priority", "is_resolved"], name="hub_satelli_priorit_a6ebaf_idx"),
        ),
    ]
