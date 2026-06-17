from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("inventory", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="MetricSample",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField()),
                ("agent_version", models.CharField(blank=True, max_length=50)),
                ("cpu_percent", models.FloatField(blank=True, null=True)),
                ("memory_percent", models.FloatField(blank=True, null=True)),
                ("disk_percent", models.FloatField(blank=True, null=True)),
                ("uptime_seconds", models.BigIntegerField(blank=True, null=True)),
                ("payload", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("server", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="metric_samples", to="inventory.server")),
            ],
            options={
                "ordering": ["-timestamp"],
                "indexes": [
                    models.Index(fields=["server", "-timestamp"], name="metrics_met_server__8e88b8_idx"),
                    models.Index(fields=["timestamp"], name="metrics_met_timesta_7a88c6_idx"),
                ],
            },
        ),
    ]
