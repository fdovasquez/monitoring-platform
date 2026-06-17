from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("inventory", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="AlertRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255)),
                ("metric", models.CharField(choices=[("cpu_percent", "CPU %"), ("memory_percent", "Memoria %"), ("disk_percent", "Disco %")], max_length=50)),
                ("threshold", models.FloatField()),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="AlertEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("value", models.FloatField()),
                ("message", models.CharField(max_length=500)),
                ("is_resolved", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("rule", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="alerts.alertrule")),
                ("server", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="alert_events", to="inventory.server")),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
