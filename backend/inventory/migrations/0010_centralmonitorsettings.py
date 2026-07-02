from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("inventory", "0009_tlscertificate"),
    ]

    operations = [
        migrations.CreateModel(
            name="CentralMonitorSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("central_api_url", models.URLField(blank=True, max_length=500)),
                ("satellite_id", models.CharField(blank=True, max_length=120)),
                ("satellite_name", models.CharField(blank=True, max_length=160)),
                ("encrypted_api_token", models.TextField(blank=True)),
                ("report_interval_seconds", models.PositiveIntegerField(default=300)),
                ("timeout_seconds", models.PositiveIntegerField(default=20)),
                ("max_batch", models.PositiveIntegerField(default=25)),
                ("reporting_enabled", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Monitor central",
                "verbose_name_plural": "Monitor central",
            },
        ),
    ]
