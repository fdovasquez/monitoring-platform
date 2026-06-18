import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0007_serverinventory"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerRuntimeSnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("services", models.JSONField(blank=True, default=list)),
                ("processes", models.JSONField(blank=True, default=list)),
                ("ports", models.JSONField(blank=True, default=list)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("collected_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("server", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="runtime_snapshot", to="inventory.server")),
            ],
            options={"ordering": ["server__hostname"]},
        ),
    ]
