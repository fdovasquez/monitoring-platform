from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("inventory", "0002_devicegroup_server_group"),
    ]

    operations = [
        migrations.CreateModel(
            name="MachineCredential",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("label", models.CharField(max_length=120)),
                ("username", models.CharField(max_length=120)),
                ("port", models.PositiveIntegerField(default=22)),
                (
                    "auth_method",
                    models.CharField(choices=[("password", "Clave SSH")], default="password", max_length=20),
                ),
                ("encrypted_secret", models.TextField(blank=True)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="credentials",
                        to="inventory.server",
                    ),
                ),
            ],
            options={
                "ordering": ["label", "username"],
                "unique_together": {("server", "label")},
            },
        ),
    ]
