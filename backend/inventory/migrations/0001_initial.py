import inventory.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Server",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(max_length=255, unique=True)),
                ("name", models.CharField(blank=True, max_length=255)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("os_type", models.CharField(choices=[("linux", "Linux"), ("windows", "Windows"), ("other", "Otro")], default="linux", max_length=20)),
                ("environment", models.CharField(blank=True, max_length=100)),
                ("owner", models.CharField(blank=True, max_length=255)),
                ("is_active", models.BooleanField(default=True)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["hostname"]},
        ),
        migrations.CreateModel(
            name="AgentToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token", models.CharField(default=inventory.models.generate_agent_token, max_length=128, unique=True)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("server", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="agent_token", to="inventory.server")),
            ],
            options={"ordering": ["server__hostname"]},
        ),
    ]
