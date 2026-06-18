import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0006_sitesettings_logo_size"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerInventory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("fqdn", models.CharField(blank=True, max_length=255)),
                ("os_name", models.CharField(blank=True, max_length=255)),
                ("os_version", models.CharField(blank=True, max_length=255)),
                ("kernel", models.CharField(blank=True, max_length=255)),
                ("architecture", models.CharField(blank=True, max_length=120)),
                ("serial_number", models.CharField(blank=True, max_length=255)),
                ("model", models.CharField(blank=True, max_length=255)),
                ("manufacturer", models.CharField(blank=True, max_length=255)),
                ("domain", models.CharField(blank=True, max_length=255)),
                ("logged_user", models.CharField(blank=True, max_length=255)),
                ("primary_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("gateway", models.CharField(blank=True, max_length=255)),
                ("dns_servers", models.JSONField(blank=True, default=list)),
                ("mac_addresses", models.JSONField(blank=True, default=list)),
                ("interfaces", models.JSONField(blank=True, default=list)),
                ("timezone", models.CharField(blank=True, max_length=120)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("collected_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("server", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="inventory", to="inventory.server")),
            ],
            options={"ordering": ["server__hostname"]},
        ),
    ]
