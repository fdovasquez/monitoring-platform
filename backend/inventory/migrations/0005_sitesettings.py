import inventory.models
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0004_userprofile"),
    ]

    operations = [
        migrations.CreateModel(
            name="SiteSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("site_name", models.CharField(default="AGFA HealthCare", max_length=120)),
                ("subtitle", models.CharField(default="Monitor de servidores", max_length=160)),
                ("logo", models.ImageField(blank=True, null=True, upload_to=inventory.models.site_logo_path)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Configuracion del sitio",
                "verbose_name_plural": "Configuracion del sitio",
            },
        ),
    ]
