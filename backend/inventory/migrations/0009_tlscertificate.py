from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("inventory", "0008_serverruntimesnapshot")]

    operations = [
        migrations.CreateModel(
            name="TlsCertificate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("domain", models.CharField(blank=True, max_length=255)),
                ("certificate_pem", models.TextField(blank=True)),
                ("encrypted_private_key", models.TextField(blank=True)),
                ("certificate_filename", models.CharField(blank=True, max_length=255)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "Certificado HTTPS", "verbose_name_plural": "Certificados HTTPS"},
        ),
    ]
