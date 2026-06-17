from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0001_initial"),
        ("alerts", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="SmtpSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("host", models.CharField(blank=True, max_length=255)),
                ("port", models.PositiveIntegerField(default=587)),
                ("username", models.CharField(blank=True, max_length=255)),
                ("encrypted_password", models.TextField(blank=True)),
                ("from_email", models.EmailField(blank=True, max_length=254)),
                ("from_name", models.CharField(blank=True, max_length=160)),
                ("security", models.CharField(choices=[("ssl", "SSL"), ("tls", "TLS"), ("none", "Sin cifrado")], default="tls", max_length=10)),
                ("require_auth", models.BooleanField(default=True)),
                ("timeout_seconds", models.PositiveIntegerField(default=10)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Configuracion SMTP",
                "verbose_name_plural": "Configuracion SMTP",
            },
        ),
        migrations.AddField(
            model_name="alertrule",
            name="event_type",
            field=models.CharField(choices=[("server_offline", "Servidor fuera de linea"), ("service_stopped", "Servicio detenido"), ("cpu_percent", "Uso de CPU superior al umbral"), ("memory_percent", "Uso de memoria superior al umbral"), ("disk_percent", "Uso de disco superior al umbral"), ("free_space_percent", "Espacio libre inferior al umbral"), ("unexpected_reboot", "Reinicio inesperado del servidor"), ("backup_error", "Error en respaldos"), ("database_connection_error", "Error en conexion con bases de datos"), ("critical_service_error", "Error en servicios criticos")], default="cpu_percent", max_length=80),
        ),
        migrations.AlterField(
            model_name="alertrule",
            name="metric",
            field=models.CharField(blank=True, choices=[("cpu_percent", "CPU %"), ("memory_percent", "Memoria %"), ("disk_percent", "Disco %")], max_length=50),
        ),
        migrations.AddField(model_name="alertrule", name="priority", field=models.CharField(choices=[("info", "Informacion"), ("warning", "Advertencia"), ("critical", "Critica")], default="warning", max_length=20)),
        migrations.AddField(model_name="alertrule", name="recipients", field=models.TextField(blank=True, help_text="Correos separados por coma, punto y coma o salto de linea.")),
        migrations.AddField(model_name="alertrule", name="notification_frequency_minutes", field=models.PositiveIntegerField(default=60)),
        migrations.AddField(model_name="alertrule", name="min_interval_minutes", field=models.PositiveIntegerField(default=30)),
        migrations.AddField(model_name="alertrule", name="service_name", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="alertrule", name="last_notified_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="alertrule", name="updated_at", field=models.DateTimeField(auto_now=True)),
        migrations.CreateModel(
            name="AlertEmailLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("status", models.CharField(choices=[("sent", "Enviado"), ("error", "Error")], max_length=20)),
                ("alert_type", models.CharField(max_length=120)),
                ("severity", models.CharField(choices=[("info", "Informacion"), ("warning", "Advertencia"), ("critical", "Critica")], default="warning", max_length=20)),
                ("service_name", models.CharField(blank=True, max_length=160)),
                ("recipients", models.TextField(blank=True)),
                ("subject", models.CharField(max_length=255)),
                ("message", models.TextField()),
                ("error_message", models.TextField(blank=True)),
                ("server", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="alert_email_logs", to="inventory.server")),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(model_name="alertemaillog", index=models.Index(fields=["-created_at"], name="alerts_aler_created_68d082_idx")),
        migrations.AddIndex(model_name="alertemaillog", index=models.Index(fields=["status"], name="alerts_aler_status_846850_idx")),
        migrations.AddIndex(model_name="alertemaillog", index=models.Index(fields=["severity"], name="alerts_aler_severit_958faa_idx")),
    ]
