from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("metrics", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="CentralReportQueue",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("payload", models.JSONField(default=dict)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pendiente"),
                            ("sent", "Enviado"),
                            ("error", "Error"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("last_error", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("sent_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "ordering": ["created_at"],
                "indexes": [
                    models.Index(fields=["status", "created_at"], name="metrics_cen_status_8f3f8d_idx"),
                    models.Index(fields=["-sent_at"], name="metrics_cen_sent_at_7c52e6_idx"),
                ],
            },
        ),
    ]
