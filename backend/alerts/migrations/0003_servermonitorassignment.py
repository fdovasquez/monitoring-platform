from django.db import migrations, models
import django.db.models.deletion


def assign_existing_monitors(apps, schema_editor):
    AlertRule = apps.get_model("alerts", "AlertRule")
    Server = apps.get_model("inventory", "Server")
    ServerMonitorAssignment = apps.get_model("alerts", "ServerMonitorAssignment")

    assignments = [
        ServerMonitorAssignment(server_id=server_id, rule_id=rule_id, is_enabled=True)
        for server_id in Server.objects.values_list("id", flat=True)
        for rule_id in AlertRule.objects.filter(is_active=True).values_list("id", flat=True)
    ]
    ServerMonitorAssignment.objects.bulk_create(assignments, ignore_conflicts=True)


class Migration(migrations.Migration):

    dependencies = [
        ("alerts", "0002_email_alerting"),
        ("inventory", "0009_tlscertificate"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerMonitorAssignment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("is_enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "rule",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="server_assignments",
                        to="alerts.alertrule",
                    ),
                ),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="monitor_assignments",
                        to="inventory.server",
                    ),
                ),
            ],
            options={
                "ordering": ["server__hostname", "rule__name"],
                "unique_together": {("server", "rule")},
            },
        ),
        migrations.AddIndex(
            model_name="servermonitorassignment",
            index=models.Index(fields=["server", "is_enabled"], name="alerts_serv_server__d61220_idx"),
        ),
        migrations.AddIndex(
            model_name="servermonitorassignment",
            index=models.Index(fields=["rule", "is_enabled"], name="alerts_serv_rule_id_5c706f_idx"),
        ),
        migrations.RunPython(assign_existing_monitors, migrations.RunPython.noop),
    ]
