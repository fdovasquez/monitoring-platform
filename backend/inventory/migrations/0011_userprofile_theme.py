from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("inventory", "0010_centralmonitorsettings"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="theme",
            field=models.CharField(
                choices=[
                    ("light", "Blanco"),
                    ("gray", "Gris"),
                    ("dark", "Oscuro"),
                ],
                default="light",
                max_length=20,
            ),
        ),
    ]
