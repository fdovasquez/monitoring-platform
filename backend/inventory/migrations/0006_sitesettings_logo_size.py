from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("inventory", "0005_sitesettings"),
    ]

    operations = [
        migrations.AddField(
            model_name="sitesettings",
            name="logo_width",
            field=models.PositiveIntegerField(default=126),
        ),
        migrations.AddField(
            model_name="sitesettings",
            name="logo_height",
            field=models.PositiveIntegerField(default=38),
        ),
    ]
