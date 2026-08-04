from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("inventory", "0011_userprofile_theme"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="must_change_password",
            field=models.BooleanField(default=False),
        ),
    ]
