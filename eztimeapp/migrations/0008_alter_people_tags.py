# Generated by Django 3.2.10 on 2023-03-16 08:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0007_auto_20230314_1255'),
    ]

    operations = [
        migrations.AlterField(
            model_name='people',
            name='tags',
            field=models.JSONField(blank=True, null=True),
        ),
    ]
