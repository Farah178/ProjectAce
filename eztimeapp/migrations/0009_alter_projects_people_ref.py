# Generated by Django 3.2.10 on 2023-03-17 07:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0008_alter_people_tags'),
    ]

    operations = [
        migrations.AlterField(
            model_name='projects',
            name='people_ref',
            field=models.JSONField(blank=True, null=True),
        ),
    ]
