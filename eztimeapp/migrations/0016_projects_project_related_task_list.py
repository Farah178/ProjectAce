# Generated by Django 3.2.10 on 2023-05-18 06:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0015_projects_task_project_category_list'),
    ]

    operations = [
        migrations.AddField(
            model_name='projects',
            name='project_related_task_list',
            field=models.JSONField(blank=True, null=True),
        ),
    ]
