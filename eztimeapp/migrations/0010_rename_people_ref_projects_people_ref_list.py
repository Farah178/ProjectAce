# Generated by Django 3.2.10 on 2023-03-17 07:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0009_alter_projects_people_ref'),
    ]

    operations = [
        migrations.RenameField(
            model_name='projects',
            old_name='people_ref',
            new_name='people_ref_list',
        ),
    ]
