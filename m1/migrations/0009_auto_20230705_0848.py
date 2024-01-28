# Generated by Django 3.2.10 on 2023-07-05 08:48

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0019_auto_20230703_1122'),
        ('m1', '0008_alter_timesheets_applied_date'),
    ]

    operations = [
        migrations.RenameField(
            model_name='timesheetsapprovalconfig',
            old_name='days_to_approve',
            new_name='grace_days_to_approve',
        ),
        migrations.AddField(
            model_name='timesheetsapprovalconfig',
            name='organization',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='eztimeapp.organization'),
        ),
    ]
