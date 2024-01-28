# Generated by Django 3.2.10 on 2023-03-09 17:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0004_leaveapplication_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='leaveapplication',
            name='approved_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='approved_by', to='eztimeapp.customuser'),
        ),
        migrations.AddField(
            model_name='leaveapplication',
            name='approved_date',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
    ]