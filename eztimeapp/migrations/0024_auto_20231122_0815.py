# Generated by Django 3.2.10 on 2023-11-22 08:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0023_notificationcenter'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='center',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='CustomCenter', to='eztimeapp.center'),
        ),
        migrations.AlterField(
            model_name='people',
            name='prefix_suffix',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='eztimeapp.prefixsuffix'),
        ),
    ]
