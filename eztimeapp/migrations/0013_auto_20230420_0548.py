# Generated by Django 3.2.10 on 2023-04-20 05:48

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('eztimeapp', '0012_auto_20230419_1422'),
    ]

    operations = [
        migrations.AddField(
            model_name='people',
            name='user_role',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='CustomCenter', to='eztimeapp.userrole'),
        ),
        migrations.AddField(
            model_name='userrole',
            name='created_time',
            field=models.DateTimeField(auto_now_add=True, null=True, verbose_name='Create_TimeStamp'),
        ),
        migrations.AddField(
            model_name='userrole',
            name='description',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AddField(
            model_name='userrole',
            name='priority',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AddField(
            model_name='userrole',
            name='role_status',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AddField(
            model_name='userrole',
            name='updated_time',
            field=models.DateTimeField(auto_now_add=True, null=True, verbose_name='Last_Update_TimeStamp'),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='user_role',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='UserRole', to='eztimeapp.userrole'),
        ),
    ]
