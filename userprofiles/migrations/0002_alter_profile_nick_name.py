# Generated by Django 4.2.1 on 2024-03-15 03:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userprofiles', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='nick_name',
            field=models.CharField(blank=True, max_length=20, unique=True),
        ),
    ]