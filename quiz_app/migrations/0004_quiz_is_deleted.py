# Generated by Django 4.2 on 2025-02-19 20:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quiz_app', '0003_alter_quiz_created_by_alter_quiz_language'),
    ]

    operations = [
        migrations.AddField(
            model_name='quiz',
            name='is_deleted',
            field=models.BooleanField(default=False),
        ),
    ]
