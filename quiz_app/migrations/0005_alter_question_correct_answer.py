# Generated by Django 4.2 on 2025-02-20 21:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quiz_app', '0004_quiz_is_deleted'),
    ]

    operations = [
        migrations.AlterField(
            model_name='question',
            name='correct_answer',
            field=models.TextField(blank=True, null=True),
        ),
    ]
