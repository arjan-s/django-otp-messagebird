# Generated by Django 3.0.5 on 2020-04-20 14:55

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('otp_messagebird', '0002_sidechanneldevice'),
    ]

    operations = [
        migrations.CreateModel(
            name='MessageBirdVoiceDevice',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='The human-readable name of this device.', max_length=64)),
                ('confirmed', models.BooleanField(default=True, help_text='Is this device ready for use?')),
                ('token', models.CharField(blank=True, max_length=16, null=True)),
                ('valid_until', models.DateTimeField(default=django.utils.timezone.now, help_text='The timestamp of the moment of expiry of the saved token.')),
                ('number', models.CharField(help_text='The mobile number to deliver tokens to (E.164).', max_length=30)),
                ('user', models.ForeignKey(help_text='The user that this device belongs to.', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'MessageBird Voice Device',
                'abstract': False,
            },
        ),
    ]
