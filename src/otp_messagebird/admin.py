from __future__ import absolute_import, division, print_function, unicode_literals

from django.contrib import admin
from django.contrib.admin.sites import AlreadyRegistered

from .models import MessageBirdSMSDevice


class MessageBirdSMSDeviceAdmin(admin.ModelAdmin):
    """
    :class:`~django.contrib.admin.ModelAdmin` for
    :class:`~otp_messagebird.models.MessageBirdSMSDevice`.
    """

    fieldsets = [
        ("Identity", {"fields": ["user", "name", "confirmed"], }),
        ("Configuration", {"fields": ["number", "key"], }),
    ]
    raw_id_fields = ["user"]


try:
    admin.site.register(MessageBirdSMSDevice, MessageBirdSMSDeviceAdmin)
except AlreadyRegistered:
    # Ignore the useless exception from multiple imports
    pass