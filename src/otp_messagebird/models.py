from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.encoding import force_text

from django_otp.models import SideChannelDevice
from django_otp.util import hex_validator, random_hex
import messagebird

from .conf import settings


logger = logging.getLogger(__name__)


def default_key():
    """ Obsolete code here for migrations. """
    return force_text(random_hex(20))


def key_validator(value):
    """ Obsolete code here for migrations. """
    return hex_validator(20)(value)


class MessageBirdBaseDevice(SideChannelDevice):
    """
    Abstract MessageBird base device that implements all required fields
    and methods for :class:`~otp_messagebird.models.MessageBirdSMSDevice`
    and :class:`~otp_messagebird.models.MessageBirdVoiceDevice`.

    The tokens are valid for :setting:`OTP_MESSAGEBIRD_TOKEN_VALIDITY` seconds.
    Once a token has been accepted, it is no longer valid.

    .. attribute:: number

        *CharField*: The mobile phone number to deliver to. This module requires
        using the `E.164 <http://en.wikipedia.org/wiki/E.164>`_ format. For US numbers,
        this would look like '+15555555555'.

    """
    number = models.CharField(
        max_length=30, help_text="The mobile number to deliver tokens to (E.164)."
    )

    class Meta(SideChannelDevice.Meta):
        abstract = True

    def generate_challenge(self):
        """
        Generates a random token and sends it to ``self.number``.

        :returns: :setting:`OTP_MESSAGEBIRD_CHALLENGE_MESSAGE` on success.
        :raises: Exception if delivery fails.

        """
        self.generate_token(valid_secs=settings.OTP_MESSAGEBIRD_TOKEN_VALIDITY)

        token_template = getattr(settings, "OTP_MESSAGEBIRD_TOKEN_TEMPLATE", None)
        if callable(token_template):
            token_template = token_template(self)
        message = token_template.format(token=self.token)

        if settings.OTP_MESSAGEBIRD_NO_DELIVERY:
            logger.info(message)
        else:
            self._deliver_token(message)

        challenge_message = getattr(settings, "OTP_MESSAGEBIRD_CHALLENGE_MESSAGE", None)
        if callable(challenge_message):
            challenge_message = challenge_message(self)
        challenge = challenge_message.format(token=self.token)

        return challenge

    def _validate_config(self):
        if settings.OTP_MESSAGEBIRD_ACCESS_KEY is None:
            raise ImproperlyConfigured(
                "OTP_MESSAGEBIRD_ACCESS_KEY must be set to your MessageBird access key"
            )

        if settings.OTP_MESSAGEBIRD_FROM is None:
            raise ImproperlyConfigured(
                "OTP_MESSAGEBIRD_FROM must be set to one of your MessageBird phone numbers or a string"
            )


class MessageBirdSMSDevice(MessageBirdBaseDevice):
    """
    A :class:`~otp_messagebird.models.MessageBirdBaseDevice` that delivers codes
    via the MessageBird SMS service.

    """

    class Meta(MessageBirdBaseDevice.Meta):
        verbose_name = "MessageBird SMS Device"

    def _deliver_token(self, token):
        self._validate_config()

        client = messagebird.Client(settings.OTP_MESSAGEBIRD_ACCESS_KEY)
        try:
            client.message_create(
                originator=settings.OTP_MESSAGEBIRD_FROM,
                recipients=self.number.replace("+", ""),
                body=str(token),
            )
        except messagebird.client.ErrorException as e:
            logger.exception("Error sending token by MessageBird SMS: {0}".format(e))
            raise


class MessageBirdVoiceDevice(MessageBirdBaseDevice):
    """
    A :class:`~django_otp.models.SideChannelDevice` that delivers codes via the
    MessageBird Voice service.

    """

    class Meta(MessageBirdBaseDevice.Meta):
        verbose_name = "MessageBird Voice Device"

    def _deliver_token(self, token):
        self._validate_config()

        client = messagebird.Client(settings.OTP_MESSAGEBIRD_ACCESS_KEY)
        try:
            client.voice_message_create(
                recipients=self.number.replace("+", ""),
                body=str(token),
            )
        except messagebird.client.ErrorException as e:
            logger.exception("Error sending token by MessageBird Voice: {0}".format(e))
            raise
